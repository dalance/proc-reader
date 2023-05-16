//! A std::io::Read implementation for stdout/stderr of other process.
//!
//! # Examples
//!
//! ```
//! # use proc_reader::ProcReader;
//! # use std::process::Command;
//! # use std::io::Read;
//! # use std::time::Duration;
//! # use std::thread;
//! # fn main() {
//! // Create a process for reading stdout
//! let mut child = Command::new("sh").arg("-c").arg("sleep 1; echo aaa").spawn().unwrap();
//!
//! // Create ProcReader from pid
//! let mut reader = ProcReader::from_stdout(child.id());
//!
//! // Wait the end of process
//! thread::sleep(Duration::from_secs(2));
//!
//! // Read from ProcReader
//! let mut line = String::new();
//! let _ = reader.read_to_string(&mut line);
//! assert_eq!( "aaa\n", line);
//! # }
//! ```

use libc::user_regs_struct;
use nix::sys::ptrace::{self, AddressType, Options};
use nix::sys::signal::Signal;
use nix::sys::wait::{self, WaitStatus};
use nix::unistd::Pid;
use std::io::Read;
use std::mem;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread::{self, JoinHandle};
use thiserror::Error;

// -------------------------------------------------------------------------------------------------
// Error
// -------------------------------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum Error {
    #[error("failed to access process ({pid})")]
    ProcAccessFailed { pid: Pid },
    #[error(transparent)]
    Nix(#[from] nix::Error),
    #[error(transparent)]
    Recv(#[from] std::sync::mpsc::RecvError),
    #[error(transparent)]
    Send(#[from] std::sync::mpsc::SendError<Vec<u8>>),
}

// -------------------------------------------------------------------------------------------------
// Type per arch
// -------------------------------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
type Word = u64;

#[cfg(target_arch = "x86")]
type Word = u32;

#[cfg(target_arch = "x86_64")]
const WORD_BYTES: u64 = 8;

#[cfg(target_arch = "x86")]
const WORD_BYTES: u32 = 4;

/// Represents all possible ptrace-accessible registers on x86_64
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy, Debug)]
struct UserRegs(user_regs_struct);

/// Represents all possible ptrace-accessible registers on x86
#[cfg(target_arch = "x86")]
#[derive(Clone, Copy, Debug)]
struct UserRegs(user_regs_struct);

#[cfg(target_arch = "x86_64")]
#[allow(dead_code)]
impl UserRegs {
    fn syscall(self) -> Word {
        self.0.orig_rax
    }

    fn ret(self) -> Word {
        self.0.rax
    }

    fn arg1(self) -> Word {
        self.0.rdi
    }

    fn arg2(self) -> Word {
        self.0.rsi
    }

    fn arg3(self) -> Word {
        self.0.rdx
    }

    fn arg4(self) -> Word {
        self.0.r10
    }

    fn arg5(self) -> Word {
        self.0.r8
    }

    fn arg6(self) -> Word {
        self.0.r9
    }
}

#[cfg(target_arch = "x86")]
#[allow(dead_code)]
impl UserRegs {
    fn syscall(self) -> Word {
        self.0.orig_eax
    }

    fn ret(self) -> Word {
        self.0.eax
    }

    fn arg1(self) -> Word {
        self.0.ebx
    }

    fn arg2(self) -> Word {
        self.0.ecx
    }

    fn arg3(self) -> Word {
        self.0.edx
    }

    fn arg4(self) -> Word {
        self.0.esi
    }

    fn arg5(self) -> Word {
        self.0.edi
    }

    fn arg6(self) -> Word {
        self.0.ebp
    }
}

// -------------------------------------------------------------------------------------------------
// ProcReader
// -------------------------------------------------------------------------------------------------

enum ProcReaderMsg {
    Stop,
    Redirect,
}

/// The struct `ProcReader` provide reader from stdout/stderr of other process.
pub struct ProcReader {
    ctl: Sender<ProcReaderMsg>,
    buf: Receiver<Vec<u8>>,
    err: Receiver<Error>,
    child: Option<JoinHandle<()>>,
    rest: Vec<u8>,
}

#[derive(PartialEq)]
enum StdType {
    Any,
    Out,
    Err,
}

impl ProcReader {
    /// Create a new `ProcReader` for stdout/stderr of the process specified by `pid`
    pub fn from_stdany(pid: u32) -> Self {
        let pid = Pid::from_raw(pid as i32);
        ProcReader::new(pid, StdType::Any)
    }

    /// Create a new `ProcReader` for stdout of the process specified by `pid`
    pub fn from_stdout(pid: u32) -> Self {
        let pid = Pid::from_raw(pid as i32);
        ProcReader::new(pid, StdType::Out)
    }

    /// Create a new `ProcReader` for stderr of the process specified by `pid`
    pub fn from_stderr(pid: u32) -> Self {
        let pid = Pid::from_raw(pid as i32);
        ProcReader::new(pid, StdType::Err)
    }

    /// Enable redirect trace
    pub fn with_redirect(self) -> Self {
        let _ = self.ctl.send(ProcReaderMsg::Redirect);
        self
    }

    fn new(pid: Pid, typ: StdType) -> Self {
        let (ctl_tx, ctl_rx) = channel();
        let (buf_tx, buf_rx) = channel();
        let (err_tx, err_rx) = channel();

        let child = thread::spawn(
            move || match ProcReader::collect(pid, typ, ctl_rx, buf_tx) {
                Err(x) => {
                    let _ = err_tx.send(x);
                }
                _ => (),
            },
        );

        ProcReader {
            ctl: ctl_tx,
            buf: buf_rx,
            err: err_rx,
            child: Some(child),
            rest: Vec::new(),
        }
    }

    fn collect(
        pid: Pid,
        typ: StdType,
        ctl_rx: Receiver<ProcReaderMsg>,
        buf_tx: Sender<Vec<u8>>,
    ) -> Result<(), Error> {
        ptrace::attach(pid).map_err(|_| Error::ProcAccessFailed { pid })?;
        ProcReader::set_tracesysgood(pid).map_err(|_| Error::ProcAccessFailed { pid })?;

        // pid stack
        let mut pids = Vec::new();
        pids.push(pid);

        // fd stack
        let mut fd = [0; 1024];
        fd[1] = 1;
        fd[2] = 2;
        let mut fds = Vec::new();
        fds.push(fd.clone());

        let mut enable_redirect = false;
        let mut is_syscall_before = false;
        let mut prev_orig_rax = 0;

        loop {
            let mut pid = *pids.last().unwrap();
            match wait::waitpid(pid, None).map_err(|_| Error::ProcAccessFailed { pid })? {
                WaitStatus::PtraceSyscall(_) => {
                    let regs =
                        ProcReader::get_regs(pid).map_err(|_| Error::ProcAccessFailed { pid })?;

                    is_syscall_before = if prev_orig_rax == regs.syscall() {
                        !is_syscall_before
                    } else {
                        true
                    };
                    prev_orig_rax = regs.syscall();

                    if !is_syscall_before && enable_redirect {
                        fd = ProcReader::update_fd(fd, regs);
                    }

                    let sys_clone = regs.syscall() == libc::SYS_clone as Word;
                    let sys_fork = regs.syscall() == libc::SYS_fork as Word;
                    let sys_vfork = regs.syscall() == libc::SYS_vfork as Word;

                    if (sys_clone || sys_fork || sys_vfork) && !is_syscall_before {
                        pid = Pid::from_raw(regs.ret() as i32);
                        pids.push(pid);
                        fds.push(fd.clone());
                        continue;
                    }

                    if regs.syscall() == libc::SYS_write as Word && is_syscall_before {
                        let out = ProcReader::peek_bytes(pid, regs.arg2(), regs.arg3());
                        let out_typ = regs.arg1();

                        let send_stdout = fd[out_typ as usize] == 1
                            && (typ == StdType::Any || typ == StdType::Out);
                        let send_stderr = fd[out_typ as usize] == 2
                            && (typ == StdType::Any || typ == StdType::Err);

                        if send_stdout || send_stderr {
                            buf_tx.send(out)?;
                        }
                    }
                }
                WaitStatus::Exited(_, _) => {
                    pids.pop();
                    if pids.is_empty() {
                        break;
                    } else {
                        pid = *pids.last().unwrap();
                        fd = fds.pop().unwrap();
                    }
                }
                _ => (),
            }

            match ctl_rx.try_recv() {
                Ok(ProcReaderMsg::Stop) => {
                    ptrace::detach(pid, None).map_err(|_| Error::ProcAccessFailed { pid })?;
                    break;
                }
                Ok(ProcReaderMsg::Redirect) => {
                    enable_redirect = true;
                    ptrace::syscall(pid, None).map_err(|_| Error::ProcAccessFailed { pid })?;
                }
                _ => {
                    ptrace::syscall(pid, None).map_err(|_| Error::ProcAccessFailed { pid })?;
                }
            }
        }
        Ok(())
    }

    fn set_tracesysgood(pid: Pid) -> Result<(), Error> {
        loop {
            match wait::waitpid(pid, None).map_err(|_| Error::ProcAccessFailed { pid })? {
                // setoptions must be called at stopped condition
                WaitStatus::Stopped(_, Signal::SIGSTOP) => {
                    // set TRACESYSGOOD to enable PtraceSyscall
                    // set TRACECLONE/FORK/VFORK to trace chile process
                    let opt = Options::PTRACE_O_TRACESYSGOOD
                        | Options::PTRACE_O_TRACECLONE
                        | Options::PTRACE_O_TRACEFORK
                        | Options::PTRACE_O_TRACEVFORK;
                    ptrace::setoptions(pid, opt).map_err(|_| Error::ProcAccessFailed { pid })?;
                    ptrace::syscall(pid, None).map_err(|_| Error::ProcAccessFailed { pid })?;
                    break;
                }
                _ => {
                    ptrace::syscall(pid, None).map_err(|_| Error::ProcAccessFailed { pid })?;
                }
            }
        }

        Ok(())
    }

    fn get_regs(pid: Pid) -> Result<UserRegs, Error> {
        let regs = ptrace::getregs(pid).map(|x| UserRegs(x))?;
        Ok(regs)
    }

    fn peek_bytes(pid: Pid, addr: Word, size: Word) -> Vec<u8> {
        let mut vec = (0..(size + WORD_BYTES - 1) / WORD_BYTES)
            .filter_map(|i| {
                ptrace::read(pid, (addr + WORD_BYTES * i) as AddressType)
                    .map(|l| unsafe { mem::transmute(l) })
                    .ok()
            })
            .collect::<Vec<[u8; WORD_BYTES as usize]>>()
            .concat();
        vec.truncate(size as usize);
        vec
    }

    fn update_fd(mut fd: [Word; 1024], regs: UserRegs) -> [Word; 1024] {
        // detect dup2 for redirect
        if regs.syscall() == libc::SYS_dup2 as Word {
            let src = regs.arg1();
            let dst = regs.arg2();
            fd[dst as usize] = fd[src as usize];
        }

        // detect fcntl for fd backup
        if regs.syscall() == libc::SYS_fcntl as Word {
            if regs.arg2() == libc::F_DUPFD as Word {
                let src = regs.arg1();
                let dst = regs.ret();
                fd[dst as usize] = fd[src as usize];
            }
        }
        fd
    }
}

impl Read for ProcReader {
    fn read(&mut self, buf: &mut [u8]) -> std::result::Result<usize, std::io::Error> {
        let err = match self.err.try_recv() {
            Ok(x) => Some(x),
            _ => None,
        };

        loop {
            match self.buf.try_recv() {
                Ok(mut x) => self.rest.append(&mut x),
                Err(_) => break,
            }
        }

        let len = if buf.len() >= self.rest.len() {
            let len = self.rest.len();
            self.rest.resize(buf.len(), 0);
            buf.copy_from_slice(&self.rest);
            self.rest.clear();
            len
        } else {
            let len = buf.len();
            let rest = self.rest.split_off(len);
            buf.copy_from_slice(&self.rest);
            self.rest = rest;
            len
        };

        if len != 0 {
            Ok(len)
        } else if let Some(err) = err {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("{}", err),
            ))
        } else {
            Ok(len)
        }
    }
}

impl Drop for ProcReader {
    fn drop(&mut self) {
        if self.child.is_some() {
            let _ = self.ctl.send(ProcReaderMsg::Stop);
            let _ = self.child.take().unwrap().join();
        }
    }
}

// -------------------------------------------------------------------------------------------------
// Test
// -------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufReader;
    use std::process::Command;
    use std::thread;
    use std::time::Duration;

    static SCRIPT: &'static str = r#"
        sleep 1;
        print "aaa\n";
        sleep 1;
        print "bbb\n";
        sleep 1;
        print "ccc\n";
    "#;

    static SCRIPT_WITH_ERR: &'static str = r#"
        sleep 1;
        print "aaa\n";
        warn "eee\n";
    "#;

    static SCRIPT_REDIRECT: &'static str = r#"
        sleep 1;
        echo 'aaa';
        echo 'bbb' > /dev/null 1>&2;
        perl -e 'warn "ccc\n"' 2>&1;
        perl -e 'warn "ddd\n"';
    "#;

    #[test]
    fn test_bufreader() {
        let child = Command::new("perl").arg("-e").arg(SCRIPT).spawn().unwrap();
        let mut reader = BufReader::new(ProcReader::from_stdout(child.id()));

        thread::sleep(Duration::from_secs(4));

        let mut line = String::new();
        let _ = reader.read_to_string(&mut line);
        assert_eq!("aaa\nbbb\nccc\n", line);
    }

    #[test]
    fn test_short_array() {
        let child = Command::new("perl").arg("-e").arg(SCRIPT).spawn().unwrap();
        let mut reader = ProcReader::from_stdout(child.id());

        thread::sleep(Duration::from_secs(4));

        let mut buf = [0; 10];
        let _ = reader.read_exact(&mut buf);
        assert_eq!("aaa\nbbb\ncc", String::from_utf8(buf.to_vec()).unwrap());
    }

    #[test]
    fn test_kill() {
        let mut child = Command::new("perl").arg("-e").arg(SCRIPT).spawn().unwrap();
        let mut reader = ProcReader::from_stdout(child.id());
        let _ = child.kill();

        thread::sleep(Duration::from_secs(4));

        let mut buf = [0; 10];
        let ret = reader.read_exact(&mut buf);
        assert_eq!(
            &format!("{:?}", ret)[0..60],
            "Err(Custom { kind: Other, error: \"failed to access process ("
        );
    }

    #[test]
    fn test_kill2() {
        let mut child = Command::new("perl").arg("-e").arg(SCRIPT).spawn().unwrap();
        let mut reader = ProcReader::from_stdout(child.id());

        thread::sleep(Duration::from_secs(2));
        let _ = child.kill();
        thread::sleep(Duration::from_secs(2));

        let mut buf = [0; 10];
        let ret = reader.read_exact(&mut buf);
        assert_eq!(
            &format!("{:?}", ret)[0..60],
            "Err(Error { kind: UnexpectedEof, message: \"failed to fill wh"
        );
    }

    #[test]
    fn test_stderr() {
        let child = Command::new("perl")
            .arg("-e")
            .arg(SCRIPT_WITH_ERR)
            .spawn()
            .unwrap();
        let mut reader = BufReader::new(ProcReader::from_stderr(child.id()));

        thread::sleep(Duration::from_secs(2));

        let mut line = String::new();
        let _ = reader.read_to_string(&mut line);
        assert_eq!("eee\n", line);
    }

    #[test]
    fn test_both() {
        let child = Command::new("perl")
            .arg("-e")
            .arg(SCRIPT_WITH_ERR)
            .spawn()
            .unwrap();
        let mut reader = BufReader::new(ProcReader::from_stdany(child.id()));

        thread::sleep(Duration::from_secs(2));

        let mut line = String::new();
        let _ = reader.read_to_string(&mut line);
        assert_eq!("aaa\neee\n", line);
    }

    #[test]
    fn test_stdout_without_redirect() {
        let child = Command::new("sh")
            .arg("-c")
            .arg(SCRIPT_REDIRECT)
            .spawn()
            .unwrap();
        let mut reader = BufReader::new(ProcReader::from_stdout(child.id()));

        thread::sleep(Duration::from_secs(4));

        let mut line = String::new();
        let _ = reader.read_to_string(&mut line);
        assert_eq!("aaa\nbbb\n", line);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_stdout_with_redirect() {
        let child = Command::new("sh")
            .arg("-c")
            .arg(SCRIPT_REDIRECT)
            .spawn()
            .unwrap();
        let mut reader = BufReader::new(ProcReader::from_stdout(child.id()).with_redirect());

        thread::sleep(Duration::from_secs(4));

        let mut line = String::new();
        let _ = reader.read_to_string(&mut line);
        assert_eq!("aaa\nccc\n", line);
    }

    #[test]
    fn test_stderr_without_redirect() {
        let child = Command::new("sh")
            .arg("-c")
            .arg(SCRIPT_REDIRECT)
            .spawn()
            .unwrap();
        let mut reader = BufReader::new(ProcReader::from_stderr(child.id()));

        thread::sleep(Duration::from_secs(4));

        let mut line = String::new();
        let _ = reader.read_to_string(&mut line);
        assert_eq!("ccc\nddd\n", line);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_stderr_with_redirect() {
        let child = Command::new("sh")
            .arg("-c")
            .arg(SCRIPT_REDIRECT)
            .spawn()
            .unwrap();
        let mut reader = BufReader::new(ProcReader::from_stderr(child.id()).with_redirect());

        thread::sleep(Duration::from_secs(4));

        let mut line = String::new();
        let _ = reader.read_to_string(&mut line);
        assert_eq!("bbb\nddd\n", line);
    }
}
