//! A std::io::Read implementation for stdout/stderr of other process.
//!
//! # Examples
//!
//! ```
//! # extern crate nix;
//! # extern crate proc_reader;
//! # use nix::unistd::Pid;
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
//! let pid = Pid::from_raw(child.id() as i32);
//! let mut reader = ProcReader::from_stdout(pid);
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

#[macro_use]
extern crate error_chain;
extern crate libc;
extern crate nix;

use libc::user_regs_struct;
#[allow(deprecated)]
use nix::sys::ptrace::{attach, detach, ptrace, setoptions, syscall, Options};
use nix::sys::ptrace::Request::{PTRACE_GETREGS, PTRACE_PEEKDATA};
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;
use std::io::Read;
use std::mem;
use std::ptr::{self, NonNull};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread::{self, JoinHandle};

// -------------------------------------------------------------------------------------------------
// Error
// -------------------------------------------------------------------------------------------------

error_chain! {
    errors {
        #[doc = "a variant for process access error"]
        ProcAccessFailed(pid: Pid) {
            description("process access failed")
            display("failed to access process ({})\n", pid)
        }
    }
    foreign_links {
        Nix(::nix::Error) #[doc = "a variant for `nix`"];
        Recv(::std::sync::mpsc::RecvError) #[doc = "a variant for `std::sync::misc::RecvError`"];
        Send(::std::sync::mpsc::SendError<Vec<u8>>) #[doc = "a variant for `std::sync::misc::SendError`"];
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
    pub fn from_stdany(pid: Pid) -> Self {
        ProcReader::new(pid, StdType::Any)
    }

    /// Create a new `ProcReader` for stdout of the process specified by `pid`
    pub fn from_stdout(pid: Pid) -> Self {
        ProcReader::new(pid, StdType::Out)
    }

    /// Create a new `ProcReader` for stderr of the process specified by `pid`
    pub fn from_stderr(pid: Pid) -> Self {
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
    ) -> Result<()> {
        attach(pid).chain_err(|| ErrorKind::ProcAccessFailed(pid))?;
        ProcReader::set_tracesysgood(pid).chain_err(|| ErrorKind::ProcAccessFailed(pid))?;

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
            match waitpid(pid, None).chain_err(|| ErrorKind::ProcAccessFailed(pid))? {
                WaitStatus::PtraceSyscall(_) => {
                    let regs =
                        ProcReader::get_regs(pid).chain_err(|| ErrorKind::ProcAccessFailed(pid))?;

                    is_syscall_before = if prev_orig_rax == regs.orig_rax {
                        !is_syscall_before
                    } else {
                        true
                    };
                    prev_orig_rax = regs.orig_rax;

                    if !is_syscall_before && enable_redirect {
                        fd = ProcReader::update_fd(fd, regs);
                    }

                    let sys_clone = regs.orig_rax == libc::SYS_clone as u64;
                    let sys_fork = regs.orig_rax == libc::SYS_fork as u64;
                    let sys_vfork = regs.orig_rax == libc::SYS_vfork as u64;

                    if (sys_clone || sys_fork || sys_vfork) && !is_syscall_before {
                        pid = Pid::from_raw(regs.rax as i32);
                        pids.push(pid);
                        fds.push(fd.clone());
                        continue;
                    }

                    if regs.orig_rax == libc::SYS_write as u64 && is_syscall_before {
                        let out = ProcReader::peek_bytes(pid, regs.rsi, regs.rdx);
                        let out_typ = regs.rdi;

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
                    detach(pid).chain_err(|| ErrorKind::ProcAccessFailed(pid))?;
                    break;
                }
                Ok(ProcReaderMsg::Redirect) => {
                    enable_redirect = true;
                    syscall(pid).chain_err(|| ErrorKind::ProcAccessFailed(pid))?;
                }
                _ => {
                    syscall(pid).chain_err(|| ErrorKind::ProcAccessFailed(pid))?;
                }
            }
        }
        Ok(())
    }

    fn set_tracesysgood(pid: Pid) -> Result<()> {
        loop {
            match waitpid(pid, None).chain_err(|| ErrorKind::ProcAccessFailed(pid))? {
                // setoptions must be called at stopped condition
                WaitStatus::Stopped(_, Signal::SIGSTOP) => {
                    // set TRACESYSGOOD to enable PtraceSyscall
                    // set TRACECLONE/FORK/VFORK to trace chile process
                    let opt = Options::PTRACE_O_TRACESYSGOOD | Options::PTRACE_O_TRACECLONE
                        | Options::PTRACE_O_TRACEFORK
                        | Options::PTRACE_O_TRACEVFORK;
                    setoptions(pid, opt).chain_err(|| ErrorKind::ProcAccessFailed(pid))?;
                    syscall(pid).chain_err(|| ErrorKind::ProcAccessFailed(pid))?;
                    break;
                }
                _ => {
                    syscall(pid).chain_err(|| ErrorKind::ProcAccessFailed(pid))?;
                }
            }
        }

        Ok(())
    }

    fn get_regs(pid: Pid) -> Result<user_regs_struct> {
        let mut regs: user_regs_struct = unsafe { mem::zeroed() };
        let regs_ptr = NonNull::new(&mut regs).unwrap();
        unsafe {
            #[allow(deprecated)]
            let _ = ptrace(
                PTRACE_GETREGS,
                pid,
                ptr::null_mut(),
                regs_ptr.as_ptr() as *mut libc::c_void,
            );
        }
        Ok(regs)
    }

    fn peek_bytes(pid: Pid, addr: u64, size: u64) -> Vec<u8> {
        let mut vec = (0..(size + 7) / 8)
            .filter_map(|i| unsafe {
                #[allow(deprecated)]
                ptrace(
                    PTRACE_PEEKDATA,
                    pid,
                    (addr + 8 * i) as *mut libc::c_void,
                    ptr::null_mut(),
                ).map(|l| mem::transmute(l))
                    .ok()
            })
            .collect::<Vec<[u8; 8]>>()
            .concat();
        vec.truncate(size as usize);
        vec
    }

    fn update_fd(mut fd: [u64; 1024], regs: user_regs_struct) -> [u64; 1024] {
        // detect dup2 for redirect
        if regs.orig_rax == libc::SYS_dup2 as u64 {
            let src = regs.rdi;
            let dst = regs.rsi;
            fd[dst as usize] = fd[src as usize];
        }

        // detect fcntl for fd backup
        if regs.orig_rax == libc::SYS_fcntl as u64 {
            if regs.rsi == libc::F_DUPFD as u64 {
                let src = regs.rdi;
                let dst = regs.rax;
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
    use std::time::Duration;
    use std::thread;

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
        let pid = Pid::from_raw(child.id() as i32);
        let mut reader = BufReader::new(ProcReader::from_stdout(pid));

        thread::sleep(Duration::from_secs(4));

        let mut line = String::new();
        let _ = reader.read_to_string(&mut line);
        assert_eq!("aaa\nbbb\nccc\n", line);
    }

    #[test]
    fn test_short_array() {
        let child = Command::new("perl").arg("-e").arg(SCRIPT).spawn().unwrap();
        let pid = Pid::from_raw(child.id() as i32);
        let mut reader = ProcReader::from_stdout(pid);

        thread::sleep(Duration::from_secs(4));

        let mut buf = [0; 10];
        let _ = reader.read_exact(&mut buf);
        assert_eq!("aaa\nbbb\ncc", String::from_utf8(buf.to_vec()).unwrap());
    }

    #[test]
    fn test_kill() {
        let mut child = Command::new("perl").arg("-e").arg(SCRIPT).spawn().unwrap();
        let pid = Pid::from_raw(child.id() as i32);
        let mut reader = ProcReader::from_stdout(pid);
        let _ = child.kill();

        thread::sleep(Duration::from_secs(4));

        let mut buf = [0; 10];
        let ret = reader.read_exact(&mut buf);
        assert_eq!(
            &format!("{:?}", ret)[0..70],
            "Err(Custom { kind: Other, error: StringError(\"failed to access process"
        );
    }

    #[test]
    fn test_kill2() {
        let mut child = Command::new("perl").arg("-e").arg(SCRIPT).spawn().unwrap();
        let pid = Pid::from_raw(child.id() as i32);
        let mut reader = ProcReader::from_stdout(pid);

        thread::sleep(Duration::from_secs(2));
        let _ = child.kill();
        thread::sleep(Duration::from_secs(2));

        let mut buf = [0; 10];
        let ret = reader.read_exact(&mut buf);
        assert_eq!(
            &format!("{:?}", ret)[0..80],
            "Err(Custom { kind: UnexpectedEof, error: StringError(\"failed to fill whole buffe"
        );
    }

    #[test]
    fn test_stderr() {
        let child = Command::new("perl")
            .arg("-e")
            .arg(SCRIPT_WITH_ERR)
            .spawn()
            .unwrap();
        let pid = Pid::from_raw(child.id() as i32);
        let mut reader = BufReader::new(ProcReader::from_stderr(pid));

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
        let pid = Pid::from_raw(child.id() as i32);
        let mut reader = BufReader::new(ProcReader::from_stdany(pid));

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
        let pid = Pid::from_raw(child.id() as i32);
        let mut reader = BufReader::new(ProcReader::from_stdout(pid));

        thread::sleep(Duration::from_secs(4));

        let mut line = String::new();
        let _ = reader.read_to_string(&mut line);
        assert_eq!("aaa\nbbb\n", line);
    }

    #[test]
    fn test_stdout_with_redirect() {
        let child = Command::new("sh")
            .arg("-c")
            .arg(SCRIPT_REDIRECT)
            .spawn()
            .unwrap();
        let pid = Pid::from_raw(child.id() as i32);
        let mut reader = BufReader::new(ProcReader::from_stdout(pid).with_redirect());

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
        let pid = Pid::from_raw(child.id() as i32);
        let mut reader = BufReader::new(ProcReader::from_stderr(pid));

        thread::sleep(Duration::from_secs(4));

        let mut line = String::new();
        let _ = reader.read_to_string(&mut line);
        assert_eq!("ccc\nddd\n", line);
    }

    #[test]
    fn test_stderr_with_redirect() {
        let child = Command::new("sh")
            .arg("-c")
            .arg(SCRIPT_REDIRECT)
            .spawn()
            .unwrap();
        let pid = Pid::from_raw(child.id() as i32);
        let mut reader = BufReader::new(ProcReader::from_stderr(pid).with_redirect());

        thread::sleep(Duration::from_secs(4));

        let mut line = String::new();
        let _ = reader.read_to_string(&mut line);
        assert_eq!("bbb\nddd\n", line);
    }
}
