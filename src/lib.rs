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
        ProcAccessFailed(pid: Pid) {
            description("process access failed")
            display("failed to access process ({})\n", pid)
        }
    }
    foreign_links {
        Nix(::nix::Error);
        Recv(::std::sync::mpsc::RecvError);
        Send(::std::sync::mpsc::SendError<Vec<u8>>);
    }
}

// -------------------------------------------------------------------------------------------------
// ProcReader
// -------------------------------------------------------------------------------------------------

enum ProcReaderMsg {
    Stop,
}

pub struct ProcReader {
    ctl: Sender<ProcReaderMsg>,
    buf: Receiver<Vec<u8>>,
    err: Receiver<Error>,
    child: Option<JoinHandle<()>>,
    rest: Vec<u8>,
}

impl ProcReader {
    pub fn new(pid: Pid) -> Self {
        let (ctl_tx, ctl_rx) = channel();
        let (buf_tx, buf_rx) = channel();
        let (err_tx, err_rx) = channel();

        let child = thread::spawn(move || {
            match ProcReader::collect(pid, ctl_rx, buf_tx) {
                Err(x) => {
                    let _ = err_tx.send(x);
                }
                _ => (),
            }
        });

        ProcReader {
            ctl: ctl_tx,
            buf: buf_rx,
            err: err_rx,
            child: Some(child),
            rest: Vec::new(),
        }
    }

    fn collect(pid: Pid, ctl_rx: Receiver<ProcReaderMsg>, buf_tx: Sender<Vec<u8>>) -> Result<()> {
        attach(pid).chain_err(|| ErrorKind::ProcAccessFailed(pid))?;
        ProcReader::set_tracesysgood(pid).chain_err(|| ErrorKind::ProcAccessFailed(pid))?;

        let mut is_enter_stop = false;
        let mut prev_orig_rax = 0;
        loop {
            match waitpid(pid, None).chain_err(|| ErrorKind::ProcAccessFailed(pid))? {
                WaitStatus::PtraceSyscall(_) => {
                    let regs = ProcReader::get_regs(pid).chain_err(|| ErrorKind::ProcAccessFailed(pid))?;

                    is_enter_stop = if prev_orig_rax == regs.orig_rax {
                        !is_enter_stop
                    } else {
                        true
                    };
                    prev_orig_rax = regs.orig_rax;
                    if regs.orig_rax == libc::SYS_write as u64 && is_enter_stop {
                        let out = ProcReader::peek_bytes(pid, regs.rsi, regs.rdx);
                        buf_tx.send(out)?;
                    }
                }
                WaitStatus::Exited(_, _) => break,
                _ => (),
            }

            match ctl_rx.try_recv() {
                Ok(ProcReaderMsg::Stop) => {
                    detach(pid).chain_err(|| ErrorKind::ProcAccessFailed(pid))?;
                    break;
                }
                _ => syscall(pid).chain_err(|| ErrorKind::ProcAccessFailed(pid))?,
            }
        }
        Ok(())
    }

    fn set_tracesysgood(pid: Pid) -> Result<()> {
        loop {
            match waitpid(pid, None).chain_err(|| ErrorKind::ProcAccessFailed(pid))? {
                WaitStatus::Stopped(_, Signal::SIGSTOP) => {
                    setoptions(pid, Options::PTRACE_O_TRACESYSGOOD).chain_err(|| ErrorKind::ProcAccessFailed(pid))?;
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
            Err(std::io::Error::new(std::io::ErrorKind::Other, format!("{}", err)))
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

    #[test]
    fn test_bufreader() {
        let child = Command::new("./script/echo.sh").spawn().unwrap();
        let pid = Pid::from_raw(child.id() as i32);
        let mut reader = BufReader::new(ProcReader::new(pid));

        thread::sleep(Duration::from_secs(4));

        let mut line = String::new();
        let _ = reader.read_to_string(&mut line);
        assert_eq!( "aaa\nbbb\nccc\n", line);
    }

    #[test]
    fn test_short_array() {
        let child = Command::new("./script/echo.sh").spawn().unwrap();
        let pid = Pid::from_raw(child.id() as i32);
        let mut reader = ProcReader::new(pid);

        thread::sleep(Duration::from_secs(4));

        let mut buf = [0;10];
        let _ = reader.read_exact(&mut buf);
        assert_eq!("aaa\nbbb\ncc", String::from_utf8(buf.to_vec()).unwrap());
    }

    #[test]
    fn test_kill() {
        let mut child = Command::new("./script/echo.sh").spawn().unwrap();
        let pid = Pid::from_raw(child.id() as i32);
        let mut reader = ProcReader::new(pid);
        let _ = child.kill();

        thread::sleep(Duration::from_secs(4));

        let mut buf = [0;10];
        let ret = reader.read_exact(&mut buf);
        assert_eq!(&format!("{:?}", ret)[0..70], "Err(Custom { kind: Other, error: StringError(\"failed to access process");
    }

    #[test]
    fn test_kill2() {
        let mut child = Command::new("./script/echo.sh").spawn().unwrap();
        let pid = Pid::from_raw(child.id() as i32);
        let mut reader = ProcReader::new(pid);

        thread::sleep(Duration::from_secs(2));
        let _ = child.kill();
        thread::sleep(Duration::from_secs(2));

        let mut buf = [0;10];
        let ret = reader.read_exact(&mut buf);
        assert_eq!(&format!("{:?}", ret)[0..80], "Err(Custom { kind: UnexpectedEof, error: StringError(\"failed to fill whole buffe");
    }
}
