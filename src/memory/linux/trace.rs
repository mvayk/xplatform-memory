use nix::sys::ptrace;
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::Pid;
use std::io;

pub struct PtraceGuard {
    pid: Pid,
}

impl PtraceGuard {
    pub fn attach(pid: Pid) -> io::Result<Self> {
        ptrace::attach(pid).map_err(io::Error::from)?;
        let guard = Self { pid };
        match waitpid(pid, None).map_err(io::Error::from)? {
            WaitStatus::Stopped(..) => Ok(guard),
            other => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("unexpected wait status after attach: {other:?}"),
            )),
        }
    }
}

impl Drop for PtraceGuard {
    fn drop(&mut self) {
        let _ = ptrace::detach(self.pid, None);
    }
}
