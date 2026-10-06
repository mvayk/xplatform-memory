use libc::user_regs_struct;
use nix::sys::ptrace;
use nix::sys::signal::Signal::SIGTRAP;
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::Pid;
use std::{io, process};

pub struct PtraceGuard {
    pid: Pid,
}

impl PtraceGuard {
    pub fn attach(pid: Pid) -> io::Result<Self> {
        ptrace::attach(pid).map_err(io::Error::from)?;
        let guard = Self { pid };
        match waitpid(pid, None).map_err(io::Error::from)? {
            WaitStatus::Stopped(..) => {
                tracing::warn!(pid = pid.as_raw(), "ptrace attached");
                Ok(guard)
            }
            other => {
                tracing::error!(pid = pid.as_raw(), status = ?other, "unexpected wait status after attach");
                Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("unexpected wait status after attach: {other:?}"),
                ))
            }
        }
    }
}

impl Drop for PtraceGuard {
    fn drop(&mut self) {
        let _ = ptrace::detach(self.pid, None);
        tracing::warn!(pid = self.pid.as_raw(), "ptrace detached");
    }
}

#[cfg(target_arch = "x86_64")]
pub struct SyscallInjector {
    guard: PtraceGuard,
    saved_regs: user_regs_struct,
    saved_word: i64,
}

#[cfg(target_arch = "x86_64")]
impl SyscallInjector {
    const STUB: [u8; 3] = [0x0f, 0x05, 0xcc]; /* syscall; int3 */

    pub fn new(pid: Pid) -> io::Result<Self> {
        let guard = PtraceGuard::attach(pid)?;
        let saved_regs = ptrace::getregs(pid)?;
        let rip = saved_regs.rip as *mut _;
        let saved_word = ptrace::read(pid, rip)?;

        let mut patched = saved_word.to_le_bytes();
        patched[..3].copy_from_slice(&Self::STUB);
        ptrace::write(pid, rip, i64::from_le_bytes(patched))?;

        tracing::info!(
            pid = pid.as_raw(),
            rip = format_args!("{:#x}", saved_regs.rip),
            "syscall stub patched in"
        );

        Ok(Self {
            guard,
            saved_regs,
            saved_word,
        })
    }

    pub fn syscall(&self, nr: i64, args: [u64; 6]) -> io::Result<i64> {
        let pid = self.guard.pid;
        let mut regs = self.saved_regs;
        regs.rax = nr as u64;
        regs.orig_rax = u64::MAX;
        regs.rdi = args[0];
        regs.rsi = args[1];
        regs.rdx = args[2];
        regs.r10 = args[3];
        regs.r8 = args[4];
        regs.r9 = args[5];

        ptrace::setregs(pid, regs)?;
        ptrace::cont(pid, None)?;
        match waitpid(pid, None)? {
            WaitStatus::Stopped(_, SIGTRAP) => {}
            other => {
                tracing::error!(pid = pid.as_raw(), nr, status = ?other, "unexpected wait status during syscall");
                //self.fake_drop(true, false);
                return Err(io::Error::other(format!(
                    "unexpected wait status: {other:?}"
                )));
            }
        }

        let ret = ptrace::getregs(pid)?.rax as i64;
        if (-4095..0).contains(&ret) {
            tracing::error!(pid = pid.as_raw(), nr, ret, "remote syscall returned error");
            Err(io::Error::from_raw_os_error(-ret as i32))
        } else {
            tracing::info!(pid = pid.as_raw(), nr, ret, "remote syscall ok");
            Ok(ret)
        }
    }

    fn restore(&self) -> bool {
        let pid = self.guard.pid;
        let mut result;

        match ptrace::write(pid, self.saved_regs.rip as *mut _, self.saved_word) {
            Ok(_) => {
                tracing::info!("restore successfully wrote instruction pointer");
                result = true;
            }
            Err(e) => {
                tracing::error!(
                    rip = self.saved_regs.rip,
                    word = self.saved_word,
                    error = %e,
                    "restore failed to write rip"
                );
                //return Err(e.into());
                result = false;
            }
        }

        if result == false {
            tracing::warn!("restore aborting");
            return result;
        }

        match ptrace::setregs(pid, self.saved_regs) {
            Ok(_) => {
                tracing::info!("restore successfully set registers");
                result = true;
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "restore failed to set registers"
                );
                // return Err(e.into());
                result = false;
            }
        }

        return result;
    }

    /* this yucky */
    fn fake_drop(&self, exit: bool, skip: bool) {
        if skip == false {
            let restore_success = self.restore();
            match restore_success {
                false => tracing::error!(
                    restore_success = restore_success,
                    "restore failed, is process alive?"
                ),
                true => {}
            }
        }

        if exit {
            std::process::exit(0x0100);
        }
    }
}

#[cfg(target_arch = "x86_64")]
impl Drop for SyscallInjector {
    fn drop(&mut self) {
        self.fake_drop(false, false);
    }
}
