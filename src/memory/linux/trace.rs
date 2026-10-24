use libc::user_regs_struct;
use nix::sys::ptrace;
use nix::sys::signal::Signal::SIGTRAP;
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::Pid;
use std::io;

#[derive(Default)]
pub struct InputRegisters {
    pub rip: u64,
    pub rax: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
}

impl InputRegisters {
    pub fn to_libc_user_regs(&self, saved_regs: libc::user_regs_struct) -> libc::user_regs_struct {
        let mut regs = saved_regs;

        regs.rax = self.rax;
        regs.orig_rax = u64::MAX;
        regs.rdi = self.rdi;
        regs.rsi = self.rsi;
        regs.rdx = self.rdx;
        regs.r10 = self.r10;
        regs.r9 = self.r9;
        regs.r8 = self.r8;

        regs
    }
}

pub struct PtraceGuard {
    pid: Pid,
}

impl PtraceGuard {
    pub fn attach(pid: Pid) -> io::Result<Self> {
        ptrace::attach(pid)
            .inspect_err(|e| tracing::error!(error = %e, "ptrace failed to attach in guard"))?;
        let guard = Self { pid };
        match waitpid(pid, None).map_err(io::Error::from)? {
            WaitStatus::Stopped(..) => {
                tracing::info!(pid = pid.as_raw(), "ptrace attached");
                Ok(guard)
            }
            other => {
                tracing::error!(pid = pid.as_raw(), status = ?other, "unexpected wait status after attach");
                Err(io::Error::other(format!(
                    "unexpected wait status after attach: {other:?}"
                )))
            }
        }
    }
}

impl Drop for PtraceGuard {
    fn drop(&mut self) {
        let _ = ptrace::detach(self.pid, None);
        tracing::info!(pid = self.pid.as_raw(), "ptrace detached");
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
        let saved_regs = ptrace::getregs(pid).inspect_err(
            |e| tracing::error!(error = %e, "SyscallInjector::new failed to save registers"),
        )?;
        let rip = saved_regs.rip as *mut _;
        let saved_word = ptrace::read(pid, rip).inspect_err(|e| tracing::error!(error = %e, "SyscallInjector::new failed to read saved instruction pointer"))?;

        let mut patched = saved_word.to_le_bytes();
        patched[..3].copy_from_slice(&Self::STUB);
        ptrace::write(pid, rip, i64::from_le_bytes(patched)).inspect_err(|e| tracing::error!(error = %e, "SyscallInjector::new failed to write patch to instruction pointer"))?;

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

    // pub fn syscall(&self, nr: i64, args: [u64; 6]) -> io::Result<i64> {
    pub fn syscall(&self, new_regs: InputRegisters) -> io::Result<i64> {
        use crate::formatter::Hex;

        let pid = self.guard.pid;
        let saved_regs = self.saved_regs;
        let regs = new_regs.to_libc_user_regs(saved_regs);

        ptrace::setregs(pid, regs)
            .inspect_err(|e| tracing::error!(error = %e, "syscall failed to set registers"))?;
        ptrace::cont(pid, None)
            .inspect_err(|e| tracing::error!(error = %e, "syscall failed to continue process"))?;
        match waitpid(pid, None)? {
            WaitStatus::Stopped(_, SIGTRAP) => {
                tracing::debug!(pid = format_args!("{pid}"), "syscall waiting for")
            }
            other => {
                tracing::error!(pid = pid.as_raw(), regs.rax, status = ?other, "unexpected wait status during syscall");
                //self.fake_drop(true, false);
                return Err(io::Error::other(format!(
                    "unexpected wait status: {other:?}"
                )));
            }
        }

        let regs = match ptrace::getregs(pid) {
            Ok(regs) => {
                tracing::debug!("syscall ptrace getregs after cont was successful.");
                regs
            }
            Err(e) => {
                tracing::error!(error = %e, "syscall failed to get regs after continue");
                return Err(io::Error::from_raw_os_error(e as i32));
            }
        };

        let ret = regs.rax as i64;
        tracing::trace!(ret, "ret as i64");

        if (-4095..0).contains(&ret) {
            tracing::error!(
                pid = pid.as_raw(),
                rax = %Hex(regs.rax),
                ret,
                "remote syscall returned error"
            );
            Err(io::Error::from_raw_os_error(-ret as i32))
        } else {
            tracing::debug!(
                pid = pid.as_raw(),
                regs.rax,
                ret,
                "remote syscall successful"
            );
            Ok(ret)
        }
    }

    fn restore(&self) -> io::Result<bool> {
        use std::io::Error;

        use crate::formatter::Hex;
        let pid = self.guard.pid;

        match ptrace::write(pid, self.saved_regs.rip as *mut _, self.saved_word) {
            Ok(_) => {
                tracing::info!("restore successfully wrote instruction pointer");
            }
            Err(e) => {
                tracing::error!(
                    rip = %Hex(self.saved_regs.rip),
                    pid = format_args!("{pid:?}"),
                    word = self.saved_word,
                    error = %e,
                    "restore failed to write rip, aborting"
                );
                return Err(Error::other("restore failed to write rip"));
            }
        }

        match ptrace::setregs(pid, self.saved_regs) {
            Ok(_) => {
                tracing::info!("restore successfully set registers");
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "restore failed to set registers"
                );

                return Err(Error::other("restore failed to set registers"));
            }
        }

        Ok(true)
    }

    /* this yucky */
    fn fake_drop(&self, exit: bool, skip: bool) {
        if !skip {
            let restore_success = self.restore().unwrap();

            if !restore_success {
                tracing::error!(
                    restore_success = restore_success,
                    "restore failed, is process alive?"
                );
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
