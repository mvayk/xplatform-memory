use libc::user_regs_struct;
use nix::sys::ptrace;
use nix::sys::signal::Signal::{self, SIGTRAP};
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::Pid;
use std::cell::Cell;
use std::io;

#[derive(Debug)]
pub struct UnexpectedWaitStatus {
    pub status: WaitStatus,
}

impl std::fmt::Display for UnexpectedWaitStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unexpected wait status: {:?}", self.status)
    }
}

impl std::error::Error for UnexpectedWaitStatus {}

#[derive(Default)]
pub struct InputRegisters {
    pub rax: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rsp: u64,
    pub rip: u64,
}

impl InputRegisters {
    pub fn to_libc_user_regs(
        &self,
        saved_regs: libc::user_regs_struct,
        remote: bool,
    ) -> libc::user_regs_struct {
        let mut regs = saved_regs;

        if remote {
            regs.rsp = self.rsp;
            regs.rip = self.rip;
        }
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
    pending_signal: Cell<Option<Signal>>,
}

impl PtraceGuard {
    pub fn attach(pid: Pid) -> io::Result<Self> {
        ptrace::attach(pid)
            .inspect_err(|e| tracing::error!(error = %e, "ptrace failed to attach in guard"))?;
        let guard = Self {
            pid,
            pending_signal: Cell::new(None),
        };
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

    pub fn defer_signal(&self, sig: Signal) {
        self.pending_signal.set(Some(sig));
    }
}

impl Drop for PtraceGuard {
    fn drop(&mut self) {
        let sig = self.pending_signal.get();
        let _ = ptrace::detach(self.pid, sig);
        tracing::info!(pid = self.pid.as_raw(), ?sig, "ptrace detached");
    }
}

#[cfg(target_arch = "x86_64")]
pub struct ASMInjector {
    guard: PtraceGuard,
    pub saved_regs: user_regs_struct,
    saved_word: i64,
    pid: Pid,
    remote: bool,
}

#[cfg(target_arch = "x86_64")]
impl ASMInjector {
    const STUB: [u8; 3] = [0x0f, 0x05, 0xcc]; /* syscall; int3 */
    const REMOTE_FUNC_STUB: [u8; 8] = [0x41, 0xff, 0xd1, 0xcc, 0x00, 0x00, 0x00, 0x00];

    pub fn new(pid: Pid, remote: bool) -> io::Result<Self> {
        let guard = PtraceGuard::attach(pid)?;
        let saved_regs = ptrace::getregs(pid).inspect_err(
            |e| tracing::error!(error = %e, "ASMInjector::new failed to save registers"),
        )?;
        let rip = saved_regs.rip as *mut _;
        let saved_word = ptrace::read(pid, rip).inspect_err(|e| tracing::error!(error = %e, "ASMInjector::new failed to read saved instruction pointer"))?;

        let mut patched = saved_word.to_le_bytes();
        if remote {
            patched[..8].copy_from_slice(&Self::REMOTE_FUNC_STUB);
        } else {
            patched[..3].copy_from_slice(&Self::STUB);
        }
        ptrace::write(pid, rip, i64::from_le_bytes(patched)).inspect_err(|e| tracing::error!(error = %e, "ASMInjector::new failed to write patch to instruction pointer"))?;

        tracing::info!(
            pid = pid.as_raw(),
            rip = format_args!("{:#x}", saved_regs.rip),
            "stub patched in"
        );

        Ok(Self {
            guard,
            saved_regs,
            saved_word,
            pid,
            remote,
        })
    }

    /* call between uses */
    /* duplicate code yucm,yyy */
    pub fn update(&mut self) -> io::Result<()> {
        ptrace::write(self.pid, self.saved_regs.rip as *mut _, self.saved_word).inspect_err(
            |e| tracing::error!(error = %e, "ASMInjector::update failed to restore previous patch"),
        )?;

        let pid = self.pid;
        let remote = self.remote;
        let saved_regs = ptrace::getregs(pid).inspect_err(
            |e| tracing::error!(error = %e, "ASMInjector::update failed to save registers"),
        )?;
        let rip = saved_regs.rip as *mut _;
        let saved_word = ptrace::read(pid, rip).inspect_err(
            |e| tracing::error!(error = %e, "ASMInjector::update failed to read saved instruction"),
        )?;

        let mut patched = saved_word.to_le_bytes();
        if remote {
            patched[..8].copy_from_slice(&Self::REMOTE_FUNC_STUB);
        } else {
            patched[..3].copy_from_slice(&Self::STUB);
        }
        ptrace::write(pid, rip, i64::from_le_bytes(patched)).inspect_err(
            |e| tracing::error!(error = %e, "ASMInjector::update failed to write new patch"),
        )?;

        self.saved_regs = saved_regs;
        self.saved_word = saved_word;
        Ok(())
    }

    // pub fn syscall(&self, nr: i64, args: [u64; 6]) -> io::Result<i64> {
    pub fn call(&self, mut new_regs: InputRegisters, remote: bool) -> io::Result<i64> {
        use crate::formatter::Hex;

        let pid = self.guard.pid;
        let saved_regs = self.saved_regs;
        if remote {
            new_regs.rsp = saved_regs.rsp - 0x400 & !0xf;
            new_regs.rip = saved_regs.rip;
        }
        let regs = new_regs.to_libc_user_regs(saved_regs, remote);

        tracing::info!(
            new_regs_rip = %Hex(new_regs.rip),
            new_regs_r9 = %Hex(new_regs.r9),
            final_rip = %Hex(regs.rip),
            final_r9 = %Hex(regs.r9),
        );

        ptrace::setregs(pid, regs)
            .inspect_err(|e| tracing::error!(error = %e, "syscall failed to set registers"))?;

        let trap_addr = self.saved_regs.rip + 4;

        loop {
            ptrace::cont(pid, None).inspect_err(
                |e| tracing::error!(error = %e, "syscall failed to continue process"),
            )?;

            match waitpid(pid, None)? {
                WaitStatus::Stopped(_, SIGTRAP) => {
                    tracing::debug!(pid = format_args!("{pid}"), "syscall waiting for");
                    break;
                }
                WaitStatus::Stopped(_, sig) => {
                    let debug_regs = ptrace::getregs(pid)?;

                    if debug_regs.rip == trap_addr {
                        tracing::warn!(?sig, rip = %Hex(debug_regs.rip), "deferring incidental signal, call completed");
                        self.guard.defer_signal(sig);
                        break;
                    }

                    if matches!(
                        sig,
                        Signal::SIGSEGV | Signal::SIGABRT | Signal::SIGILL | Signal::SIGBUS
                    ) {
                        let siginfo = ptrace::getsiginfo(pid)?;
                        let si_addr_info = unsafe { siginfo.si_addr() as u64 };
                        tracing::error!(
                            pid = pid.as_raw(),
                            si_addr_info,
                            debug_regs.rax,
                            debug_regs.rip,
                            debug_regs.rsp,
                            ?sig,
                            "unexpected wait status during syscall"
                        );
                        return Err(io::Error::other(UnexpectedWaitStatus {
                            status: WaitStatus::Stopped(pid, sig),
                        }));
                    }

                    tracing::warn!(?sig, rip = %Hex(debug_regs.rip), "deferring unrelated signal, continuing wait");
                    self.guard.defer_signal(sig);
                }
                other => {
                    let siginfo = ptrace::getsiginfo(pid)?;
                    let debug_regs = ptrace::getregs(pid).inspect_err(
                |e| tracing::error!(error = %e, "ASMInjector::call waitpid debug regs get failed"),
            )?;
                    let si_addr_info = unsafe { siginfo.si_addr() as u64 };
                    tracing::error!(pid = pid.as_raw(), si_addr_info, debug_regs.rax, debug_regs.rip, debug_regs.rsp, status = ?other, "unexpected wait status during syscall");
                    return Err(io::Error::other(UnexpectedWaitStatus { status: other }));
                }
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
                regs.rip = %Hex(regs.rip),
                regs.rax = %Hex(regs.rax),
                ret,
                "remote syscall returned error"
            );
            Err(io::Error::from_raw_os_error(-ret as i32))
        } else {
            tracing::debug!(
                pid = pid.as_raw(),
                regs.rip = %Hex(regs.rip),
                regs.rax = %Hex(regs.rax),
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
impl Drop for ASMInjector {
    fn drop(&mut self) {
        self.fake_drop(false, false);
    }
}
