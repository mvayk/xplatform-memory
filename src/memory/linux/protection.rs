/* todo refactor*/
use crate::memory::definitions::ProtectionType;
use crate::memory::linux::platform::ProcessPlatform;
use crate::memory::utils::ctx;
use libc::{PROT_EXEC, PROT_NONE, PROT_READ, PROT_WRITE, user_regs_struct};
use nix::sys::ptrace;
use nix::sys::signal::Signal::SIGTRAP;
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::Pid;
use std::io;

impl ProcessPlatform {
    pub fn protect_memory(
        &self,
        addresses: Vec<u64>,
        length: u64,
        protection: ProtectionType,
    ) -> io::Result<()> {
        let prot: i32 = match protection {
            ProtectionType::PAGE_EXECUTE => PROT_EXEC,
            ProtectionType::PAGE_EXECUTE_READ => PROT_READ | PROT_EXEC,
            ProtectionType::PAGE_EXECUTE_READWRITE => PROT_READ | PROT_EXEC | PROT_WRITE,
            ProtectionType::PAGE_NOACCESS => PROT_NONE,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Failed to match protection",
                ));
            }
        };

        let pid = Pid::from_raw(self.pid);

        ptrace::attach(pid).map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e))?;
        waitpid(pid, None).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let original_registers: user_regs_struct = ctx("getregs (start)", ptrace::getregs(pid))?;
        let rip = original_registers.rip;
        let original_word = ctx("original_word: ", ptrace::read(pid, rip as *mut _))?;

        let mut patched = (original_word as usize).to_le_bytes();
        patched[0] = 0x0f;
        patched[1] = 0x05; /* syscall */
        patched[2] = 0xcc; /* int3    */
        ptrace::write(pid, rip as *mut _, i64::from_le_bytes(patched))?;

        let mut result: io::Result<()> = Ok(());

        for &addr in &addresses {
            let mut registers = original_registers;
            registers.rax = libc::SYS_mprotect as u64;
            registers.orig_rax = u64::MAX;
            registers.rdi = addr;
            registers.rsi = length;
            registers.rdx = prot as u64;
            registers.rip = rip;

            let step = (|| -> io::Result<i64> {
                ptrace::setregs(pid, registers)?;
                ptrace::cont(pid, None)?;
                match waitpid(pid, None)? {
                    WaitStatus::Stopped(_, SIGTRAP) => {}
                    other => {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            format!("unexpected wait status: {:?}", other),
                        ));
                    }
                }
                Ok(ptrace::getregs(pid)?.rax as i64)
            })();

            match step {
                Ok(ret) if ret < 0 => {
                    result = Err(io::Error::from_raw_os_error(-ret as i32));
                    break;
                }
                Ok(_) => {}
                Err(e) => {
                    result = Err(e);
                    break;
                }
            }
        }

        ptrace::write(pid, rip as *mut _, original_word)?;
        ptrace::setregs(pid, original_registers)?;
        ptrace::detach(pid, None).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        result
    }
}
