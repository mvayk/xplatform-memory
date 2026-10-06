use crate::memory::definitions::ProtectionType;
use crate::memory::linux::platform::ProcessPlatform;
use crate::memory::linux::trace::SyscallInjector;
use ProtectionType::*;
use libc::{PROT_EXEC, PROT_NONE, PROT_READ, PROT_WRITE};
use nix::unistd::Pid;
use std::io;

fn match_protection(p: ProtectionType) -> io::Result<i32> {
    Ok(match p {
        PAGE_NOACCESS => PROT_NONE,
        PAGE_EXECUTE => PROT_EXEC,
        PAGE_EXECUTE_READ => PROT_READ | PROT_EXEC,
        PAGE_EXECUTE_READWRITE => PROT_READ | PROT_WRITE | PROT_EXEC,
    })
}

impl ProcessPlatform {
    pub fn protect_memory(
        &self,
        addresses: Vec<u64>,
        length: u64,
        protection: ProtectionType,
    ) -> io::Result<()> {
        let prot = match_protection(protection)? as u64;
        let injector = SyscallInjector::new(Pid::from_raw(self.pid))?;
        for addr in addresses {
            match injector.syscall(libc::SYS_mprotect, [addr, length, prot, 0, 0, 0]) {
                Ok(ret) if ret < 0 => {
                    tracing::error!(addr = format_args!("{addr:#x}"), ret, "mprotect failed");
                    return Err(io::Error::from_raw_os_error(-ret as i32));
                }
                Ok(_) => tracing::info!(addr = format_args!("{addr:#x}"), "protected"),
                Err(e) => {
                    tracing::error!(addr = format_args!("{addr:#x}"), error = %e, "syscall failed");
                    return Err(e);
                }
            }
        }
        Ok(())
    }
}
