/* todo refactor*/

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
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported protection: {other:?}"),
            ));
        }
    })
}

impl ProcessPlatform {
    pub fn protect_memory(
        &self,
        addresses: &[u64],
        length: u64,
        protection: ProtectionType,
    ) -> io::Result<()> {
        let prot = match_protection(protection)? as u64;
        let injector = SyscallInjector::new(Pid::from_raw(self.pid))?;
        for &addr in addresses {
            injector.syscall(libc::SYS_mprotect, [addr, length, prot, 0, 0, 0])?;
        }
        Ok(())
    }
}
