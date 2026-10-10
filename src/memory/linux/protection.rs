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
        PAGE_READONLY => PROT_READ,
        PAGE_READWRITE => PROT_READ | PROT_WRITE,
    })
}

pub fn protection_to_string<'a>(protection: ProtectionType) -> io::Result<&'a str> {
    match protection {
        PAGE_NOACCESS => return Ok("PAGE_NOACCESS"),
        PAGE_EXECUTE => return Ok("PAGE_EXECUTE"),
        PAGE_EXECUTE_READ => return Ok("PAGE_EXECUTE_READ"),
        PAGE_EXECUTE_READWRITE => return Ok("PAGE_EXECUTE_READWRITE"),
        PAGE_READONLY => return Ok("PAGE_READONLY"),
        PAGE_READWRITE => return Ok("PAGE_READWRITE"),
        //_ => { return Err(io::Error::new( io::ErrorKind::InvalidInput, "failed to convert protectiontype to string: unknown flag provided",)); }
    }
}

impl ProcessPlatform {
    pub fn query_address_protection(&self, address: u64) -> io::Result<ProtectionType> {
        let page = self.get_page_from_address(address)?;
        Ok(page.protection_flag)
    }

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
                Ok(_) => tracing::info!(addr = format_args!("{addr:#x} as {protection:?}"), ""),
                Err(e) => {
                    tracing::error!(addr = format_args!("{addr:#x}"), error = %e, "syscall failed");
                    return Err(e);
                }
            }
        }
        Ok(())
    }
}
