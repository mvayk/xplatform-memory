use crate::linux::page::Page;
use crate::linux::platform::ProcessPlatform;
use crate::linux::trace::{ASMInjector, InputRegisters};
use crate::types::{Address, ProtectionType, address_align_to_page_down};
use libc::{PROT_EXEC, PROT_NONE, PROT_READ, PROT_WRITE};
use nix::unistd::Pid;
use std::io;

use ProtectionType::*;

pub fn match_protection(p: ProtectionType) -> i32 {
    match p {
        PAGE_NOACCESS => PROT_NONE,
        PAGE_EXECUTE => PROT_EXEC,
        PAGE_EXECUTE_READ => PROT_READ | PROT_EXEC,
        PAGE_EXECUTE_READWRITE => PROT_READ | PROT_WRITE | PROT_EXEC,
        PAGE_READONLY => PROT_READ,
        PAGE_READWRITE => PROT_READ | PROT_WRITE,
        UNKNOWN => 0,
    }
}

impl ProcessPlatform {
    pub fn query_address_protection(&self, address: u64) -> io::Result<ProtectionType> {
        let page: Page = self.get_page_from_address(address)?;
        Ok(page.get_protection_flag())
    }

    pub fn protect_memory(
        &self,
        addresses: &[Address],
        length: usize,
        protection: ProtectionType,
    ) -> io::Result<()> {
        let prot = match_protection(protection) as u64;
        let injector = ASMInjector::new(Pid::from_raw(self.pid), false)?;
        for addr in addresses {
            let address = address_align_to_page_down(*addr);
            tracing::debug!(self.pid, "protect_memory called mprotect on:");
            let new_regs = InputRegisters {
                rax: libc::SYS_mprotect as u64,
                rdi: address,
                rsi: length as u64,
                rdx: prot,
                r10: 0,
                r9: 0,
                r8: 0,
                ..Default::default()
            };
            match injector.call(new_regs, false) {
                Ok(ret) if ret < 0 => {
                    tracing::error!(
                        addr = format_args!("{addr:#x}"),
                        ret,
                        "protect_memory: syscall returned failure"
                    );
                    return Err(io::Error::from_raw_os_error(-ret as i32));
                }
                Ok(_) => {
                    tracing::info!(
                        addr = format_args!("{addr:#x} as {protection:?}"),
                        "protect_memory"
                    )
                }
                Err(e) => {
                    tracing::error!(addr = format_args!("{address:#x}"), error = %e, "memory_protect: syscall MUNTED");
                    return Err(e);
                }
            }
        }
        Ok(())
    }
}
