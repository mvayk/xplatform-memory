use nix::unistd::Pid;
use std::io;

use crate::{
    linux::{
        platform::ProcessPlatform,
        protection::match_protection,
        trace::{InputRegisters, SyscallInjector},
    },
    types::{Address, ProtectionType},
};

impl ProcessPlatform {
    pub fn allocate_memory(&self) -> io::Result<Address> {
        let injector = SyscallInjector::new(Pid::from_raw(self.pid))?;

        let prot = match_protection(ProtectionType::PAGE_EXECUTE_READWRITE) as u64;
        let new_regs = InputRegisters {
            rax: libc::SYS_mmap as u64,
            rdi: 0,
            rsi: 1u64, /* im not sure about this, but pretty sure that mmap can at minimum allocate a page so a single page is probably enough */
            rdx: prot,
            r10: (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64,
            r8: -1i64 as u64,
            r9: 0,
            ..Default::default()
        };

        match injector.syscall(new_regs) {
            Ok(ret) if ret < 0 => {
                tracing::error!(ret, "allocate_memory failed");
                Err(io::Error::from_raw_os_error(-ret as i32))
            }
            Ok(ptr) => {
                tracing::info!(
                    memory_address = format_args!("{ptr:#x}"),
                    "allocate_memory received success"
                );
                Ok(ptr as Address)
            }
            Err(e) => {
                tracing::error!(error = %e, "syscall failed");
                Err(e)
            }
        }
    }
}
