use std::io;

use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE};

use crate::{
    types::{Address, ProtectionType::PAGE_EXECUTE_READWRITE},
    windows::{platform::ProcessPlatform, protection::match_protection},
};

impl ProcessPlatform {
    pub fn allocate_memory(&self) -> io::Result<Address> {
        use winapi::um::memoryapi::VirtualAllocEx;

        let addr = unsafe {
            VirtualAllocEx(
                self.handle,
                std::ptr::null_mut(),
                0,
                MEM_COMMIT | MEM_RESERVE,
                match_protection(PAGE_EXECUTE_READWRITE),
            )
        };

        if addr.is_null() {
            return Err(io::Error::last_os_error());
        }

        Ok(addr as Address)
    }
}
