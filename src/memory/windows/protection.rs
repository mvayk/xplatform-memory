use std::{ffi::c_void, io};

use winapi::{
    shared::minwindef::DWORD,
    um::{
        memoryapi::VirtualProtectEx,
        winnt::{MEM_COMMIT, MEM_RESERVE},
    },
};

use crate::{
    types::{
        Address,
        ProtectionType::{self},
    },
    windows::platform::ProcessPlatform,
};

pub fn match_protection(p: ProtectionType) -> DWORD {
    match p {
        ProtectionType::PAGE_EXECUTE => winapi::um::winnt::PAGE_EXECUTE,
        ProtectionType::PAGE_EXECUTE_READ => winapi::um::winnt::PAGE_EXECUTE_READ,
        ProtectionType::PAGE_EXECUTE_READWRITE => winapi::um::winnt::PAGE_EXECUTE_READWRITE,
        ProtectionType::PAGE_NOACCESS => winapi::um::winnt::PAGE_NOACCESS,
        ProtectionType::PAGE_READONLY => winapi::um::winnt::PAGE_READONLY,
        ProtectionType::PAGE_READWRITE => winapi::um::winnt::PAGE_READWRITE,
    }
}

impl ProcessPlatform {
    pub fn protect_memory(
        &self,
        address: &[Address],
        size: usize,
        protection: ProtectionType,
    ) -> io::Result<()> {
        /* match protection type from our enum to winapi */
        let addr = unsafe {
            VirtualProtectEx(
                self.handle,
                std::ptr::null_mut(),
                size,
                MEM_COMMIT | MEM_RESERVE,
                match_protection(protection) as *mut u32,
            ) as *mut c_void
        };

        if addr.is_null() {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }
}
