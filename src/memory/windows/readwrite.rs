use std::{io, mem};

use winapi::{
    shared::minwindef::FALSE,
    um::memoryapi::{ReadProcessMemory, WriteProcessMemory},
};

use crate::{types::Address, windows::platform::ProcessPlatform};

impl ProcessPlatform {
    pub fn read_memory<T: Copy>(&self, address: Address) -> io::Result<T> {
        let mut buffer: T = unsafe { mem::zeroed() };
        let mut bytes_read = 0usize;
        let result = unsafe {
            ReadProcessMemory(
                self.handle,
                address as *const _,
                &mut buffer as *mut _ as *mut _,
                mem::size_of::<T>(),
                &mut bytes_read,
            )
        };
        if result == FALSE {
            return Err(io::Error::last_os_error());
        }
        Ok(buffer)
    }

    pub fn write_memory<T: Copy>(&self, address: Address, value: &T) -> io::Result<()> {
        let mut bytes_written = 0usize;
        let result = unsafe {
            WriteProcessMemory(
                self.handle,
                address as *mut _,
                value as *const _ as *const _,
                mem::size_of::<T>(),
                &mut bytes_written,
            )
        };
        if result == FALSE {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}
