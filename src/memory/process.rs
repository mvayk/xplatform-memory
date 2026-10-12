use crate::types::{Address, Module, Pod, ProtectionType};

use std::io;

#[cfg(target_os = "windows")]
use crate::memory::windows::memory::platform;

#[cfg(target_os = "linux")]
use crate::memory::linux::platform;

pub struct Process {
    pub pid: i32,
    pub inner: platform::ProcessPlatform,
}

impl Process {
    pub fn new(name: &str) -> io::Result<Self> {
        let pid = platform::ProcessPlatform::find_pid(name)?;
        let inner = platform::ProcessPlatform::new(pid)?;
        Ok(Process { pid, inner })
    }

    pub fn get_module(&self, module_name: &str) -> io::Result<Module<'_>> {
        let module_platform = self.inner.get_module(module_name)?;

        Ok(Module {
            name: module_platform.name.to_string(),
            process: self,
            address: module_platform.address,
        })
    }

    pub fn get_module_base(&self, module_name: &str) -> io::Result<Address> {
        let module_platform = self.inner.get_module(module_name)?;
        Ok(module_platform.address.start)
    }

    pub fn read_memory<T: Pod>(&self, address: Address) -> io::Result<T> {
        self.inner.read_memory(address)
    }

    pub fn write_memory<T: Pod>(&self, address: Address, value: &T) -> io::Result<()> {
        self.inner.write_memory(address, value)
    }

    /* TODO: signature scanning, protect memory, allocate memory, free memory, so injection */
    pub fn protect_memory(
        &self,
        addresses: &[Address],
        length: usize,
        protection: ProtectionType,
    ) -> io::Result<()> {
        self.inner
            .protect_memory(addresses, length as u64, protection)
    }

    pub fn allocate_memory() -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::Other, "Not implemented"))
    }

    pub fn free_memory() -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Other, "Not implemented"))
    }

    pub fn get_memory_protection(&self, address: Address) -> io::Result<ProtectionType> {
        self.inner.query_address_protection(address)
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        tracing::info!("xplatform-memory exited");
    }
}
