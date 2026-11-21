use bytemuck::Pod;
use std::io::{self};

use crate::{
    formatter::Hex,
    types::{Address, Module, ProtectionType},
};

#[cfg(target_os = "windows")]
use crate::memory::windows::platform;

#[cfg(target_os = "linux")]
use crate::{linux::module::ModuleP, memory::linux::platform};

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

    pub fn get_module(&self, module_name: &str) -> io::Result<Module<'_, '_>> {
        let module_platform = self.inner.get_module(module_name)?;

        return Ok(Module {
            name: module_platform.name.to_string(),
            process: self,
            addresses: module_platform.addresses,
            inner: module_platform,
        });
    }

    pub fn get_module_base(&self, module_name: &str) -> io::Result<Address> {
        let module_platform = self.inner.get_module(module_name)?;
        let base = module_platform.addresses.start;
        //tracing::info!(%Hex(base), "found base");
        tracing::info!(
            base = format_args!("{}, {:#x}", module_name, base),
            "found base:"
        );
        Ok(base)
    }

    pub fn read_memory<T: Pod>(&self, address: Address) -> io::Result<T> {
        self.inner.read_memory::<T>(address)
    }

    pub fn write_memory<T: Copy>(&self, address: Address, data: T) -> io::Result<()> {
        self.inner.write_memory(address, &data)
    }

    pub fn query_address_protection(&self, address: Address) -> io::Result<ProtectionType> {
        self.inner.query_address_protection(address)
    }

    /* TODO: signature scanning, protect memory, allocate memory, free memory, so injection */
    pub fn protect_memory(
        &self,
        addresses: &[Address],
        length: usize,
        protection: ProtectionType,
    ) -> io::Result<()> {
        self.inner.protect_memory(addresses, length, protection)
    }

    pub fn allocate_memory(&self) -> io::Result<Address> {
        self.inner.allocate_memory() /* allocates a page */
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        tracing::info!(self.pid, "dropped");
    }
}
