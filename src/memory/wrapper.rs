use std::io;

#[cfg(target_os = "windows")]
use crate::memory::windows::memory::platform;

#[cfg(target_os = "linux")]
use crate::memory::definitions::ProtectionType;
use crate::memory::linux::page::Page;
use crate::memory::linux::platform;

pub struct Process {
    pub pid: i32,
    process: platform::ProcessPlatform,
}

impl Process {
    pub fn new(name: &str) -> io::Result<Self> {
        use crate::memory::formatter::construct_formatter;
        construct_formatter();
        let pid = platform::ProcessPlatform::find_pid(name)?;
        let process = platform::ProcessPlatform::new(pid)?;
        Ok(Process { pid, process })
    }

    pub fn get_module_base(&self, module: &str) -> io::Result<usize> {
        self.process.get_module_base(module)
    }

    pub fn read_memory<T: Copy>(&self, address: usize) -> io::Result<T> {
        self.process.read_memory(address)
    }

    pub fn write_memory<T: Copy>(&self, address: usize, value: &T) -> io::Result<()> {
        self.process.write_memory(address, value)
    }

    /* TODO: signature scanning, protect memory, allocate memory, free memory, so injection */
    pub fn protect_memory(
        &self,
        addresses: Vec<u64>,
        length: usize,
        protection: ProtectionType,
    ) -> io::Result<()> {
        self.process
            .protect_memory(addresses, length as u64, protection)
    }

    pub fn allocate_memory() -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::Other, "Not implemented"))
    }

    pub fn free_memory() -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Other, "Not implemented"))
    }

    pub fn get_all_addresses(&self) -> io::Result<Vec<usize>> {
        self.process.get_all_addresses()
    }

    pub fn get_all_pages(&self) -> io::Result<Vec<Page>> {
        self.process.get_all_pages()
    }

    pub fn get_readable_regions(&self) -> io::Result<Vec<(usize, usize)>> {
        self.process.get_readable_regions()
    }

    pub fn get_memory_protection(&self, address: u64) -> io::Result<ProtectionType> {
        self.process.query_address_protection(address)
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        tracing::info!("xplatform-memory exited");
    }
}
