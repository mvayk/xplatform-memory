use crate::utils::*;
use std::io;

#[cfg(target_os = "windows")]
use crate::windows::memory::platform;

#[cfg(target_os = "linux")]
use crate::linux::memory::platform;

pub struct Process {
    pub pid: i32,
    inner: platform::ProcessPlatform,
}

impl Process {
    pub fn new(name: &str) -> io::Result<Self> {
        let pid = platform::find_pid(name)?;
        let inner = platform::ProcessPlatform::new(pid)?;
        Ok(Process { pid, inner })
    }

    pub fn get_module_base(&self, module: &str) -> io::Result<usize> {
        self.inner.get_module_base(module)
    }

    pub fn get_module_size(&self, module: &str) -> io::Result<usize> {
        self.inner.get_module_size(module)
    }

    pub fn read_memory<T: Copy>(&self, address: usize) -> io::Result<T> {
        self.inner.read_memory(address)
    }

    pub fn read_memory_range(&self, address_start: usize, size: usize) -> io::Result<Vec<u8>> {
        self.inner.read_memory_range(address_start, size)
    }

    pub fn write_memory<T: Copy>(&self, address: usize, value: &T) -> io::Result<()> {
        self.inner.write_memory(address, value)
    }

    pub fn allocate_memory(&self, size: usize) -> io::Result<usize> {
        self.inner.allocate_memory(size)
    }

    pub fn scan_module(&self, module: &str, pattern: &str) -> io::Result<usize> {
        let module_base = self.get_module_base(module)?;
        let module_size = self.get_module_size(module)?;
        let memory = self.read_memory_range(module_base, module_size)?;
        let parsed = parse_pattern(pattern);

        pattern_scan_all(&memory, &parsed)
            .first()
            .map(|&offset| module_base + offset)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Pattern not found"))
    }
}
