use crate::memory::linux::platform::ProcessPlatform;
use std::{fs, io};

impl ProcessPlatform {
    pub fn get_module_base(&self, module: &str) -> io::Result<usize> {
        let maps = fs::read_to_string(format!("/proc/{}/maps", self.pid))?;
        for line in maps.lines() {
            if line.contains(module) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                let addresses: Vec<&str> = parts[0].split('-').collect();
                let base = usize::from_str_radix(addresses[0], 16).unwrap();

                tracing::info!(
                    module,
                    base = format_args!("{base:#x}"),
                    "get_module_base ok"
                );
                return Ok(base);
            }
        }
        tracing::warn!(module, "get_module_base failed");
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Failed to find module base",
        ))
    }
}
