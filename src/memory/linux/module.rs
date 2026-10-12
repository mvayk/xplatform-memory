use crate::memory::{definitions::Address, linux::platform::ProcessPlatform};
use std::{fs, io};

fn get_module_base(pid: i32, module_name: &str) -> io::Result<Address> {
    let maps = fs::read_to_string(format!("/proc/{}/maps", pid))?;
    for line in maps.lines() {
        if line.contains(module_name) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            let addresses: Vec<&str> = parts[0].split('-').collect();
            let base = Address::from_str_radix(addresses[0], 16).unwrap();

            tracing::info!(
                module_name,
                base = format_args!("{base:#x}"),
                "get_module_base successful"
            );
            return Ok(base);
        }
    }
    tracing::error!(module_name, "get_module_base failed");
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "Failed to find module base",
    ))
}

#[derive(Clone)]
pub struct ModuleP {
    pub name: String,
    pub base_address: Address,
}

impl ProcessPlatform {
    pub fn get_module(&self, module_name: &str) -> io::Result<ModuleP> {
        let base_address: Address = get_module_base(self.pid, module_name)?;

        Ok(ModuleP {
            name: module_name.to_string(),
            base_address,
        })
    }
}
