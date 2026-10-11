use crate::memory::{
    definitions::Address, definitions::Module, linux::platform::ProcessPlatform, wrapper::Process,
};
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

impl<'a> Module<'a> {
    pub fn new(process: &'a Process, module_name: &str) -> io::Result<Self> {
        let base_address: Address = get_module_base(process.pid, module_name)?;

        Ok(Module {
            name: module_name.to_string(),
            process,
            base_address,
        })
    }
}

impl ProcessPlatform {
    pub fn get_module<'a>(
        &self,
        process: &'a Process,
        module_name: &str,
    ) -> io::Result<Module<'a>> {
        Module::new(process, module_name)
    }
}
