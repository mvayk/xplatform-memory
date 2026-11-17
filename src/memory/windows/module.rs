use std::mem;

use std::io;
use winapi::shared::minwindef::DWORD;
use winapi::shared::minwindef::FALSE;
use winapi::shared::minwindef::HMODULE;
use winapi::shared::minwindef::MAX_PATH;
use winapi::um::psapi::EnumProcessModules;
use winapi::um::psapi::GetModuleFileNameExA;
use winapi::um::psapi::{GetModuleInformation, MODULEINFO};

use crate::formatter::Hex;
use crate::types::Address;
use crate::types::AddyRange;
use crate::windows::platform::ProcessPlatform;

#[derive(Clone)]
pub struct ModuleP<'a> {
    pub name: String,
    pub handle: HMODULE,
    pub process: &'a ProcessPlatform,
    pub addresses: AddyRange,
}

impl<'a> ModuleP<'a> {
    pub fn get_range(&self) -> io::Result<AddyRange> {
        self.process.get_module_range(self.handle)
    }
}

impl ProcessPlatform {
    pub fn get_module_range(&self, hmodule: HMODULE) -> io::Result<AddyRange> {
        unsafe {
            let mut info: MODULEINFO = mem::zeroed();
            if GetModuleInformation(
                self.handle,
                hmodule,
                &mut info,
                mem::size_of::<MODULEINFO>() as DWORD,
            ) == 0
            {
                tracing::error!("failed to get module range, failed to find hmodule handle");
                return Err(io::Error::last_os_error());
            }

            tracing::info!(
                base = %Hex(info.lpBaseOfDll as u64),
                size = info.SizeOfImage,
                "module range found"
            );
            Ok(AddyRange::from_len(
                info.lpBaseOfDll as Address,
                info.SizeOfImage as u64,
            ))
        }
    }

    pub fn get_module(&self, module: &str) -> io::Result<ModuleP<'_>> {
        unsafe {
            let mut modules: Vec<HMODULE> = vec![std::ptr::null_mut(); 1024];
            let mut cb_needed: DWORD = 0;

            if EnumProcessModules(
                self.handle,
                modules.as_mut_ptr(),
                (modules.len() * mem::size_of::<HMODULE>()) as DWORD,
                &mut cb_needed,
            ) == FALSE
            {
                tracing::error!("failed to get module");
                return Err(io::Error::last_os_error());
            }

            let count = (cb_needed as usize / mem::size_of::<HMODULE>()).min(modules.len());
            let wanted = module.to_lowercase();

            for &hmodule in &modules[..count] {
                let mut file_name = vec![0i8; MAX_PATH];
                let len = GetModuleFileNameExA(
                    self.handle,
                    hmodule,
                    file_name.as_mut_ptr(),
                    MAX_PATH as DWORD,
                );
                if len == 0 {
                    tracing::trace!("skipping module filename, continuing");
                    continue;
                }

                let name_str = std::ffi::CStr::from_ptr(file_name.as_ptr())
                    .to_string_lossy()
                    .to_lowercase();
                let base_name = std::path::Path::new(&name_str)
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy();

                if base_name == wanted.as_str() {
                    let modulep = ModuleP {
                        name: module.to_string(),
                        handle: hmodule,
                        process: self,
                        addresses: self.get_module_range(hmodule)?,
                    };
                    tracing::info!(
                        module_name = modulep.name,
                        base = %Hex(modulep.addresses.start),
                        pid = self.pid,
                        "get_module successful"
                    );

                    return Ok(modulep);
                }
            }
        }
        tracing::error!("failed to find module");
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Failed to find module",
        ))
    }
}
