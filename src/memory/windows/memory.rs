use std::io;

use crate::memory::platform;

#[cfg(target_os = "windows")]
platform {
    use std::{io, mem};
    use winapi::shared::minwindef::{DWORD, FALSE, HMODULE, MAX_PATH};
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::memoryapi::{ReadProcessMemory, WriteProcessMemory};
    use winapi::um::processthreadsapi::OpenProcess;
    use winapi::um::psapi::{
        EnumProcessModules, EnumProcesses, GetModuleFileNameExA, GetModuleInformation, MODULEINFO,
    };
    use winapi::um::winnt::{
        HANDLE, PROCESS_ALL_ACCESS, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    pub struct ProcessPlatform {
        pub pid: i32,
        handle: HANDLE,
    }

    impl ProcessPlatform {
        pub fn new(pid: i32) -> io::Result<Self> {
            let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid as DWORD) };
            if handle.is_null() {
                return Err(io::Error::last_os_error());
            }
            Ok(Process { pid, handle })
        }

        impl Drop for Platform {
            fn drop(&mut self) {
                unsafe {
                    CloseHandle(self.handle);
                }
            }
        }

        fn get_module_handle(&self, module: &str) -> io::Result<HMODULE> {
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
                    return Err(io::Error::last_os_error());
                }

                let count = cb_needed as usize / mem::size_of::<HMODULEL>();
                for &hmodule in &modules[..count] {
                    let mut file_name = vec![0i8; MAX_PATH];
                    GetModuleFileNameExA(
                        self.handle,
                        hmodule,
                        file_name.as_mut_ptr(),
                        MAX_PATH as DWORD,
                    );
                    let name_str = std::ffi::CStr::from_ptr(file_name.as_ptr())
                        .to_string_lossy()
                        .to_lowercase();
                    let base_name = std::path::Path::new(name_str.as_str())
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string();
                    if base_name == module.to_lowercase() {
                        return Ok(hmodule);
                    }
                }
            }
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Failed to find module",
            ))
        }

        pub fn get_module_size(&self, module: &str) -> io::Result<usize> {
            unsafe {
                let hmodule = self.get_module_handle(module)?;
                let mut info: MODULEINFO = mem::zeroed();
                GetModuleInformation(
                    self.handle,
                    hmodule,
                    &mut info,
                    mem::size_of::<MODULEINFO>() as DWORD,
                );
                Ok(info.SizeOfImage as usize)
            };
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Failed to get module size",
            ))
        }

        pub fn read_memory_range(&self, addr: usize, size: usize) -> io::Result<Vec<u8>> {
            let mut buf = vec![0u8; size];
            let mut bytes_read = 0usize;
            let result = unsafe {
                ReadProcessMemory(self.handle, addr as *const _, buf.as_mut_ptr() as * mut _, size, &mut bytes_read)
            };
            if result == FALSE {
                return Err(io::Error::last_os_error());
            }
            buf.truncate(bytes_read);
            Ok(buf)
        }

        pub fn read_memory<T: Copy>(&self, address: usize) -> io::Result<T> {
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
        pub fn write_memory<T: Copy>(&self, address: usize, value: &T) -> io::Result<()> {
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
}
