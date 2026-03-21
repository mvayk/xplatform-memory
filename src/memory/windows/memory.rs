#[cfg(target_os = "windows")]
pub mod platform {
    use std::ffi::CString;
    use std::{io, mem};
    use winapi::shared::minwindef::{DWORD, FALSE, HMODULE, MAX_PATH};
    use winapi::shared::windef::RECT;
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::memoryapi::{ReadProcessMemory, WriteProcessMemory};
    use winapi::um::processthreadsapi::OpenProcess;
    use winapi::um::psapi::{
        EnumProcessModules, EnumProcesses, GetModuleFileNameExA, GetModuleInformation, MODULEINFO,
    };
    use winapi::um::winnt::{
        HANDLE, PROCESS_ALL_ACCESS, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };
    use winapi::um::winuser::{FindWindowA, GetClientRect};

    pub fn find_pid(name: &str) -> io::Result<i32> {
        unsafe {
            let mut pids: Vec<DWORD> = vec![0u32; 1024];
            let mut bytes_returned: DWORD = 0;
            if EnumProcesses(
                pids.as_mut_ptr(),
                (pids.len() * mem::size_of::<DWORD>()) as DWORD,
                &mut bytes_returned,
            ) == FALSE
            {
                return Err(io::Error::last_os_error());
            }
            let count = bytes_returned as usize / mem::size_of::<DWORD>();
            for &pid in &pids[..count] {
                let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
                if handle.is_null() {
                    continue;
                }
                let mut module: HMODULE = std::ptr::null_mut();
                let mut cb_needed: DWORD = 0;
                if EnumProcessModules(
                    handle,
                    &mut module,
                    mem::size_of::<HMODULE>() as DWORD,
                    &mut cb_needed,
                ) != FALSE
                {
                    let mut filename = vec![0i8; MAX_PATH];
                    GetModuleFileNameExA(handle, module, filename.as_mut_ptr(), MAX_PATH as DWORD);
                    let proc_name = std::ffi::CStr::from_ptr(filename.as_ptr())
                        .to_string_lossy()
                        .to_lowercase();
                    let basename = std::path::Path::new(proc_name.as_str())
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string();
                    if basename == name.to_lowercase() {
                        CloseHandle(handle);
                        return Ok(pid as i32);
                    }
                }
                CloseHandle(handle);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Failed to find process",
        ))
    }

    pub struct ProcessPlatform {
        pub pid: i32,
        handle: HANDLE,
    }

    impl Drop for ProcessPlatform {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.handle);
            }
        }
    }

    impl ProcessPlatform {
        pub fn new(pid: i32) -> io::Result<Self> {
            let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid as DWORD) };
            if handle.is_null() {
                return Err(io::Error::last_os_error());
            }
            Ok(ProcessPlatform { pid, handle })
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

                let count = cb_needed as usize / mem::size_of::<HMODULE>();
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

        pub fn get_module_base(&self, module: &str) -> io::Result<usize> {
            Ok(self.get_module_handle(module)? as usize)
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
            }
        }

        pub fn read_memory_range(&self, addr: usize, size: usize) -> io::Result<Vec<u8>> {
            let mut buf = vec![0u8; size];
            let mut bytes_read = 0usize;
            let result = unsafe {
                ReadProcessMemory(
                    self.handle,
                    addr as *const _,
                    buf.as_mut_ptr() as *mut _,
                    size,
                    &mut bytes_read,
                )
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

        pub fn allocate_memory(&self, size: usize) -> io::Result<usize> {
            use winapi::um::memoryapi::VirtualAllocEx;
            use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE};

            let addr = unsafe {
                VirtualAllocEx(
                    self.handle,
                    std::ptr::null_mut(),
                    size,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE,
                )
            };

            if addr.is_null() {
                return Err(io::Error::last_os_error());
            }

            Ok(addr as usize)
        }

        pub fn get_aspect_ratio(&self, window_title: &str) -> io::Result<f32> {
            unsafe {
                let title = CString::new(window_title).unwrap();
                let hwnd = FindWindowA(std::ptr::null(), title.as_ptr());
                if hwnd.is_null() {
                    return Ok(16.0 / 9.0);
                }
                let mut rect: RECT = std::mem::zeroed();
                GetClientRect(hwnd, &mut rect);
                let w = (rect.right - rect.left) as f32;
                let h = (rect.bottom - rect.top) as f32;
                Ok(if h == 0.0 { 16.0 / 9.0 } else { w / h })
            }
        }
    }
}
