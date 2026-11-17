use winapi::{
    shared::minwindef::{DWORD, FALSE, HMODULE, MAX_PATH},
    um::{
        handleapi::CloseHandle,
        processthreadsapi::OpenProcess,
        psapi::{EnumProcessModules, EnumProcesses, GetModuleFileNameExA},
        winnt::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
    },
};

use crate::windows::platform::ProcessPlatform;
use std::{io, mem};

impl ProcessPlatform {
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
                tracing::error!("failed to enumerate processes");
                return Err(io::Error::last_os_error());
            }
            let count = bytes_returned as usize / mem::size_of::<DWORD>();
            for &pid in &pids[..count] {
                let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
                if handle.is_null() {
                    tracing::trace!("encountered null handle, continuing");
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
                        tracing::info!(pid = pid, "found pid");
                        CloseHandle(handle);
                        return Ok(pid as i32);
                    }
                }
                CloseHandle(handle);
            }
        }
        tracing::error!("failed to find process");
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Failed to find process",
        ))
    }
}
