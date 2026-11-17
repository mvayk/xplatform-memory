#![cfg(target_os = "windows")]
use std::io;

use winapi::{
    shared::minwindef::{DWORD, FALSE},
    um::{
        handleapi::CloseHandle,
        processthreadsapi::OpenProcess,
        winnt::{HANDLE, PROCESS_ALL_ACCESS},
    },
};

use crate::formatter::Hex;

#[derive(Clone)]
pub struct ProcessPlatform {
    pub pid: i32,
    pub handle: HANDLE,
}

impl ProcessPlatform {
    pub fn new(pid: i32) -> io::Result<Self> {
        let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid as DWORD) };
        tracing::info!(pid = pid, handle = %Hex(handle as u64), "found handle for pid:");
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(ProcessPlatform { pid, handle })
    }
}

impl Drop for ProcessPlatform {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}
