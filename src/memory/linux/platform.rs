#[cfg(target_os = "linux")]
use crate::memory::linux::seccomp::{SeccompMode, seccomp_check};
use std::io;

pub struct ProcessPlatform {
    pub pid: i32,
    pub seccomp_mode: SeccompMode,
}

impl ProcessPlatform {
    pub fn new(pid: i32) -> io::Result<Self> {
        let seccomp_mode = seccomp_check(pid)?;
        Ok(ProcessPlatform { pid, seccomp_mode })
    }
}
