#[cfg(target_os = "linux")]
use crate::linux::seccomp::{SeccompMode, seccomp_check};
use std::{fs, io};

#[derive(Clone, Copy)]
pub struct ProcessPlatform {
    pub pid: i32,
    pub seccomp_mode: SeccompMode,
}

const PTRACE_SCOPE_PATH: &str = "/proc/sys/kernel/yama/ptrace_scope";

impl ProcessPlatform {
    pub fn new(pid: i32) -> io::Result<Self> {
        let seccomp_mode = seccomp_check(pid)?;

        let pscope = fs::read_to_string(PTRACE_SCOPE_PATH)
            .inspect_err(|e| tracing::error!(PTRACE_SCOPE_PATH, error = %e, "failed to read:"))?;

        if pscope != "2" {
            tracing::warn!(
                value = pscope,
                PTRACE_SCOPE_PATH,
                "you may encounter permission errors"
            );
        }

        Ok(ProcessPlatform { pid, seccomp_mode })
    }
}
