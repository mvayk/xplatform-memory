use std::{fs, io};

use crate::memory::linux::platform::ProcessPlatform;

impl ProcessPlatform {
    pub fn find_pid(name: &str) -> io::Result<i32> {
        for entry in fs::read_dir("/proc")? {
            let entry = entry?;
            let filename = entry.file_name();
            let filename = filename.to_string_lossy();
            if let Ok(pid) = filename.parse::<i32>() {
                let cmdline_path = format!("/proc/{}/cmdline", pid);
                if let Ok(cmdline) = fs::read_to_string(cmdline_path) {
                    if let Some(exe_path) = cmdline.split('\0').next() {
                        let exe_name = exe_path
                            .rsplit(|c| c == '/' || c == '\\')
                            .next()
                            .unwrap_or(exe_path);

                        if exe_name.eq_ignore_ascii_case(name) {
                            tracing::info!(pid, name, "find_pid ok");
                            return Ok(pid);
                        }
                    }
                }
            }
        }
        tracing::error!(name, "find_pid failed");
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Failed to find process",
        ))
    }
}
