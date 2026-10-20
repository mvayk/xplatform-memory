use crate::linux::platform::ProcessPlatform;
use std::{fs, io};

const PID_SEARCH_PATCH: [&str; 2] = ["sober", "Main"];

fn get_pids() -> io::Result<Vec<i32>> {
    let mut pids = Vec::new();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let filename = entry.file_name();
        let filename = filename.to_string_lossy();
        if let Ok(pid) = filename.parse::<i32>() {
            tracing::trace!(
                entry = format_args!("{entry:?}, {filename:?}"),
                "get_pids scanning:"
            );

            pids.push(pid);
        }
    }
    Ok(pids)
}

impl ProcessPlatform {
    pub fn find_first_pid_cmdline(name: &str) -> io::Result<i32> {
        let pids = get_pids()?;

        for pid in pids {
            let cmdline_path = format!("/proc/{}/cmdline", pid);
            if let Ok(cmdline) = fs::read_to_string(cmdline_path)
                && let Some(exe_path) = cmdline.split('\0').next()
            {
                let exe_name = exe_path.rsplit(['/', '\\']).next().unwrap_or(exe_path);
                tracing::trace!(exe_name);

                if exe_name.eq_ignore_ascii_case(name) {
                    tracing::info!(pid, name, "find_first_pid_cmdline ok");
                    return Ok(pid);
                }
            }
        }
        tracing::error!(name, "find_first_pid_cmdline failed");
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Failed to find process",
        ))
    }

    pub fn find_first_pid_comm(name: &str) -> io::Result<i32> {
        let pids = get_pids()?;

        for pid in pids {
            let comm_path = format!("/proc/{}/comm", pid);
            if let Ok(comm_contents) = fs::read_to_string(comm_path)
                && let Some(comm) = comm_contents.split('\n').next()
            {
                tracing::trace!(name, comm, "find_first_pid_comm:");
                if comm == name && comm.eq_ignore_ascii_case(name) {
                    tracing::info!(pid, name, "find_first_pid_comm ok");
                    return Ok(pid);
                }
            }
        }
        tracing::error!(name, "find_first_pid_comm failed");
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Failed to find process",
        ))
    }

    pub fn find_pid(name: &str) -> io::Result<i32> {
        if let Some(&name) = PID_SEARCH_PATCH.iter().find(|&&n| n == name) {
            ProcessPlatform::find_first_pid_comm(name)
        } else {
            ProcessPlatform::find_first_pid_cmdline(name)
        }
    }
}
