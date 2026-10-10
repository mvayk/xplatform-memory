use crate::memory::definitions::SeccompMode;
use std::{fs, io, str::FromStr};

impl TryFrom<u32> for SeccompMode {
    type Error = io::Error;

    fn try_from(v: u32) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(Self::Disabled),
            1 => Ok(Self::Strict),
            2 => Ok(Self::Filter),
            n => {
                tracing::warn!(value = n, "unknown seccomp mode");
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unknown seccomp mode: {n}"),
                ))
            }
        }
    }
}

impl FromStr for SeccompMode {
    type Err = io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.trim()
            .parse::<u32>()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
            .try_into()
    }
}

pub fn seccomp_check(pid: i32) -> io::Result<SeccompMode> {
    let status = fs::read_to_string(format!("/proc/{pid}/status"))?;

    let mode = status
        .lines()
        .find_map(|line| line.strip_prefix("Seccomp:"))
        .ok_or_else(|| {
            tracing::error!(pid, mode = ?mode, "seccomp check");
            io::Error::new(
                io::ErrorKind::NotFound,
                "Seccomp field not found (kernel may lack CONFIG_SECCOMP)",
            )
        })?
        .parse()?;

    tracing::info!(pid, mode = ?mode, "seccomp check");
    Ok(mode)
}
