/*
 TODO: REFACTOR NOW
*/
use crate::memory::linux::platform::ProcessPlatform;
use std::{fs, io};

impl ProcessPlatform {
    pub fn get_readable_regions(&self) -> io::Result<Vec<(usize, usize)>> {
        let maps = fs::read_to_string(format!("/proc/{}/maps", self.pid))?;
        let mut regions = Vec::new();

        for line in maps.lines() {
            let mut it = line.split_whitespace();
            let (Some(range), Some(perms)) = (it.next(), it.next()) else {
                continue;
            };
            if !perms.starts_with('r') {
                continue;
            }
            let path = it.nth(3).unwrap_or("");
            if matches!(path, "[vvar]" | "[vvar_vclock]" | "[vsyscall]")
                || path.starts_with("/dev/")
            {
                continue;
            }
            let Some((s, e)) = range.split_once('-') else {
                continue;
            };
            let (Ok(s), Ok(e)) = (usize::from_str_radix(s, 16), usize::from_str_radix(e, 16))
            else {
                continue;
            };
            regions.push((s, e));
        }
        Ok(regions)
    }

    pub fn get_all_addresses(&self) -> io::Result<Vec<usize>> {
        let mut addrs = Vec::new();
        for (s, e) in self.get_readable_regions()? {
            addrs.extend(s..e);
        }
        Ok(addrs)
    }

    pub fn get_mapped_pages(&self) -> io::Result<Vec<u64>> {
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
        let maps = fs::read_to_string(format!("/proc/{}/maps", self.pid))?;
        let mut pages = Vec::new();

        for line in maps.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }
            if parts.len() >= 6
                && matches!(
                    parts[5],
                    "[vvar]" | "[vvar_vclock]" | "[vdso]" | "[vsyscall]"
                )
            {
                continue;
            }
            let Some((s, e)) = parts[0].split_once('-') else {
                continue;
            };
            let (Ok(s), Ok(e)) = (u64::from_str_radix(s, 16), u64::from_str_radix(e, 16)) else {
                continue;
            };
            pages.extend((s..e).step_by(page as usize));
        }
        Ok(pages)
    }
}
