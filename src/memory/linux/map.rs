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
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 || !parts[1].starts_with('r') {
                continue;
            }
            // [vvar]/[vsyscall]
            if parts.len() >= 6 && (parts[5] == "[vvar]" || parts[5] == "[vsyscall]") {
                continue;
            }
            if let Some((s, e)) = parts[0].split_once('-') {
                if let (Ok(s), Ok(e)) = (usize::from_str_radix(s, 16), usize::from_str_radix(e, 16))
                {
                    regions.push((s, e));
                }
            }
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

    pub fn dump_memory(&self) -> io::Result<(Vec<usize>, Vec<u8>)> {
        use std::os::unix::fs::FileExt;

        let file = fs::File::open(format!("/proc/{}/mem", self.pid))?;
        let mut addrs = Vec::new();
        let mut bytes = Vec::new();

        for (start, end) in self.get_readable_regions()? {
            let mut buf = vec![0u8; end - start];
            let n = match file.read_at(&mut buf, start as u64) {
                Ok(n) => n,
                Err(_) => continue,
            };
            buf.truncate(n);
            addrs.extend(start..start + n);
            bytes.extend_from_slice(&buf);
        }
        Ok((addrs, bytes))
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
