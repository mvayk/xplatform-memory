/*
 TODO: REFACTOR NOW
*/
use crate::memory::definitions::ProtectionType::{self, PAGE_EXECUTE_READ};
use crate::memory::linux::page::Page;
use crate::memory::linux::platform::ProcessPlatform;
use crate::memory::linux::protection::protection_to_string;
use std::{fs, io};

fn parse_line(line: &str) -> io::Result<(u64, u64, &str)> {
    let mut it = line.split_whitespace();
    let (s, e) = it.next().unwrap().split_once('-').unwrap();
    let perms = it.next().unwrap();

    tracing::debug!(s = s, e = e, perms = perms, "parse_line called");
    Ok((
        u64::from_str_radix(s, 16).unwrap(),
        u64::from_str_radix(e, 16).unwrap(),
        perms,
    ))
}

fn parse_permissions(parsed_line: (u64, u64, &str)) -> io::Result<ProtectionType> {
    let permission = parsed_line.2;
    let bytes = permission.as_bytes();

    let _ = |c: u8, on: u8| -> io::Result<bool> {
        match c {
            b'-' => Ok(false),
            c if c == on => Ok(true),
            _ => {
                tracing::error!(
                    permission = permission,
                    bytes = bytes,
                    "parse_permissions failed"
                );
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "unknown permission char {:?} in {:?}",
                        c as char, permission
                    ),
                ))
            }
        }
    };

    match &bytes[..3] {
        b"---" => Ok(ProtectionType::PAGE_NOACCESS),
        b"r--" => Ok(ProtectionType::PAGE_READONLY),
        b"rw-" => Ok(ProtectionType::PAGE_READWRITE),
        b"--x" => Ok(ProtectionType::PAGE_EXECUTE),
        b"r-x" => Ok(ProtectionType::PAGE_EXECUTE_READ),
        b"rwx" => Ok(ProtectionType::PAGE_EXECUTE_READWRITE),
        _ => {
            tracing::error!(
                permission = permission,
                "parse_permissions failed to determine protection flags"
            );
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("no ProtectionType for permissions {:?}", permission),
            ))
        }
    }
}

impl ProcessPlatform {
    pub fn get_page_from_address(&self, address: u64) -> io::Result<Page> {
        let pages = self.get_all_pages()?;

        for page in pages {
            if (page.start_address..page.end_address).contains(&address) {
                return Ok(page);
            }
        }

        tracing::error!(
            address,
            "get_page_from_address failed to find page for address"
        );
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Failed to find page from address",
        ))
    }
    /* returns all availabe pages, including guarded & mapped libraries */
    pub fn get_all_pages(&self) -> io::Result<Vec<Page>> {
        let mut pages: Vec<Page> = Vec::new();

        let maps = match fs::read_to_string(format!("/proc/{}/maps", self.pid)) {
            Ok(maps) => maps,
            Err(e) => {
                tracing::error!(
                    pid = self.pid,
                    error = %e,
                    "get_all_pages failed to read maps file"
                );
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "get_all_pages failed to find maps file",
                ));
            }
        };

        /*
        6ffffff31000-6ffffffa7000 r-xp 00001000 08:02 109856277                  /home/mvayk/.local/share/Steam/steamapps/common/Proton - Experimental/files/lib/wine/x86_64-windows/ntdll.dll
        start_address-end_address permission
        */

        let mut line_permissions: ProtectionType;
        let mut iteration_count = 0;
        for jordan in maps.lines() {
            let line = parse_line(jordan)?;
            line_permissions = parse_permissions(line)?;
            let line_permissions_as_string = protection_to_string(line_permissions)?;
            iteration_count += 1;

            tracing::info!(
                i = iteration_count,
                perms = line_permissions_as_string,
                context = jordan,
                "get_all_pages successfully read line"
            );

            pages.push(Page {
                size: 0u64,
                protection_flag: line_permissions,
                start_address: line.0,
                end_address: line.1,
            });
        }

        Ok(pages)
    }

    pub fn get_readable_pages(&self) -> io::Result<Vec<Page>> {
        let pages = self.get_all_pages()?;
        let mut readable_pages: Vec<Page> = Vec::new();

        for page in pages {
            match page.protection_flag {
                ProtectionType::PAGE_READONLY => readable_pages.push(page),
                ProtectionType::PAGE_READWRITE => readable_pages.push(page),
                ProtectionType::PAGE_EXECUTE_READWRITE => readable_pages.push(page),
                _ => {}
            }
        }

        Ok(readable_pages)
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
