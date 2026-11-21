use crate::formatter::Hex;
use crate::linux::page::{Page, page_size};
use crate::linux::platform::ProcessPlatform;
use crate::process::Process;
use crate::types::{Address, AddyRange, ProtectionType, address_align_to_page_down};
use std::path::Path;
use std::{fmt, fs, io};

pub const SPECIAL_REGIONS: [&str; 7] = [
    "[vvar]",
    "[vvar_vclock]",
    "[vdso]",
    "[vsyscall]",
    "[heap]",
    "[stack]",
    "/dev/nvidia0",
];

/* aka Region */
#[derive(Clone)]
pub struct MapEntry {
    pub addresses: AddyRange,
    pub protection_flag: ProtectionType,
    pub shared: bool,
    pub offset: u64,
    pub dev: (u32, u32),
    pub inode: u64,
    pub module_name: String,
    pub pid: i32,
}

impl fmt::Display for MapEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let protectiontype = self.protection_flag.to_string();

        write!(
            f,
            "MapEntry {}, {}, {}",
            self.addresses,
            protectiontype,
            if self.module_name.is_empty() {
                "anonymous"
            } else {
                self.module_name.as_str()
            },
        )
    }
}

pub fn maps_loaded(p: &ProcessPlatform, lib: &str, timeout: std::time::Duration) -> io::Result<()> {
    let is_lib = |m: &str| {
        Path::new(m)
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_prefix(lib))
            .map_or(false, |rest| {
                (rest.starts_with('.') || rest.starts_with('-')) && !m.ends_with(" (deleted)")
            })
    };

    let deadline = std::time::Instant::now() + timeout;
    loop {
        let regions = p.get_all_regions()?;
        let found = regions.iter().find(|r| is_lib(&r.module_name));

        if let Some(region) = found {
            let non_empty = fs::metadata(&region.module_name)
                .map(|m| m.len() > 0)
                .unwrap_or(false);
            if non_empty {
                return Ok(());
            }
        }

        if std::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{lib} did not appear (or was empty) in target process within {timeout:?}"),
            ));
        }
        //std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

pub fn process_ready(p: &ProcessPlatform, timeout: std::time::Duration) -> io::Result<()> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if let Ok(regions) = p.get_all_regions() {
            if !regions.is_empty() {
                return Ok(());
            }
        }
        if std::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("process did not become ready within {timeout:?}"),
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

impl MapEntry {
    pub fn update(&mut self, process: &Process) -> io::Result<()> {
        let updated_entry =
            ProcessPlatform::get_region_from_address(&process.inner, self.addresses.start)?;

        *self = updated_entry;

        Ok(())
    }

    pub fn get_size(&self) -> u64 {
        self.addresses.end - self.addresses.start
    }

    pub fn get_page_count(&self) -> u64 {
        self.get_size() / page_size()
    }

    pub fn contains(&self, address: Address) -> bool {
        self.addresses.contains(address)
    }

    pub fn get_pages(&self) -> io::Result<Vec<Page>> {
        let step = page_size();
        if !self.get_size().is_multiple_of(step) {
            tracing::warn!(
                range = %self.addresses,
                size = self.get_size(),
                page_size = step,
                "region size is not a multiple of the page size, last partial page will be included"
            );
        }

        tracing::trace!(
            range = %self.addresses,
            pages = self.get_page_count(),
            module = self.module_name,
            "MapEntry::pages iterating"
        );

        let end = self.addresses.end;

        let pages = self
            .addresses
            .step_by(step as usize)
            .enumerate()
            .map(|(index, start)| Page {
                addresses: AddyRange {
                    start,
                    end: (start + step).min(end),
                },
                index_in_region: index,
                region: self.clone(),
            })
            .collect();

        Ok(pages)
    }

    pub fn page_at(&self, address: Address) -> Option<Page> {
        if !self.contains(address) {
            tracing::trace!(
                address = %Hex(address),
                range = %self.addresses,
                "page_at: address not in this region"
            );
            return None;
        }

        let size = page_size();
        let aligned = address_align_to_page_down(address);

        let start_address = aligned.max(self.addresses.start);
        let end_address = (aligned + size).min(self.addresses.end);

        /* bugged */
        let index_in_region = ((start_address - self.addresses.start) / size) as usize;

        tracing::trace!(
            address = %Hex(address),
            page_range = %self.addresses,
            index_in_region,
            "page_at: resolved page"
        );

        Some(Page {
            addresses: AddyRange {
                start: start_address,
                end: end_address,
            },
            index_in_region,
            region: self.clone(),
        })
    }

    pub fn is_readable(&self) -> bool {
        matches!(
            self.protection_flag,
            ProtectionType::PAGE_READONLY
                | ProtectionType::PAGE_READWRITE
                | ProtectionType::PAGE_EXECUTE_READ
                | ProtectionType::PAGE_EXECUTE_READWRITE
        )
    }

    pub fn is_writable(&self) -> bool {
        matches!(
            self.protection_flag,
            ProtectionType::PAGE_READWRITE | ProtectionType::PAGE_EXECUTE_READWRITE
        )
    }

    pub fn is_special(&self) -> bool {
        SPECIAL_REGIONS.contains(&self.module_name.as_str())
    }
}

fn invalid(what: &str, line: &str) -> io::Error {
    tracing::error!(context = line, "maps parse failed: {what}");
    io::Error::new(io::ErrorKind::InvalidData, format!("{what} in {line:?}"))
}

fn parse_permissions(perms: &str, line: &str) -> io::Result<(ProtectionType, bool)> {
    let bytes = perms.as_bytes();
    if bytes.len() != 4 {
        tracing::error!(
            permission = perms,
            length = bytes.len(),
            "parse_permissions expected exactly 4 characters"
        );
        return Err(invalid("bad permissions length", line));
    }

    let protection = match &bytes[..3] {
        b"---" => ProtectionType::PAGE_NOACCESS,
        b"r--" => ProtectionType::PAGE_READONLY,
        b"rw-" => ProtectionType::PAGE_READWRITE,
        b"--x" => ProtectionType::PAGE_EXECUTE,
        b"r-x" => ProtectionType::PAGE_EXECUTE_READ,
        b"rwx" => ProtectionType::PAGE_EXECUTE_READWRITE,
        b"-w-" => ProtectionType::UNKNOWN,
        _ => {
            tracing::warn!(
                permission = perms,
                "parse_permissions failed to determine protection flags"
            );
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("no ProtectionType for permissions {perms:?}"),
            ));
        }
    };

    let shared = match bytes[3] {
        b'p' => false,
        b's' => true,
        other => {
            tracing::error!(
                permission = perms,
                flag = %(other as char),
                "parse_permissions got an unknown private/shared flag"
            );
            return Err(invalid("bad private/shared flag", line));
        }
    };

    let p = protection.to_string();
    tracing::trace!(
        permission = perms,
        shared = shared,
        protection = p,
        "parse_permissions ok"
    );

    Ok((protection, shared))
}

fn parse_dev(dev: &str, line: &str) -> io::Result<(u32, u32)> {
    let (major, minor) = dev
        .split_once(':')
        .ok_or_else(|| invalid("bad dev", line))?;
    let major = u32::from_str_radix(major, 16).map_err(|_| invalid("bad dev major", line))?;
    let minor = u32::from_str_radix(minor, 16).map_err(|_| invalid("bad dev minor", line))?;
    Ok((major, minor))
}

/*
    we have to handle dlls (wine/proton mappings) a bit differently due to how they're loaded
    for some reason wine likes to map the module header? with its path and then map the rest anonymously
    example:

    6ffff5420000-6ffff5421000 r--p 00000000 08:02 108550771                  /home/mvayk/.local/share/Steam/steamapps/common/Counter-Strike Source/cstrike/bin/x64/server.dll
    6ffff5421000-6ffff5883000 r-xp 00000000 00:00 0
    6ffff5883000-6ffff5a72000 r--p 00000000 00:00 0
    6ffff5a72000-6ffff5c4e000 rw-p 00000000 00:00 0
    6ffff5c4e000-6ffff5cf8000 r--p 00000000 00:00 0
    6ffff5d10000-6ffff5d11000 r--p 00000000 08:02 108550755                  /home/mvayk/.local/share/Steam/steamapps/common/Counter-Strike Source/cstrike/bin/x64/client.dll
    6ffff5d11000-6ffff60f1000 r-xp 00000000 00:00 0
    6ffff60f1000-6ffff62b3000 r--p 00000000 00:00 0
    6ffff62b3000-6ffff63f0000 rw-p 00000000 00:00 0
    6ffff63f0000-6ffff648e000 r--p 00000000 00:00 0
*/
fn parse_line(line: &str, pid: i32) -> io::Result<MapEntry> {
    let mut it = line.splitn(6, ' ');

    let range = it.next().ok_or_else(|| invalid("missing range", line))?;
    let perms = it.next().ok_or_else(|| invalid("missing perms", line))?;
    let offset = it.next().ok_or_else(|| invalid("missing offset", line))?;
    let dev = it.next().ok_or_else(|| invalid("missing dev", line))?;
    let inode = it.next().ok_or_else(|| invalid("missing inode", line))?;
    let module_name = it.next().unwrap_or("").trim();

    let (s, e) = range
        .split_once('-')
        .ok_or_else(|| invalid("bad address range", line))?;

    let start_address =
        Address::from_str_radix(s, 16).map_err(|_| invalid("bad start address", line))?;
    let end_address =
        Address::from_str_radix(e, 16).map_err(|_| invalid("bad end address", line))?;
    if end_address < start_address {
        tracing::error!(context = line, "end address found before start address");
        return Err(invalid("end address before start address", line));
    }
    if end_address == start_address {
        tracing::warn!(context = line, "parse_line found a zero-sized region");
    }

    let offset = u64::from_str_radix(offset, 16).map_err(|_| invalid("bad offset", line))?;
    let inode = inode
        .trim()
        .parse::<u64>()
        .map_err(|_| invalid("bad inode", line))?;

    let (protection_flag, shared) = parse_permissions(perms, line)?;
    let dev = parse_dev(dev, line)?;

    let range = AddyRange {
        start: start_address,
        end: end_address,
    };

    tracing::trace!(
        %range,
        perms = perms,
        offset = %Hex(offset),
        dev = dev.0 as u64 * 256 + dev.1 as u64,
        inode = inode,
        path = module_name,
        context = line,
        "parse_line ok"
    );

    Ok(MapEntry {
        addresses: AddyRange {
            start: start_address,
            end: end_address,
        },
        protection_flag,
        shared,
        offset,
        dev,
        inode,
        module_name: module_name.to_string(),
        pid,
    })
}

impl ProcessPlatform {
    fn read_maps(&self) -> io::Result<String> {
        let path = format!("/proc/{}/maps", self.pid);
        fs::read_to_string(&path).map_err(|e| {
            tracing::error!(
                pid = self.pid,
                path = path.as_str(),
                kind = ?e.kind(),
                error = %e,
                "failed to read maps file (is the process still running? permissions?)"
            );
            e
        })
    }

    pub fn get_all_regions(&self) -> io::Result<Vec<MapEntry>> {
        let maps = self.read_maps()?;
        let mut regions = Vec::new();

        for (i, line) in maps.lines().enumerate() {
            let line_number = i + 1;
            if line.trim().is_empty() {
                continue;
            }

            let entry = parse_line(line, self.pid).map_err(|e| {
                tracing::error!(
                    pid = self.pid,
                    line_number,
                    error = %e,
                    context = line,
                    "get_all_regions failed to parse line"
                );
                e
            })?;

            let p = entry.protection_flag.to_string();
            tracing::trace!(
                pid = self.pid,
                line_number,
                range = %entry.addresses,
                perms = p,
                module = entry.module_name,
                "get_all_regions read line"
            );
            regions.push(entry);
        }

        use crate::linux::wine_map::attribute_wine_modules;
        if let Err(err) = attribute_wine_modules(&mut regions, self.pid) {
            tracing::warn!(
                pid = self.pid,
                error = %err,
                "get_all_regions could not attribute wine modules"
            );
        }

        if regions.is_empty() {
            tracing::warn!(
                pid = self.pid,
                "get_all_regions found no regions (process may have exited)"
            );
        } else {
            tracing::info!(
                pid = self.pid,
                regions = regions.len(),
                total_bytes = regions.iter().map(MapEntry::get_size).sum::<u64>(),
                "get_all_regions successful"
            );
        }

        Ok(regions)
    }

    fn filter_regions(
        &self,
        caller: &'static str,
        skip_reason: impl Fn(&MapEntry) -> Option<&'static str>,
    ) -> io::Result<Vec<MapEntry>> {
        let all = self.get_all_regions()?;
        let total = all.len();

        let regions: Vec<MapEntry> = all
            .into_iter()
            .filter(|r| match skip_reason(r) {
                Some(reason) => {
                    tracing::trace!(
                        caller,
                        range = %r.addresses,
                        module = r.module_name,
                        reason,
                        "skipping region"
                    );
                    false
                }
                None => true,
            })
            .collect();

        tracing::debug!(
            pid = self.pid,
            caller,
            total,
            kept = regions.len(),
            "filter_regions done"
        );
        Ok(regions)
    }

    pub fn get_readable_regions(&self) -> io::Result<Vec<MapEntry>> {
        self.filter_regions("get_readable_regions", |r| {
            (!r.is_readable()).then_some("non-readable")
        })
    }

    pub fn get_filtered_regions(&self) -> io::Result<Vec<MapEntry>> {
        self.filter_regions("get_filtered_regions", |r| {
            r.is_special().then_some("special")
        })
    }

    pub fn get_scannable_regions(&self) -> io::Result<Vec<MapEntry>> {
        let regions = self.filter_regions("get_scannable_regions", |r| {
            if r.is_special() {
                Some("special")
            } else if !r.is_readable() {
                Some("non-readable")
            } else {
                None
            }
        })?;

        tracing::info!(
            pid = self.pid,
            scannable_bytes = regions.iter().map(MapEntry::get_size).sum::<u64>(),
            "get_scannable_regions successful"
        );
        Ok(regions)
    }

    pub fn get_regions_in_range(&self, range: AddyRange) -> io::Result<Vec<MapEntry>> {
        Ok(self
            .get_all_regions()?
            .into_iter()
            .filter(|r| r.addresses.overlaps(range))
            .collect())
    }

    pub fn get_region_from_address(&self, address: Address) -> io::Result<MapEntry> {
        let region = self
            .get_all_regions()?
            .into_iter()
            .find(|r| r.contains(address))
            .ok_or_else(|| {
                tracing::error!(pid = self.pid, address = %Hex(address), "no region for address");
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "Failed to find region from address",
                )
            })?;

        tracing::debug!(
            pid = self.pid,
            address = %Hex(address),
            range = %region.addresses,
            module = region.module_name,
            "get_region_from_address found region"
        );
        Ok(region)
    }

    pub fn get_page_from_address(&self, address: Address) -> io::Result<Page> {
        let region = self.get_region_from_address(address)?;

        let page = region.page_at(address).ok_or_else(|| {
            tracing::error!(
                pid = self.pid,
                address = %Hex(address),
                range = %region.addresses,
                "region contained address but page_at returned None"
            );
            io::Error::other("region contained address but no page found")
        })?;

        tracing::info!(
            pid = self.pid,
            address = %Hex(address),
            page_start = %Hex(page.addresses.start),
            index_in_region = page.index_in_region,
            "get_page_from_address found page"
        );
        Ok(page)
    }
}
