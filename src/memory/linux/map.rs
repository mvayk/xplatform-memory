use crate::formatter::Hex;
use crate::linux::page::{Page, page_align_down, page_size};
use crate::linux::platform::ProcessPlatform;
use crate::linux::protection::protection_to_string;
use crate::types::Address;
use crate::types::ProtectionType;
use std::ops::Range;
use std::{fmt, fs, io};

const SPECIAL_REGIONS: [&str; 4] = ["[vvar]", "[vvar_vclock]", "[vdso]", "[vsyscall]"];
const PAGE_ADDRESS_WARN_THRESHOLD: u64 = 10_000_000;

#[derive(Clone)]
pub struct MapEntry {
    pub start_address: Address,
    pub end_address: Address,
    pub protection_flag: ProtectionType,
    pub shared: bool,
    pub offset: u64,
    pub dev: (u32, u32),
    pub inode: u64,
    pub module_name: String,
}

impl fmt::Display for MapEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let protectiontype = protection_to_string(self.protection_flag).unwrap();

        write!(
            f,
            "MapEntry {:#x}-{:#x} {}, {}",
            self.start_address,
            self.end_address,
            protectiontype,
            if self.module_name.is_empty() {
                "anonymous"
            } else {
                self.module_name.as_str()
            },
        )
    }
}

impl MapEntry {
    pub fn size(&self) -> u64 {
        self.end_address - self.start_address
    }

    pub fn page_count(&self) -> u64 {
        self.size() / page_size()
    }

    pub fn range(&self) -> Range<Address> {
        self.start_address..self.end_address
    }

    pub fn contains(&self, address: Address) -> bool {
        self.range().contains(&address)
    }

    pub fn range_string(&self) -> String {
        format!("{:x}-{:x}", self.start_address, self.end_address)
    }

    pub fn pages(&self) -> impl Iterator<Item = Address> {
        let step = page_size();

        if self.size() % step != 0 {
            tracing::warn!(
                range = %self.range_string(),
                size = self.size(),
                page_size = step,
                "region size is not a multiple of the page size, last partial page will be included"
            );
        }

        tracing::trace!(
            range = %self.range_string(),
            pages = self.page_count(),
            module = self.module_name,
            "MapEntry::pages iterating"
        );

        self.range().step_by(step as usize)
    }
    pub fn page_at(&self, address: Address) -> Option<Page> {
        if !self.contains(address) {
            tracing::trace!(
                address = %Hex(address),
                range = %self.range_string(),
                "page_at: address not in this region"
            );
            return None;
        }

        let size = page_size();
        let aligned = page_align_down(address);
        let start_address = aligned.max(self.start_address);
        let end_address = (aligned + size).min(self.end_address);
        let index_in_region = (start_address - self.start_address) / size;

        tracing::trace!(
            address = %Hex(address),
            page_start = %Hex(start_address),
            page_end = %Hex(end_address),
            index_in_region,
            "page_at: resolved page"
        );

        Some(Page {
            start_address,
            end_address,
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
        _ => {
            tracing::error!(
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

    tracing::trace!(
        permission = perms,
        shared = shared,
        protection = ?protection_to_string(protection).ok(),
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

fn parse_line(line: &str) -> io::Result<MapEntry> {
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

    tracing::trace!(
        start = %Hex(start_address),
        end = %Hex(end_address),
        perms = perms,
        offset = %Hex(offset),
        dev = dev.0 as u64 * 256 + dev.1 as u64,
        inode = inode,
        path = module_name,
        context = line,
        "parse_line ok"
    );

    Ok(MapEntry {
        start_address,
        end_address,
        protection_flag,
        shared,
        offset,
        dev,
        inode,
        module_name: module_name.to_string(),
    })
}

impl ProcessPlatform {
    pub fn get_all_regions(&self) -> io::Result<Vec<MapEntry>> {
        let path = format!("/proc/{}/maps", self.pid);
        let maps = fs::read_to_string(&path).map_err(|e| {
            tracing::error!(
                pid = self.pid,
                path = path.as_str(),
                kind = ?e.kind(),
                error = %e,
                "get_all_regions failed to read maps file (is the process still running? permissions?)"
            );
            e
        })?;

        let mut regions = Vec::new();
        let mut total_bytes: u64 = 0;

        for (i, line) in maps.lines().enumerate() {
            let line_number = i + 1;

            if line.trim().is_empty() {
                tracing::trace!(
                    pid = self.pid,
                    line_number,
                    "get_all_regions skipping empty line"
                );
                continue;
            }

            let entry = parse_line(line).map_err(|e| {
                tracing::error!(
                    pid = self.pid,
                    line_number,
                    error = %e,
                    context = line,
                    "get_all_regions failed to parse line"
                );
                e
            })?;

            tracing::trace!(
                pid = self.pid,
                line_number,
                range = %entry.range_string(),
                perms = ?protection_to_string(entry.protection_flag).ok(),
                module = entry.module_name,
                "get_all_regions successfully read line"
            );

            total_bytes += entry.size();
            regions.push(entry);
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
                total_bytes,
                "get_all_regions successful"
            );
        }

        Ok(regions)
    }

    pub fn get_region_from_address(&self, address: Address) -> io::Result<MapEntry> {
        match self
            .get_all_regions()?
            .into_iter()
            .find(|region| region.contains(address))
        {
            Some(region) => {
                tracing::debug!(
                    pid = self.pid,
                    address = %Hex(address),
                    range = %region.range_string(),
                    module = region.module_name,
                    "get_region_from_address found region"
                );
                Ok(region)
            }
            None => {
                tracing::error!(
                    pid = self.pid,
                    address = %Hex(address),
                    "get_region_from_address failed to find region for address"
                );
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "Failed to find region from address",
                ))
            }
        }
    }

    pub fn get_page_from_address(&self, address: u64) -> io::Result<Page> {
        tracing::debug!(
            pid = self.pid,
            address = %Hex(address),
            "get_page_from_address looking up page"
        );

        let region = self.get_region_from_address(address)?;

        let page = region.page_at(address).ok_or_else(|| {
            tracing::error!(
                pid = self.pid,
                address = %Hex(address),
                range = %region.range_string(),
                "get_page_from_address found a region but page_at returned None"
            );
            io::Error::new(
                io::ErrorKind::Other,
                "region contained address but no page found",
            )
        })?;

        tracing::info!(
            pid = self.pid,
            address = %Hex(address),
            page_start = %Hex(page.start_address),
            index_in_region = page.index_in_region,
            "get_page_from_address found page"
        );

        Ok(page)
    }

    pub fn get_readable_regions(&self) -> io::Result<Vec<MapEntry>> {
        let all = self.get_all_regions()?;
        let total = all.len();

        let regions: Vec<MapEntry> = all
            .into_iter()
            .filter(|region| {
                let keep = region.is_readable();
                if !keep {
                    tracing::trace!(
                        range = %region.range_string(),
                        module = region.module_name,
                        "get_readable_regions skipping non-readable region"
                    );
                }
                keep
            })
            .collect();

        tracing::info!(
            pid = self.pid,
            total,
            kept = regions.len(),
            "get_readable_regions successful"
        );

        Ok(regions)
    }

    pub fn get_filtered_regions(&self) -> io::Result<Vec<MapEntry>> {
        let all = self.get_all_regions()?;
        let total = all.len();

        let regions: Vec<MapEntry> = all
            .into_iter()
            .filter(|region| {
                let keep = !region.is_special();
                if !keep {
                    tracing::trace!(
                        range = %region.range_string(),
                        module = region.module_name,
                        "get_filtered_regions skipping special region"
                    );
                }
                keep
            })
            .collect();

        tracing::debug!(
            pid = self.pid,
            total,
            kept = regions.len(),
            "get_filtered_regions successful"
        );

        Ok(regions)
    }

    pub fn get_scannable_regions(&self) -> io::Result<Vec<MapEntry>> {
        let all = self.get_all_regions()?;
        let total = all.len();

        let regions: Vec<MapEntry> = all
            .into_iter()
            .filter(|region| {
                if region.is_special() {
                    tracing::trace!(
                        range = %region.range_string(),
                        module = region.module_name,
                        "get_scannable_regions skipping special region"
                    );
                    return false;
                }
                if !region.is_readable() {
                    tracing::trace!(
                        range = %region.range_string(),
                        module = region.module_name,
                        "get_scannable_regions skipping non-readable region"
                    );
                    return false;
                }
                true
            })
            .collect();

        let scannable_bytes: u64 = regions.iter().map(MapEntry::size).sum();
        tracing::info!(
            pid = self.pid,
            total,
            kept = regions.len(),
            scannable_bytes,
            "get_scannable_regions successful"
        );

        Ok(regions)
    }

    pub fn get_page_addresses(regions: &[MapEntry]) -> Vec<u64> {
        let expected: u64 = regions.iter().map(MapEntry::page_count).sum();

        if expected > PAGE_ADDRESS_WARN_THRESHOLD {
            tracing::warn!(
                regions = regions.len(),
                expected_pages = expected,
                "get_page_addresses building large vec expect lag, consider iterating regions instead"
            );
        }

        let mut addresses = Vec::with_capacity(expected as usize);
        addresses.extend(regions.iter().flat_map(|region| region.pages()));

        tracing::info!(
            regions = regions.len(),
            pages = addresses.len(),
            "get_page_addresses successful"
        );

        addresses
    }

    pub fn get_regions_in_range(&self, range: Range<Address>) -> io::Result<Vec<MapEntry>> {
        Ok(self
            .get_all_regions()?
            .into_iter()
            .filter(|r| r.start_address < range.end && r.end_address > range.start)
            .collect())
    }
}
