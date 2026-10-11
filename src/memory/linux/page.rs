use crate::memory::definitions::ProtectionType;
use crate::memory::linux::map::*;
use std::fmt;
use std::sync::OnceLock;

/* i might wake up one day and the page size might shift to like 727 bytes */
pub fn page_size() -> u64 {
    static PAGE_SIZE: OnceLock<u64> = OnceLock::new();
    *PAGE_SIZE.get_or_init(|| {
        let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if size > 0 {
            tracing::debug!(page_size = size, "page_size queried from sysconf");
            size as u64
        } else {
            tracing::warn!(
                returned = size,
                fallback = 0x4096,
                "sysconf(_SC_PAGESIZE) failed, falling back to 0x4096"
            );
            0x4096
        }
    })
}

#[derive(Clone)]
pub struct Page {
    pub start_address: u64,
    pub end_address: u64,
    pub index_in_region: u64,
    pub region: MapEntry,
}

pub fn page_align_down(address: u64) -> u64 {
    address & !(page_size() - 1)
}

impl Page {
    pub fn size(&self) -> u64 {
        self.end_address - self.start_address
    }

    pub fn contains(&self, address: u64) -> bool {
        (self.start_address..self.end_address).contains(&address)
    }

    pub fn offset_of(&self, address: u64) -> Option<u64> {
        self.contains(address).then(|| address - self.start_address)
    }

    /* pages inherit a regions protection flags */
    pub fn get_protection_flag(&self) -> ProtectionType {
        self.region.protection_flag
    }

    pub fn is_readable(&self) -> bool {
        self.region.is_readable()
    }

    pub fn is_writable(&self) -> bool {
        self.region.is_writable()
    }
}

impl fmt::Display for Page {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "page {:#x}-{:#x} (#{} of {}) in region {:#x}-{:#x} [{}]",
            self.start_address,
            self.end_address,
            self.index_in_region,
            self.region.page_count(),
            self.region.start_address,
            self.region.end_address,
            if self.region.module.is_empty() {
                "anonymous"
            } else {
                self.region.module.as_str()
            },
        )
    }
}
