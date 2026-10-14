use crate::linux::map::*;
use crate::types::{Address, AddyRange, ProtectionType};
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
    pub addresses: AddyRange,
    pub index_in_region: usize,
    pub region: MapEntry,
}

pub fn page_align_down(address: Address) -> u64 {
    address & !(page_size() - 1)
}

impl Page {
    pub fn get_size(&self) -> u64 {
        self.addresses.end - self.addresses.start
    }

    pub fn contains(&self, address: Address) -> bool {
        (self.addresses.start..self.addresses.end).contains(&address)
    }

    pub fn offset_of(&self, address: Address) -> Option<u64> {
        self.contains(address)
            .then(|| address - self.addresses.start)
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
            "page {} ({} of {}) in region [{}] module {}",
            (self.addresses),
            self.index_in_region,
            self.region.get_page_count(),
            (self.region.addresses),
            if self.region.module_name.is_empty() {
                "anonymous"
            } else {
                self.region.module_name.as_str()
            },
        )
    }
}
