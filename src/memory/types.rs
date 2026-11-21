use crate::memory::process::Process;
use std::ops::Range;

#[cfg(target_os = "linux")]
use crate::memory::linux::module::ModuleP;

#[cfg(target_os = "windows")]
use crate::memory::windows::module::ModuleP;

/* :\ lifetime hell */
pub struct Module<'a, 'b> {
    pub name: String,
    pub process: &'a Process,
    pub inner: ModuleP<'b>,
    pub addresses: AddyRange,
}

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
pub enum ProtectionType {
    PAGE_EXECUTE,           /* PROT_EXEC  */
    PAGE_EXECUTE_READ,      /* PROT_EXEC | PROT_READ */
    PAGE_EXECUTE_READWRITE, /* PROT_EXEC | PROT_READ | PROT_WRITE */
    PAGE_NOACCESS,          /* PROT_NONE  */
    PAGE_READONLY,          /* PROT_READ */
    PAGE_READWRITE,         /* PROT_READWRITE */
    UNKNOWN,                /* -w-s */
}

impl ProtectionType {
    pub fn is_readable(&self) -> bool {
        matches!(
            self,
            Self::PAGE_EXECUTE_READ
                | Self::PAGE_EXECUTE_READWRITE
                | Self::PAGE_READONLY
                | Self::PAGE_READWRITE
        )
    }

    pub fn to_string(&self) -> String {
        match self {
            Self::PAGE_NOACCESS => String::from("PAGE_NOACCESS"),
            Self::PAGE_EXECUTE => String::from("PAGE_EXECUTE"),
            Self::PAGE_EXECUTE_READ => String::from("PAGE_EXECUTE_READ"),
            Self::PAGE_EXECUTE_READWRITE => String::from("PAGE_EXECUTE_READWRITE"),
            Self::PAGE_READONLY => String::from("PAGE_READONLY"),
            Self::PAGE_READWRITE => String::from("PAGE_READWRITE"),
            Self::UNKNOWN => String::from("UNKNOWN"),
            //_ => { return Err(io::Error::new( io::ErrorKind::InvalidInput, "failed to convert protectiontype to string: unknown flag provided",)); }
        }
    }

    /* TODO: implement protection types more robustly */
    pub fn is_writable(&self) -> bool {
        matches!(
            self,
            Self::PAGE_READWRITE
               // | Self::PAGE_WRITECOPY
               | Self::PAGE_EXECUTE_READWRITE // | Self::PAGE_EXECUTE_WRITECOPY
        )
    }
}

pub type Address = u64;

const PAGE_SIZE: u64 = 0x1000;

pub fn address_align_to_page_down(address: Address) -> Address {
    address & !(PAGE_SIZE - 1)
}

pub fn address_align_to_page_up(address: Address) -> Address {
    (address + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AddyRange {
    pub start: Address,
    pub end: Address,
}

impl AddyRange {
    pub fn new(start: Address, end: Address) -> Self {
        debug_assert!(start <= end);
        Self { start, end }
    }

    pub fn as_string(&self) -> String {
        format!("{:x}-{:x}", self.start, self.end)
    }

    pub fn from_len(start: Address, len: u64) -> Self {
        Self::new(start, start + len)
    }

    pub fn len(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    pub fn is_empty(&self) -> bool {
        self.start >= self.end
    }

    pub fn contains(&self, addr: Address) -> bool {
        self.start <= addr && addr < self.end
    }

    pub fn overlaps(&self, other: AddyRange) -> bool {
        self.start < other.end && other.start < self.end
    }

    pub fn iter(&self) -> Range<Address> {
        self.start..self.end
    }

    pub fn step_by(&self, step: usize) -> std::iter::StepBy<Range<Address>> {
        (self.start..self.end).step_by(step)
    }
}

impl From<Range<Address>> for AddyRange {
    fn from(r: Range<Address>) -> Self {
        Self {
            start: r.start,
            end: r.end,
        }
    }
}

impl From<AddyRange> for Range<Address> {
    fn from(r: AddyRange) -> Self {
        r.start..r.end
    }
}

impl IntoIterator for AddyRange {
    type Item = Address;
    type IntoIter = Range<Address>;

    fn into_iter(self) -> Self::IntoIter {
        self.start..self.end
    }
}

impl std::fmt::Display for AddyRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#x}-{:#x}", self.start, self.end)
    }
}

/// DEPRECATED PROBABLY
/// # Safety
///
/// Should not be used before the horsemen are ready.
pub unsafe trait Pod: Copy + 'static {}

macro_rules! impl_pod {
    ($($t:ty),* $(,)?) => { $(unsafe impl Pod for $t {})* };
}
impl_pod!(
    u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize, f32, f64
);
unsafe impl<T: Pod, const N: usize> Pod for [T; N] {}
