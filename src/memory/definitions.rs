use crate::memory::wrapper::Process;
use std::{fmt, io, ops::Add, ops::Deref, ops::Sub};

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
pub enum ProtectionType {
    PAGE_EXECUTE,           /* PROT_EXEC  */
    PAGE_EXECUTE_READ,      /* PROT_EXEC | PROT_READ */
    PAGE_EXECUTE_READWRITE, /* PROT_EXEC | PROT_READ | PROT_WRITE */
    PAGE_NOACCESS,          /* PROT_NONE  */
    PAGE_READONLY,          /* PROT_READ */
    PAGE_READWRITE,         /* PROT_READWRITE */
}

pub struct Module<'a> {
    pub name: String,
    pub process: &'a Process,
    pub base_address: Address,
}

pub type Address = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Hex(pub u64);

impl fmt::Display for Hex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl fmt::LowerHex for Hex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl Deref for Hex {
    type Target = u64;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Sub for Hex {
    type Output = u64;
    fn sub(self, rhs: Self) -> Self::Output {
        self.0 - rhs.0
    }
}

impl Add<u64> for Hex {
    type Output = Self;
    fn add(self, rhs: u64) -> Self::Output {
        Hex(self.0 + rhs)
    }
}
