use std::ops::Range;

use crate::memory::process::Process;

pub struct Module<'a> {
    pub name: String,
    pub process: &'a Process,
    pub address: Range<Address>,
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
}

pub type Address = u64;
