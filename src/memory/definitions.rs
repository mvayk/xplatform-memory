#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
pub enum ProtectionType {
    PAGE_EXECUTE,           /* PROT_EXEC  */
    PAGE_EXECUTE_READ,      /* PROT_READ  */
    PAGE_EXECUTE_READWRITE, /* PROT_WRITE */
    PAGE_NOACCESS,          /* PROT_NONE  */
}
