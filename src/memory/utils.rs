use std::io;

#[allow(non_camel_case_types)]
pub enum ProtectionType {
    PAGE_EXECUTE,           /* PROT_EXEC  */
    PAGE_EXECUTE_READ,      /* PROT_READ  */
    PAGE_EXECUTE_READWRITE, /* PROT_WRITE */
    PAGE_NOACCESS,          /* PROT_NONE  */
}

/* helps with finding errors */
pub fn ctx<T, E: std::fmt::Display>(label: &str, r: Result<T, E>) -> io::Result<T> {
    r.map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{label}: {e}")))
}

pub fn parse_pattern(pattern: &str) -> Vec<Option<u8>> {
    pattern
        .split_whitespace()
        .map(|b| {
            if b == "??" || b == "?" {
                None
            } else {
                u8::from_str_radix(b, 16).ok()
            }
        })
        .collect()
}

pub fn pattern_scan_all(memory: &[u8], pattern: &[Option<u8>]) -> Vec<usize> {
    if pattern.is_empty() || pattern.len() > memory.len() {
        return vec![];
    }
    memory
        .windows(pattern.len())
        .enumerate()
        .filter_map(|(i, window)| {
            let matches = window
                .iter()
                .zip(pattern.iter())
                .all(|(byte, pat)| pat.map_or(true, |p| *byte == p));
            if matches { Some(i) } else { None }
        })
        .collect()
}
