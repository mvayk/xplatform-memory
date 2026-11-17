/* todo
    swap mapentry and pages to ranges for addresses like modules do
    have a better system for querying data from regions, modules and pages
    allow memory functions to use those AddrRange for addresses
    remove all the unnecessary io::Result<>
*/

use crate::formatter;
use std::{io, path::PathBuf, sync::OnceLock};

static INITIALIZED: OnceLock<()> = OnceLock::new();

pub struct Xpmentool {
    log: bool,
}

impl Xpmentool {
    pub fn init(log: bool) -> Self {
        if log {
            INITIALIZED.get_or_init(formatter::init);
        }

        Xpmentool { log }
    }

    pub fn get_dll_path() -> io::Result<PathBuf> {
        let path_str = "./xpmemtool.dll";
        let dll_path = std::path::PathBuf::from(path_str);
        Ok(dll_path)
    }

    pub fn is_initialized() -> bool {
        if INITIALIZED.get().is_some() {
            return true;
        } else {
            return false;
        }
    }
}
