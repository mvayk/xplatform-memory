/* todo
    swap mapentry and pages to ranges for addresses like modules do
    have a better system for querying data from regions, modules and pages
    allow memory functions to use those AddrRange for addresses
    remove all the unnecessary io::Result<>
*/

use crate::formatter;
use std::sync::OnceLock;

static INITIALIZED: OnceLock<()> = OnceLock::new();

pub struct Xpmentool {}

impl Xpmentool {
    pub fn init() {
        INITIALIZED.get_or_init(formatter::init);
    }

    pub fn is_initialized() -> bool {
        INITIALIZED.get().is_some()
    }
}
