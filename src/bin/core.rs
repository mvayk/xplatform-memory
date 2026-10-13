/* todo
    swap mapentry and pages to ranges for addresses like modules do
    have a better system for querying data from regions, modules and pages
    allow memory functions to use those ranges for addresses
    remove all the unnecessary io::Result<>
*/

use std::io;
use xpmemtool::{formatter, patch};

fn main() -> io::Result<()> {
    formatter::init();
    patch::entry(env!("CARGO_BIN_NAME"))
}
