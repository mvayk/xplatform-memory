use std::io;
use xpmemtool::{formatter, patch};

fn main() -> io::Result<()> {
    formatter::init();
    patch::entry(env!("CARGO_BIN_NAME"))
}
