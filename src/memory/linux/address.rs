use crate::types::{Address, AddyRange};

pub fn get_size(range: AddyRange) -> u64 {
    range.end - range.start
}

pub fn contains(inside: AddyRange, address: Address) -> bool {
    inside.contains(address)
}

pub fn offset_of(inside: AddyRange, address: Address) -> Option<u64> {
    inside.contains(address).then(|| address - inside.start)
}
