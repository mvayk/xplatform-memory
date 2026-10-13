use crate::types::AddyRange;

pub fn range_to_string(address_range: AddyRange) -> String {
    format!("{:x}-{:x}", address_range.start, address_range.end)
}
