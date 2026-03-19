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
