use std::{fmt, io};

pub struct Hex(pub u64);
impl fmt::Display for Hex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

pub fn parse_address(input: &str) -> io::Result<u64> {
    let trimmed = input.trim();
    let digits = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);

    u64::from_str_radix(digits, 16).map_err(|e| {
        tracing::error!(input = input, error = %e, "parse_address failed");
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{input:?} is not a valid hex address"),
        )
    })
}
