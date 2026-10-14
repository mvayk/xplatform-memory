use chrono::{
    Local,
    format::{DelayedFormat, StrftimeItems},
};

pub fn get_timestamp() -> DelayedFormat<StrftimeItems<'static>> {
    Local::now().format("%H:%M:%S%.3f")
}
