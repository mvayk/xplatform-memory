use chrono::Local;

pub fn get_timestamp() {
    Local::now().format("%H:%M:%S%.3f");
}
