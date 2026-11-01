use std::{
    fs::{File, OpenOptions},
    io::{self, Error, ErrorKind, Read, Seek, SeekFrom, Write, stdin, stdout},
    path::Path,
};
use xpmemtool::{core::Xpmentool, process::Process};

const FAKETIME_RC_PATH: &str = "/tmp/my-faketime.rc";

/* ENV Variables
LD_PRELOAD=/run/current-system/sw/lib/libfaketime.so.1
FAKETIME_TIMESTAMP_FILE=/tmp/my-faketime.rc
FAKETIME_CACHE_DURATION=1
*/

fn main() -> io::Result<()> {
    Xpmentool::init(false);

    let path = Path::new(FAKETIME_RC_PATH);
    let mut file = OpenOptions::new().write(true).create(true).open(path)?;

    set_faketime(&mut file, 1.0)?;

    let Ok(_) = Process::new("java") else {
        xpmemtool::log!("failed to find minecraft, please launch it with libfaketime: ");
        std::process::exit(0);
    };

    set_faketime(&mut file, 1.0)?;

    let multiplier = query_input()?;
    set_faketime(&mut file, multiplier)?;

    Ok(())
}

fn set_faketime(file: &mut File, multiplier: f32) -> io::Result<()> {
    let s = format!("+0 x{}\n", multiplier);
    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(s.as_bytes())
}

fn query_input() -> io::Result<f32> {
    print!("enter speed multiplier (0.1 - 10.0): ");
    stdout().flush()?;

    let mut input = String::new();
    stdin().read_line(&mut input)?;

    let multi: f32 = input
        .trim()
        .parse()
        .map_err(|_| Error::new(ErrorKind::InvalidInput, "please enter a valid number"))?;

    if !(0.1..=10.0).contains(&multi) {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "please enter a value between 0.1 and 10.0",
        ));
    }

    Ok(multi)
}
