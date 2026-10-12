// pub mod openttd;
// pub mod test;
// pub mod tfoc;
// pub mod twfc;

use std::io;

#[macro_export]
macro_rules! binify {
    ($($name:ident),* $(,)?) => {
        $(pub mod $name;)*

        pub fn entry(game: &str) -> io::Result<()> {
            match game {
                $(stringify!($name) => $name::entry(),)*
                other => Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no patch for bin `{other}`"),
                )),
            }
        }
    };
}

binify!(openttd, test, tfoc, twfc);
