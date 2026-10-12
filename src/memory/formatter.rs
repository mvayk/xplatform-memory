use chrono::Local;
use owo_colors::OwoColorize;
use std::sync::Once;
use std::{fmt, ops::Add, ops::Deref, ops::Sub};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields, format::Writer};
use tracing_subscriber::registry::LookupSpan;

enum TraceLevel {
    ERROR,
    WARN,
    INFO,
    DEBUG,
    TRACE,
}

impl TraceLevel {
    pub fn match_string(&self) -> &str {
        match self {
            TraceLevel::ERROR => "error",
            TraceLevel::WARN => "warn",
            TraceLevel::INFO => "info",
            TraceLevel::DEBUG => "debug",
            TraceLevel::TRACE => "trace",
        }
    }
}

static INIT: Once = Once::new();
static DEBUG_BUILD_LEVEL: TraceLevel = TraceLevel::DEBUG;

#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => {
        tracing::info!(target: "MAIN", $($arg)*)
    };
}

struct FormatOutput {}

pub fn init() {
    INIT.call_once(|| {
        let default_level = if cfg!(debug_assertions) {
            DEBUG_BUILD_LEVEL.match_string()
        } else {
            "info"
        };

        tracing_subscriber::fmt()
            .event_format(FormatOutput {})
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| default_level.into()),
            )
            .init();
    });
}

impl<S, N> FormatEvent<S, N> for FormatOutput
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> std::fmt::Result {
        let timestamp = Local::now().format("%H:%M:%S%.3f");
        //let level = *event.metadata().level();

        let meta = event.metadata();
        let level = *meta.level();

        let level_str = if meta.target() == "MAIN" {
            "MAIN".white().bold().to_string()
        } else {
            match level {
                Level::ERROR => "ERRO".red().bold().to_string(),
                Level::WARN => "WARN".yellow().bold().to_string(),
                Level::INFO => "INFO".green().to_string(),
                Level::DEBUG => "DEBG".blue().to_string(),
                Level::TRACE => "TRCE".magenta().to_string(),
            }
        };

        write!(
            writer,
            "[{}][{}]: ",
            timestamp.to_string().dimmed(),
            //self.pid,
            level_str
        )?;

        ctx.field_format().format_fields(writer.by_ref(), event)?;

        writeln!(writer)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Hex(pub u64);

impl fmt::Display for Hex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl fmt::LowerHex for Hex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl Deref for Hex {
    type Target = u64;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Sub for Hex {
    type Output = u64;
    fn sub(self, rhs: Self) -> Self::Output {
        self.0 - rhs.0
    }
}

impl Add<u64> for Hex {
    type Output = Self;
    fn add(self, rhs: u64) -> Self::Output {
        Hex(self.0 + rhs)
    }
}
