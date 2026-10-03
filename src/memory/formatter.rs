use chrono::Local;
use owo_colors::OwoColorize;
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields, format::Writer};
use tracing_subscriber::registry::LookupSpan;

struct CustomFormatter;

impl<S, N> FormatEvent<S, N> for CustomFormatter
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
        let level = *event.metadata().level();

        let level_str = match level {
            Level::ERROR => "ERROR".red().bold().to_string(),
            Level::WARN => "WARN".yellow().bold().to_string(),
            Level::INFO => "INFO".green().to_string(),
            Level::DEBUG => "DEBUG".blue().to_string(),
            Level::TRACE => "TRACE".magenta().to_string(),
        };

        write!(
            writer,
            "[{}][{}]: ",
            timestamp.to_string().dimmed(),
            level_str
        )?;

        ctx.field_format().format_fields(writer.by_ref(), event)?;

        writeln!(writer)
    }
}

pub fn construct_formatter() {
    tracing_subscriber::fmt()
        .event_format(CustomFormatter)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
}
