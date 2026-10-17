//! How `kariz run` looks: the startup banner and the log lines.
//!
//! On a terminal, lines carry the local time, a coloured level badge and highlighted
//! fields. Under systemd (stdout going to the journal) they carry no colours and no time
//! of their own; instead each line starts with the kernel-style priority prefix (`<4>`
//! for a warning, ...), which journald turns into the entry's priority. So `journalctl`
//! highlights warnings and errors itself, and `journalctl -p warning` filters them.

use std::fmt::{self, Write as _};
use std::io::IsTerminal;

use time::{OffsetDateTime, UtcOffset};
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::fmt::format::{FormatEvent, FormatFields, Writer};
use tracing_subscriber::fmt::FmtContext;
use tracing_subscriber::registry::LookupSpan;

use kariz::config::{mode_name, role_name, Config, LogColor};

/// Who made it; shown in the banner.
const AUTHOR: &str = "ErfanXRay";
const REPOSITORY: &str = "github.com/MAHDI-byte64/tun2";

pub(crate) const RESET: &str = "\x1b[0m";
pub(crate) const BOLD: &str = "\x1b[1m";
pub(crate) const DIM: &str = "\x1b[2m";
pub(crate) const TEAL: &str = "\x1b[38;5;43m";
pub(crate) const AQUA: &str = "\x1b[38;5;86m";
pub(crate) const SAND: &str = "\x1b[38;5;179m";
pub(crate) const RED: &str = "\x1b[38;5;203m";
pub(crate) const YELLOW: &str = "\x1b[38;5;221m";
pub(crate) const BLUE: &str = "\x1b[38;5;111m";

/// Where the log lines go, which decides their look.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Style {
    pub color: bool,
    /// systemd's journal: priority prefixes instead of time and colours.
    pub journal: bool,
    /// Local time offset, read before any thread starts (see [`local_offset`]).
    pub offset: UtcOffset,
}

impl Style {
    /// Decides from `[log] color`, `NO_COLOR` and where stdout goes.
    pub fn detect(color: LogColor, offset: UtcOffset) -> Self {
        let terminal = std::io::stdout().is_terminal();
        let journal = !terminal && stdout_is_journal();
        let color = match color {
            LogColor::Always => true,
            LogColor::Never => false,
            LogColor::Auto => terminal && std::env::var_os("NO_COLOR").is_none(),
        };
        Self {
            color,
            journal,
            offset,
        }
    }

    pub(crate) fn paint(&self, code: &str, text: &str) -> String {
        if self.color {
            format!("{code}{text}{RESET}")
        } else {
            text.to_string()
        }
    }
}

/// Whether stdout is the journal. systemd sets `JOURNAL_STREAM=<device>:<inode>` for a
/// service whose output goes there, but children inherit it (a CI runner, a shell started
/// from a service) and they may have redirected stdout since. So stdout has to be that
/// very stream.
#[cfg(unix)]
fn stdout_is_journal() -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(var) = std::env::var("JOURNAL_STREAM") else {
        return false;
    };
    std::fs::metadata("/proc/self/fd/1").is_ok_and(|m| same_stream(&var, m.dev(), m.ino()))
}

#[cfg(not(unix))]
fn stdout_is_journal() -> bool {
    false
}

/// Whether a `JOURNAL_STREAM` value names the stream with this device and inode.
#[cfg_attr(not(unix), allow(dead_code))]
fn same_stream(var: &str, dev: u64, ino: u64) -> bool {
    var == format!("{dev}:{ino}")
}

/// The local offset from UTC. Must be called while the process has one thread: the
/// `time` crate refuses to read it later on Unix. Falls back to UTC.
pub fn local_offset() -> UtcOffset {
    UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC)
}

/// Formats one event as a log line.
pub struct Pretty(pub Style);

impl<S, N> FormatEvent<S, N> for Pretty
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        _ctx: &FmtContext<'_, S, N>,
        mut w: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let mut fields = Fields::default();
        event.record(&mut fields);
        w.write_str(&line(
            &self.0,
            *event.metadata().level(),
            &fields,
            now(self.0.offset),
        ))
    }
}

fn now(offset: UtcOffset) -> (u8, u8, u8) {
    let t = OffsetDateTime::now_utc().to_offset(offset);
    (t.hour(), t.minute(), t.second())
}

/// The message and the other fields of an event, in order.
#[derive(Default)]
struct Fields {
    message: String,
    rest: Vec<(&'static str, String)>,
}

impl Visit for Fields {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        } else {
            self.rest.push((field.name(), value.to_string()));
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}");
        } else {
            self.rest.push((field.name(), format!("{value:?}")));
        }
    }
}

/// One log line, with its newline.
fn line(style: &Style, level: Level, fields: &Fields, (h, m, s): (u8, u8, u8)) -> String {
    let mut out = String::new();
    if style.journal {
        // <3> err, <4> warning, <6> info, <7> debug (sd-daemon(3)).
        let priority = match level {
            Level::ERROR => 3,
            Level::WARN => 4,
            Level::INFO => 6,
            Level::DEBUG | Level::TRACE => 7,
        };
        let _ = write!(out, "<{priority}>");
    } else {
        out += &style.paint(DIM, &format!("{h:02}:{m:02}:{s:02}"));
        out.push(' ');
    }
    let (badge, color) = match level {
        Level::ERROR => ("✖ ERROR", RED),
        Level::WARN => ("▲ WARN ", YELLOW),
        Level::INFO => ("● INFO ", TEAL),
        Level::DEBUG => ("◆ DEBUG", BLUE),
        Level::TRACE => ("· TRACE", DIM),
    };
    out += &style.paint(&format!("{BOLD}{color}"), badge);
    out.push_str("  ");
    let message = match level {
        Level::ERROR => style.paint(RED, &fields.message),
        Level::WARN => style.paint(YELLOW, &fields.message),
        _ => fields.message.clone(),
    };
    out += &message;
    for (key, value) in &fields.rest {
        out.push_str("  ");
        out += &style.paint(DIM, &format!("{key}="));
        out += &style.paint(AQUA, value);
    }
    out.push('\n');
    out
}

/// The banner `kariz run` prints first: the name, the version, the author, and what this
/// side is about to do.
pub fn banner(style: &Style, config: &Config) -> String {
    const ART: [&str; 4] = [
        r" _  __   _   ___  ___  ____",
        r"| |/ /  /_\ | _ \|_ _||_  /",
        r"| ' <  / _ \|   / | |  / / ",
        r"|_|\_\/_/ \_\_|_\|___|/___|",
    ];
    let shades = [TEAL, TEAL, AQUA, AQUA];
    let mut lines = Vec::new();
    lines.push(String::new());
    for (art, shade) in ART.iter().zip(shades) {
        lines.push(format!("  {}", style.paint(&format!("{BOLD}{shade}"), art)));
    }
    lines.push(format!(
        "  {}  {}",
        style.paint(
            &format!("{BOLD}{SAND}"),
            &format!("v{}", env!("CARGO_PKG_VERSION"))
        ),
        style.paint(DIM, "fast, light tunnel core"),
    ));
    lines.push(format!(
        "  {} {}  {}",
        style.paint(DIM, "developed by"),
        style.paint(&format!("{BOLD}{SAND}"), AUTHOR),
        style.paint(DIM, REPOSITORY),
    ));
    lines.push(String::new());

    let row = |label: &str, value: String| {
        // Padded before painting: colour codes would count towards the width.
        let label = format!("{label:<8}");
        format!(
            "  {} {} {}",
            style.paint(TEAL, "▸"),
            style.paint(DIM, &label),
            value
        )
    };
    let tunnel = &config.tunnel;
    lines.push(row(
        "side",
        format!(
            "{} · {} mode",
            style.paint(BOLD, role_name(config.role)),
            mode_name(config.mode)
        ),
    ));
    lines.push(row(
        "tunnel",
        format!(
            "{} · profile {} · encryption {}",
            style.paint(BOLD, tunnel.transport.name()),
            config.profile.name(),
            tunnel.encryption.name()
        ),
    ));
    if let Some(listen) = &tunnel.listen {
        lines.push(row("listen", style.paint(AQUA, listen)));
    }
    if let Some(remote) = &tunnel.remote {
        lines.push(row("remote", style.paint(AQUA, remote)));
    }
    for f in &config.forward {
        lines.push(row(
            "forward",
            format!(
                "{} {} {} {}",
                style.paint(AQUA, &f.listen),
                style.paint(TEAL, "→"),
                style.paint(AQUA, &f.target),
                style.paint(DIM, &format!("({})", f.protocol.name())),
            ),
        ));
    }
    lines.push(String::new());

    let mut out = String::new();
    for line in lines {
        if style.journal {
            // Banner lines are plain information in the journal.
            out.push_str("<6>");
        }
        out.push_str(&line);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain() -> Style {
        Style {
            color: false,
            journal: false,
            offset: UtcOffset::UTC,
        }
    }

    fn fields(message: &str, rest: &[(&'static str, &str)]) -> Fields {
        Fields {
            message: message.to_string(),
            rest: rest.iter().map(|&(k, v)| (k, v.to_string())).collect(),
        }
    }

    #[test]
    fn plain_lines_have_time_badge_message_and_fields() {
        let f = fields("session established", &[("peer", "1.2.3.4:5")]);
        assert_eq!(
            line(&plain(), Level::INFO, &f, (9, 5, 3)),
            "09:05:03 ● INFO   session established  peer=1.2.3.4:5\n"
        );
        let w = line(&plain(), Level::WARN, &fields("slow", &[]), (23, 59, 0));
        assert_eq!(w, "23:59:00 ▲ WARN   slow\n");
    }

    #[test]
    fn journal_lines_carry_the_priority_and_no_time_or_colour() {
        let style = Style {
            journal: true,
            ..plain()
        };
        let f = fields("gone", &[]);
        assert_eq!(
            line(&style, Level::ERROR, &f, (1, 2, 3)),
            "<3>✖ ERROR  gone\n"
        );
        assert!(line(&style, Level::WARN, &f, (1, 2, 3)).starts_with("<4>"));
        assert!(line(&style, Level::INFO, &f, (1, 2, 3)).starts_with("<6>"));
        assert!(line(&style, Level::DEBUG, &f, (1, 2, 3)).starts_with("<7>"));
    }

    #[test]
    fn only_the_named_stream_is_the_journal() {
        assert!(same_stream("8:1234", 8, 1234));
        // Inherited by a child whose stdout is something else.
        assert!(!same_stream("8:1234", 8, 1235));
        assert!(!same_stream("8:1234", 9, 1234));
        assert!(!same_stream("", 8, 1234));
        assert!(!same_stream("8:1234:5", 8, 1234));
    }

    #[test]
    fn colour_only_when_asked() {
        let f = fields("x", &[("k", "v")]);
        assert!(!line(&plain(), Level::INFO, &f, (0, 0, 0)).contains('\x1b'));
        let color = Style {
            color: true,
            ..plain()
        };
        let l = line(&color, Level::INFO, &f, (0, 0, 0));
        assert!(l.contains(TEAL) && l.contains(AQUA) && l.ends_with('\n'));
    }

    #[test]
    fn banner_names_the_author_version_and_setup() {
        let text = "role = \"entry\"\nmode = \"reverse\"\n\
            [tunnel]\ntransport = \"tcpmux\"\nlisten = \"0.0.0.0:3080\"\n\
            token = \"test-token-0123456789\"\n\
            [[forward]]\nlisten = \"0.0.0.0:443\"\ntarget = \"127.0.0.1:443\"\n";
        let config = Config::parse(text).unwrap();
        let b = banner(&plain(), &config);
        assert!(b.contains("developed by ErfanXRay"), "{b}");
        assert!(b.contains(&format!("v{}", env!("CARGO_PKG_VERSION"))));
        assert!(b.contains("entry · reverse mode"));
        assert!(b.contains("tcpmux · profile balanced"));
        assert!(b.contains("0.0.0.0:443 → 127.0.0.1:443 (tcp)"));
        assert!(!b.contains('\x1b'));
        let journal = Style {
            journal: true,
            ..plain()
        };
        assert!(banner(&journal, &config)
            .lines()
            .all(|l| l.starts_with("<6>")));
    }
}
