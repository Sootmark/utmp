//! Linux login records: `utmp` (who is logged in), `wtmp` (every login,
//! logout and boot) and `btmp` (failed logins), glibc's `struct utmp`.
//!
//! The record has two sizes, and two byte orders:
//!
//! - 384 bytes where glibc keeps 32-bit times (`__WORDSIZE_TIME64_COMPAT32`:
//!   x86-64, ppc64, riscv64, mips, sparc64, and 32-bit systems):
//!   `ut_session` and `ut_tv` are 32-bit;
//! - 400 bytes elsewhere (aarch64, loongarch64, s390x): both are 64-bit;
//! - little- or big-endian (s390x, sparc64, ppc64 but not ppc64le).
//!
//! [`parse`] tells which from the records themselves: the layout under
//! which they read as login records (known types, times in a plausible
//! range, text fields that end) is the one used. A record that doesn't
//! read (an unknown type, damage) is reported in `problems` and skipped;
//! a truncated record at the end is reported too.
//!
//! [`parse_lastlog`] reads `lastlog` (each account's last login, by UID),
//! whose records come in the same layouts: 292 bytes where `struct utmp` is
//! 384, 296 where it is 400.
//!
//! [`parse_wtmpdb`] and [`parse_lastlog2`] read the SQLite databases newer
//! distributions keep instead (`/var/lib/wtmpdb/wtmp.db`,
//! `/var/lib/lastlog/lastlog2.db`), with their write-ahead logs.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use common::time::Ts;

mod lastlog;
mod sqlite_logins;

pub use lastlog::{parse_lastlog, LastLogin, Lastlog};
pub use sqlite_logins::{
    parse_lastlog2, parse_wtmpdb, LastLogin2, Lastlog2, Session, SessionKind, Sessions,
};

/// This crate's version, for records of what parsed them.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// `ut_line`, `ut_user`: 32 bytes; `ut_host`: 256; `ut_id`: 4.
const LINE: usize = 32;
const USER: usize = 32;
const HOST: usize = 256;
/// Earliest and latest plausible record times (1990, 2100), seconds.
const PLAUSIBLE: std::ops::Range<i64> = 631_152_000..4_102_444_800;

/// How the records are laid out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// 384-byte records (292 in `lastlog`), 32-bit times, little-endian
    /// (x86-64, ppc64le, riscv64, 32-bit systems).
    Time32,
    /// 400-byte records (296 in `lastlog`), 64-bit times, little-endian
    /// (aarch64, loongarch64).
    Time64,
    /// 400-byte records (296 in `lastlog`), 64-bit times, big-endian
    /// (s390x).
    Time64BigEndian,
    /// 384-byte records (292 in `lastlog`), 32-bit times, big-endian
    /// (ppc64, sparc64, big-endian mips and 32-bit systems).
    Time32BigEndian,
}

impl Layout {
    /// Every layout, the most common first: when two read equally well,
    /// the earlier is taken.
    pub const ALL: [Self; 4] = [
        Self::Time32,
        Self::Time64,
        Self::Time64BigEndian,
        Self::Time32BigEndian,
    ];
}

impl Layout {
    /// Bytes per `utmp` record.
    #[must_use]
    pub const fn record_size(self) -> usize {
        match self {
            Self::Time32 | Self::Time32BigEndian => 384,
            Self::Time64 | Self::Time64BigEndian => 400,
        }
    }

    const fn big_endian(self) -> bool {
        matches!(self, Self::Time64BigEndian | Self::Time32BigEndian)
    }

    /// Offsets of `ut_exit`, `ut_session`, `ut_tv` and `ut_addr_v6`.
    const fn offsets(self) -> (usize, usize, usize, usize) {
        match self {
            Self::Time32 | Self::Time32BigEndian => (332, 336, 340, 348),
            Self::Time64 | Self::Time64BigEndian => (332, 336, 344, 360),
        }
    }
}

/// What a record is (`ut_type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// No valid entry (0).
    Empty,
    /// A change of run level (1).
    RunLevel,
    /// The system booted (2).
    BootTime,
    /// The clock was set: the time after (3).
    NewTime,
    /// The clock was set: the time before (4).
    OldTime,
    /// A process started by init (5).
    InitProcess,
    /// A login prompt (`getty`) (6).
    LoginProcess,
    /// A user's session: a login (7).
    UserProcess,
    /// A process that ended: a logout (8).
    DeadProcess,
    /// Accounting (9, unused by glibc).
    Accounting,
}

impl Kind {
    fn from_raw(raw: i16) -> Option<Self> {
        Some(match raw {
            0 => Self::Empty,
            1 => Self::RunLevel,
            2 => Self::BootTime,
            3 => Self::NewTime,
            4 => Self::OldTime,
            5 => Self::InitProcess,
            6 => Self::LoginProcess,
            7 => Self::UserProcess,
            8 => Self::DeadProcess,
            9 => Self::Accounting,
            _ => return None,
        })
    }

    /// The name glibc gives it (`USER_PROCESS`, …).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Empty => "EMPTY",
            Self::RunLevel => "RUN_LVL",
            Self::BootTime => "BOOT_TIME",
            Self::NewTime => "NEW_TIME",
            Self::OldTime => "OLD_TIME",
            Self::InitProcess => "INIT_PROCESS",
            Self::LoginProcess => "LOGIN_PROCESS",
            Self::UserProcess => "USER_PROCESS",
            Self::DeadProcess => "DEAD_PROCESS",
            Self::Accounting => "ACCOUNTING",
        }
    }
}

/// One login record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Offset in the file.
    pub offset: u64,
    /// What it is.
    pub kind: Kind,
    /// `ut_pid`.
    pub pid: i32,
    /// `ut_line`: the terminal (`pts/0`, `tty1`, `~` for boot and run level).
    pub line: String,
    /// `ut_id`: the terminal's short id, as text (`ts/0`, `tty4`'s `4`).
    pub id: String,
    /// `ut_id` as a little-endian number, as some tools show it.
    pub id_number: u32,
    /// `ut_user`: the account (`reboot`, `runlevel` for those kinds).
    pub user: String,
    /// `ut_host`: where the login came from (a host name, an address, or a
    /// kernel version for boot records).
    pub host: String,
    /// `ut_exit`: termination and exit status of a dead process.
    pub exit_termination: i16,
    /// See `exit_termination`.
    pub exit_status: i16,
    /// `ut_session`.
    pub session: i64,
    /// `ut_tv`: when it was written, seconds since the epoch (UTC).
    pub seconds: i64,
    /// `ut_tv`: microseconds within the second.
    pub microseconds: i64,
    /// `ut_addr_v6`: the remote address, `None` when all zero.
    pub address: Option<IpAddr>,
}

impl Record {
    /// When it was written (UTC, to the microsecond).
    #[must_use]
    pub fn time(&self) -> Ts {
        Ts::from_unix_micros(
            self.seconds
                .saturating_mul(1_000_000)
                .saturating_add(self.microseconds),
        )
    }
}

/// A file's records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Records {
    /// The layout they were read with.
    pub layout: Layout,
    /// Records in file order.
    pub records: Vec<Record>,
    /// Records that couldn't be read, and a truncated end.
    pub problems: Vec<String>,
}

/// Why a file isn't login records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

/// Read the records of a `utmp`, `wtmp` or `btmp` file.
///
/// # Errors
/// When no layout reads the file as login records (empty, too short, or
/// not a login record file).
pub fn parse(data: &[u8]) -> Result<Records, Error> {
    let layout = detect(data).ok_or_else(|| Error("not utmp/wtmp/btmp records".to_owned()))?;
    let size = layout.record_size();
    let mut records = Vec::new();
    let mut problems = Vec::new();
    for (index, bytes) in data.chunks_exact(size).enumerate() {
        let offset = (index * size) as u64;
        match record(bytes, layout, offset) {
            Some(record) => records.push(record),
            None => problems.push(format!(
                "record at 0x{offset:08x}: unknown type {}",
                i16_at(bytes, 0, layout.big_endian())
            )),
        }
    }
    problems.extend(remainder(data, size));
    Ok(Records {
        layout,
        records,
        problems,
    })
}

/// The layout under which the file reads best as login records.
fn detect(data: &[u8]) -> Option<Layout> {
    Layout::ALL
        .into_iter()
        .filter(|layout| data.len() >= layout.record_size())
        .map(|layout| (score(data, layout), layout))
        .filter(|&(score, _)| score > 0)
        // `max_by_key` keeps the last of equals: reversed, ties go to the
        // earlier (more common) layout.
        .rev()
        .max_by_key(|&(score, _)| score)
        .map(|(_, layout)| layout)
}

/// How well the first records read as login records under `layout`: a
/// plausible time counts for, an impossible type or time against, an unused
/// slot for nothing; a whole number of records counts in favour.
fn score(data: &[u8], layout: Layout) -> i64 {
    let size = layout.record_size();
    let mut score = 0;
    for (index, bytes) in data.chunks_exact(size).take(64).enumerate() {
        score += match record(bytes, layout, (index * size) as u64) {
            Some(r)
                if PLAUSIBLE.contains(&r.seconds) && (0..1_000_000).contains(&r.microseconds) =>
            {
                2
            }
            // An unused slot: says nothing either way.
            Some(r) if r.kind == Kind::Empty && r.seconds == 0 => 0,
            // A time out of range, or a type that doesn't exist.
            Some(_) | None => -1,
        };
    }
    if data.len() % size == 0 {
        score += 1;
    }
    score
}

fn record(bytes: &[u8], layout: Layout, offset: u64) -> Option<Record> {
    let big = layout.big_endian();
    let kind = Kind::from_raw(i16_at(bytes, 0, big))?;
    let (exit, session, tv, addr) = layout.offsets();
    let (session, seconds, microseconds) = match layout {
        Layout::Time32 | Layout::Time32BigEndian => (
            i64::from(i32_at(bytes, session, big)),
            i64::from(i32_at(bytes, tv, big)),
            i64::from(i32_at(bytes, tv + 4, big)),
        ),
        Layout::Time64 | Layout::Time64BigEndian => (
            i64_at(bytes, session, big),
            i64_at(bytes, tv, big),
            i64_at(bytes, tv + 8, big),
        ),
    };
    let id_bytes: [u8; 4] = bytes[40..44].try_into().ok()?;
    Some(Record {
        offset,
        kind,
        pid: i32_at(bytes, 4, big),
        line: text(&bytes[8..8 + LINE]),
        id: text(&id_bytes),
        id_number: u32::from_le_bytes(id_bytes),
        user: text(&bytes[44..44 + USER]),
        host: text(&bytes[76..76 + HOST]),
        exit_termination: i16_at(bytes, exit, big),
        exit_status: i16_at(bytes, exit + 2, big),
        session,
        seconds,
        microseconds,
        address: address(&bytes[addr..addr + 16]),
    })
}

/// Bytes after the last whole record of `size`, as a problem.
fn remainder(data: &[u8], size: usize) -> Option<String> {
    let rest = data.len() % size;
    (rest > 0).then(|| {
        format!(
            "{rest} bytes after the last whole record (at 0x{:08x})",
            data.len() - rest
        )
    })
}

/// `ut_addr_v6`: an IPv4 address in the first word (network order) when
/// the others are zero, else IPv6.
fn address(bytes: &[u8]) -> Option<IpAddr> {
    if bytes.iter().all(|&b| b == 0) {
        return None;
    }
    if bytes[4..].iter().all(|&b| b == 0) {
        return Some(IpAddr::V4(Ipv4Addr::new(
            bytes[0], bytes[1], bytes[2], bytes[3],
        )));
    }
    let octets: [u8; 16] = bytes.try_into().ok()?;
    Some(IpAddr::V6(Ipv6Addr::from(octets)))
}

/// A NUL-terminated (or full-width) text field.
fn text(field: &[u8]) -> String {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}

fn i16_at(bytes: &[u8], at: usize, big: bool) -> i16 {
    let raw = [bytes[at], bytes[at + 1]];
    if big {
        i16::from_be_bytes(raw)
    } else {
        i16::from_le_bytes(raw)
    }
}

fn i32_at(bytes: &[u8], at: usize, big: bool) -> i32 {
    let raw = [bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]];
    if big {
        i32::from_be_bytes(raw)
    } else {
        i32::from_le_bytes(raw)
    }
}

fn i64_at(bytes: &[u8], at: usize, big: bool) -> i64 {
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&bytes[at..at + 8]);
    if big {
        i64::from_be_bytes(raw)
    } else {
        i64::from_le_bytes(raw)
    }
}
