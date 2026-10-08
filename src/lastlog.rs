//! `/var/log/lastlog`: each account's last login, glibc's `struct lastlog`.
//!
//! The file is indexed by UID: the record for UID n is at n times the
//! record size, and an account that never logged in has an all-zero record
//! (most of the file, which is sparse). A record is `ll_time`, `ll_line`
//! (32 bytes) and `ll_host` (256), in the layouts of `struct utmp`:
//!
//! - 292 bytes where `struct utmp` is 384: `ll_time` is a 32-bit number,
//!   unsigned in current glibc (signed in older headers: the two agree
//!   until 2038);
//! - 296 bytes where it is 400: `ll_time` is 64-bit, in either byte order.

use common::time::Ts;

use crate::{i32_at, i64_at, remainder, text, Layout, HOST, LINE, PLAUSIBLE};

/// One account's last login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LastLogin {
    /// The account: the record's place in the file.
    pub uid: u32,
    /// `ll_time`: when (UTC, to the second).
    pub time: Ts,
    /// `ll_line`: the terminal (`pts/0`, `tty1`).
    pub line: String,
    /// `ll_host`: where the login came from, empty for a local one.
    pub host: String,
}

/// A `lastlog` file's logins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lastlog {
    /// The layout they were read with.
    pub layout: Layout,
    /// Accounts that have logged in, by UID.
    pub entries: Vec<LastLogin>,
    /// Logins at an implausible time, and a truncated end.
    pub problems: Vec<String>,
}

/// Read the last login of every account in a `lastlog` file.
///
/// Any bytes read as something: a file of zeros (no one has logged in) has
/// no entries, and a login at an implausible time is kept and reported in
/// `problems`.
#[must_use]
pub fn parse_lastlog(data: &[u8]) -> Lastlog {
    let layout = detect(data);
    let size = record_size(layout);
    let mut entries = Vec::new();
    let mut problems = Vec::new();
    for (uid, bytes) in logins(data, layout) {
        let login = login(bytes, layout);
        if !login.plausible() {
            problems.push(format!(
                "uid {uid} (at 0x{:08x}): time {} out of range",
                u64::from(uid) * size as u64,
                login.seconds
            ));
        }
        entries.push(LastLogin {
            uid,
            time: Ts::from_unix_seconds(login.seconds),
            line: text(login.line),
            host: text(login.host),
        });
    }
    problems.extend(remainder(data, size));
    Lastlog {
        layout,
        entries,
        problems,
    }
}

/// The layout under which the file reads best as last logins, the 32-bit
/// one when nothing tells (a file of zeros).
fn detect(data: &[u8]) -> Layout {
    Layout::ALL
        .into_iter()
        // `max_by_key` keeps the last of equals: reversed, ties go to the
        // earlier (more common) layout.
        .rev()
        .max_by_key(|&layout| score(data, layout))
        .unwrap_or(Layout::Time32)
}

/// How well the first logins read under `layout`: a plausible time with
/// text fields that end in zeros counts for, anything else against; a whole
/// number of records counts in favour.
fn score(data: &[u8], layout: Layout) -> i64 {
    let mut score = 0;
    for (_, bytes) in logins(data, layout).take(64) {
        let login = login(bytes, layout);
        score += if login.plausible() && padded(login.line) && padded(login.host) {
            2
        } else {
            -1
        };
    }
    if data.len() % record_size(layout) == 0 {
        score += 1;
    }
    score
}

/// The records that aren't all zero, with their UID.
fn logins(data: &[u8], layout: Layout) -> impl Iterator<Item = (u32, &[u8])> {
    (0..=u32::MAX)
        .zip(data.chunks_exact(record_size(layout)))
        .filter(|(_, bytes)| bytes.iter().any(|&b| b != 0))
}

/// A record's fields, undecoded.
struct Login<'a> {
    seconds: i64,
    line: &'a [u8],
    host: &'a [u8],
}

impl Login<'_> {
    fn plausible(&self) -> bool {
        PLAUSIBLE.contains(&self.seconds)
    }
}

fn login(bytes: &[u8], layout: Layout) -> Login<'_> {
    let big = layout.big_endian();
    let (seconds, line) = match layout {
        // Unsigned: a 32-bit time that runs to 2106.
        // macOS keeps no lastlog: its layout never reads one.
        Layout::Time32 | Layout::Time32BigEndian | Layout::MacUtmpx => {
            (i64::from(i32_at(bytes, 0, big) as u32), 4)
        }
        Layout::Time64 | Layout::Time64BigEndian => (i64_at(bytes, 0, big), 8),
    };
    Login {
        seconds,
        line: &bytes[line..line + LINE],
        host: &bytes[line + LINE..line + LINE + HOST],
    }
}

/// Whether a text field is all zeros after its end, as written.
fn padded(field: &[u8]) -> bool {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    field[end..].iter().all(|&b| b == 0)
}

const fn record_size(layout: Layout) -> usize {
    match layout {
        Layout::Time32 | Layout::Time32BigEndian | Layout::MacUtmpx => 292,
        Layout::Time64 | Layout::Time64BigEndian => 296,
    }
}
