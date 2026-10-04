//! The SQLite databases that replace `wtmp` and `lastlog` on recent
//! distributions (Debian 13, openSUSE, …): wtmpdb's
//! `/var/lib/wtmpdb/wtmp.db`, one row per session with its login and
//! logout, and util-linux's `/var/lib/lastlog/lastlog2.db`, each account's
//! last login by name. Both are read with their write-ahead log, if any:
//! recent sessions may be only there.
//!
//! wtmpdb writes times in microseconds since the Unix epoch, lastlog2 in
//! seconds; a session still open has no logout.

use common::time::Ts;
use sqlite::{Database, Row, Value};

use crate::Error;

/// What a wtmpdb row records (its `Type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionKind {
    /// `1`: a boot; the user is `reboot`, the remote host the kernel.
    Boot,
    /// `2`: a run level change (unused with systemd).
    RunLevel,
    /// `3`: a login session.
    User,
    /// Any other number, as written.
    Other(i64),
}

impl SessionKind {
    fn from_raw(value: i64) -> Self {
        match value {
            1 => Self::Boot,
            2 => Self::RunLevel,
            3 => Self::User,
            other => Self::Other(other),
        }
    }
}

/// One wtmpdb row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// `ID`: the row's number, in the order sessions began.
    pub id: i64,
    /// `Type`.
    pub kind: SessionKind,
    /// `User`.
    pub user: String,
    /// `Login`: when it began.
    pub login: Option<Ts>,
    /// `Logout`: when it ended; `None` while open, or if the host stopped
    /// before it did.
    pub logout: Option<Ts>,
    /// `TTY`: the terminal (`pts/0`, `tty1`, `~` for a boot).
    pub tty: String,
    /// `RemoteHost`: where it came from; for a boot, the kernel.
    pub remote_host: String,
    /// `Service`: the PAM service that opened it (`sshd`, `login`).
    pub service: String,
}

/// A wtmpdb database's sessions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sessions {
    /// In `ID` order.
    pub sessions: Vec<Session>,
    /// Damage in the database or its log.
    pub problems: Vec<String>,
}

/// One lastlog2 row: an account's last login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LastLogin2 {
    /// `Name`: the account.
    pub user: String,
    /// `Time`: when.
    pub time: Option<Ts>,
    /// `TTY`.
    pub tty: String,
    /// `RemoteHost`.
    pub remote_host: String,
    /// `Service`: the PAM service.
    pub service: String,
}

/// A lastlog2 database's logins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lastlog2 {
    /// By account, in the order they were first recorded.
    pub logins: Vec<LastLogin2>,
    /// Damage in the database or its log.
    pub problems: Vec<String>,
}

/// Read a wtmpdb database (`wtmp.db`), with its `-wal` file's committed
/// changes (`wal` may be empty).
///
/// # Errors
/// When it isn't a SQLite database or has no `wtmp` table.
pub fn parse_wtmpdb(database: &[u8], wal: &[u8]) -> Result<Sessions, Error> {
    let (sessions, problems) = read_table(database, wal, "wtmp", |row| Session {
        id: row.integer("ID").unwrap_or(row.rowid),
        kind: SessionKind::from_raw(row.integer("Type").unwrap_or(0)),
        user: row.text("User"),
        login: row.integer("Login").map(Ts::from_unix_micros),
        logout: row.integer("Logout").map(Ts::from_unix_micros),
        tty: row.text("TTY"),
        remote_host: row.text("RemoteHost"),
        service: row.text("Service"),
    })?;
    Ok(Sessions { sessions, problems })
}

/// Read a lastlog2 database (`lastlog2.db`), with its `-wal` file's
/// committed changes (`wal` may be empty).
///
/// # Errors
/// When it isn't a SQLite database or has no `Lastlog2` table.
pub fn parse_lastlog2(database: &[u8], wal: &[u8]) -> Result<Lastlog2, Error> {
    let (logins, problems) = read_table(database, wal, "Lastlog2", |row| LastLogin2 {
        user: row.text("Name"),
        time: row.integer("Time").map(Ts::from_unix_seconds),
        tty: row.text("TTY"),
        remote_host: row.text("RemoteHost"),
        service: row.text("Service"),
    })?;
    Ok(Lastlog2 { logins, problems })
}

/// A row with its table's column names, read by name.
struct Named<'t> {
    columns: &'t [String],
    rowid: i64,
    values: Vec<Value>,
}

impl Named<'_> {
    fn value(&self, column: &str) -> Option<&Value> {
        let at = self
            .columns
            .iter()
            .position(|name| name.eq_ignore_ascii_case(column))?;
        self.values.get(at)
    }

    fn integer(&self, column: &str) -> Option<i64> {
        self.value(column).and_then(Value::as_integer)
    }

    fn text(&self, column: &str) -> String {
        self.value(column)
            .and_then(Value::as_text)
            .unwrap_or_default()
            .to_owned()
    }
}

/// Every row of `table`, converted, and the problems met reading them.
fn read_table<T>(
    database: &[u8],
    wal: &[u8],
    table: &str,
    convert: impl Fn(&Named<'_>) -> T,
) -> Result<(Vec<T>, Vec<String>), Error> {
    let db = Database::open_with_wal(database, wal).map_err(|e| Error(e.to_string()))?;
    let columns: Vec<String> = db
        .table(table)
        .ok_or_else(|| Error(format!("no {table} table")))?
        .column_names()
        .into_iter()
        .map(str::to_owned)
        .collect();
    let mut rows = db.rows(table).map_err(|e| Error(e.to_string()))?;
    let converted = rows
        .by_ref()
        .map(|Row { rowid, values, .. }| {
            convert(&Named {
                columns: &columns,
                rowid,
                values,
            })
        })
        .collect();
    let problems = db.problems.iter().chain(rows.problems()).cloned().collect();
    Ok((converted, problems))
}
