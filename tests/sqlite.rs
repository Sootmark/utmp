//! wtmpdb and lastlog2 databases made by `tests/fixtures/sqlite/gen.sh`
//! with the tables wtmpdb 0.73 and util-linux 2.41 create: what wtmpdb's
//! own `last` prints for the same file, the session only in the
//! write-ahead log, and lastlog2's logins.

use utmp::{parse_lastlog2, parse_wtmpdb, SessionKind};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/sqlite/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

/// `2026-09-01T08:01:40` from `Ts::to_iso8601`'s full precision.
fn seconds(ts: Option<common::time::Ts>) -> Option<String> {
    ts.and_then(|ts| ts.to_iso8601())
        .map(|iso| iso[..19].to_owned())
}

#[test]
fn sessions_as_wtmpdb_last_prints_them() {
    let parsed = parse_wtmpdb(&fixture("wtmp.db"), &[]).unwrap();
    assert!(parsed.problems.is_empty(), "{:?}", parsed.problems);
    let ours: Vec<_> = parsed
        .sessions
        .iter()
        .rev()
        .map(|s| {
            (
                s.user.as_str(),
                s.tty.as_str(),
                s.remote_host.as_str(),
                seconds(s.login),
                seconds(s.logout),
            )
        })
        .collect();
    // wtmpdb last -F, newest first (wtmp.last), times in UTC.
    let at = |t: &str| Some(format!("2026-09-01T{t}"));
    assert_eq!(
        ours,
        [
            (
                "deploy",
                "pts/1",
                "2001:db8::7",
                at("08:23:20"),
                at("08:24:20")
            ),
            ("root", "tty1", "", at("08:06:40"), None),
            (
                "alice",
                "pts/0",
                "192.0.2.15",
                at("08:01:40"),
                at("09:01:40")
            ),
            ("reboot", "~", "6.12.48+deb13-amd64", at("08:00:00"), None),
        ]
    );
    let last = String::from_utf8(fixture("wtmp.last")).unwrap();
    assert!(last.starts_with("deploy   pts/1        2001:db8::7      Tue Sep  1 08:23:20 2026"));
    assert_eq!(parsed.sessions[0].kind, SessionKind::Boot);
    assert_eq!(parsed.sessions[1].kind, SessionKind::User);
    assert_eq!(parsed.sessions[1].service, "sshd");
    // Microseconds kept.
    assert_eq!(
        parsed.sessions[1].login.unwrap().to_iso8601().unwrap(),
        "2026-09-01T08:01:40.1234560Z"
    );
}

#[test]
fn sessions_only_in_the_log() {
    let database = fixture("wal/wtmp.db");
    let users = |wal: &[u8]| -> Vec<String> {
        parse_wtmpdb(&database, wal)
            .unwrap()
            .sessions
            .into_iter()
            .map(|s| s.user)
            .collect()
    };
    assert_eq!(users(&[]), ["reboot", "alice", "root", "deploy"]);
    assert_eq!(
        users(&fixture("wal/wtmp.db-wal")),
        ["reboot", "alice", "root", "deploy", "mallory"]
    );
}

#[test]
fn lastlog2_logins() {
    let parsed = parse_lastlog2(&fixture("lastlog2.db"), &[]).unwrap();
    assert!(parsed.problems.is_empty(), "{:?}", parsed.problems);
    let logins: Vec<_> = parsed
        .logins
        .iter()
        .map(|l| {
            (
                l.user.as_str(),
                seconds(l.time),
                l.remote_host.as_str(),
                l.service.as_str(),
            )
        })
        .collect();
    assert_eq!(
        logins,
        [
            ("root", Some("2026-09-01T08:06:40".to_owned()), "", "login"),
            (
                "alice",
                Some("2026-09-01T08:01:40".to_owned()),
                "192.0.2.15",
                "sshd"
            ),
        ]
    );
}

#[test]
fn other_files_and_damage() {
    assert!(parse_wtmpdb(b"not a database", &[]).is_err());
    // A lastlog2 database has no wtmp table, and the reverse.
    assert!(parse_wtmpdb(&fixture("lastlog2.db"), &[]).is_err());
    assert!(parse_lastlog2(&fixture("wtmp.db"), &[]).is_err());
}

proptest::proptest! {
    /// Damaged anywhere, a database gives sessions, problems or an error,
    /// never a panic.
    #[test]
    fn damage_never_panics(
        flips in proptest::collection::vec((0usize..8192, proptest::prelude::any::<u8>()), 1..40),
        cut in 0usize..8192,
    ) {
        for name in ["wtmp.db", "lastlog2.db"] {
            let mut data = fixture(name);
            for &(at, byte) in &flips {
                let at = at % data.len();
                data[at] = byte;
            }
            data.truncate(cut.max(1));
            let _ = parse_wtmpdb(&data, &[]);
            let _ = parse_lastlog2(&data, &[]);
        }
    }

}
