//! `lastlog` files built here, record by record, in each layout.

use utmp::Layout;

/// 2024-03-01T12:00:00Z and 2025-07-14T08:30:00Z.
const ROOT_LOGIN: i64 = 1_709_294_400;
const USER_LOGIN: i64 = 1_752_481_800;

const LAYOUTS: [Layout; 4] = Layout::ALL;

/// One `struct lastlog`, as glibc writes it: text zero-padded.
fn record(layout: Layout, seconds: i64, line: &str, host: &str) -> Vec<u8> {
    let mut bytes = match layout {
        Layout::Time32 => (seconds as u32).to_le_bytes().to_vec(),
        Layout::Time32BigEndian => (seconds as u32).to_be_bytes().to_vec(),
        Layout::Time64 => seconds.to_le_bytes().to_vec(),
        Layout::Time64BigEndian => seconds.to_be_bytes().to_vec(),
    };
    for (text, width) in [(line, 32), (host, 256)] {
        let mut field = text.as_bytes().to_vec();
        field.resize(width, 0);
        bytes.extend(field);
    }
    bytes
}

/// A file of `uids` records, zero but for `logins`.
fn file(layout: Layout, uids: usize, logins: &[(usize, Vec<u8>)]) -> Vec<u8> {
    let size = record(layout, 0, "", "").len();
    let mut data = vec![0; uids * size];
    for (uid, bytes) in logins {
        data[uid * size..(uid + 1) * size].copy_from_slice(bytes);
    }
    data
}

/// root from a remote host, and UID 1000 at the console.
fn two_logins(layout: Layout) -> Vec<u8> {
    file(
        layout,
        1_001,
        &[
            (0, record(layout, ROOT_LOGIN, "pts/0", "192.0.2.10")),
            (1_000, record(layout, USER_LOGIN, "tty1", "")),
        ],
    )
}

#[test]
fn every_layout_reads_and_is_told_apart() {
    for layout in LAYOUTS {
        let lastlog = utmp::parse_lastlog(&two_logins(layout));
        assert_eq!(lastlog.layout, layout);
        assert!(lastlog.problems.is_empty(), "{:?}", lastlog.problems);
        let got: Vec<(u32, String, &str, &str)> = lastlog
            .entries
            .iter()
            .map(|e| {
                (
                    e.uid,
                    e.time.to_iso8601().unwrap(),
                    e.line.as_str(),
                    e.host.as_str(),
                )
            })
            .collect();
        assert_eq!(
            got,
            [
                (
                    0,
                    "2024-03-01T12:00:00.0000000Z".to_owned(),
                    "pts/0",
                    "192.0.2.10"
                ),
                (1_000, "2025-07-14T08:30:00.0000000Z".to_owned(), "tty1", ""),
            ],
            "{layout:?}"
        );
    }
}

#[test]
fn a_single_login_past_uid_zero_is_told_apart() {
    for layout in LAYOUTS {
        let data = file(
            layout,
            43,
            &[(42, record(layout, USER_LOGIN, "pts/3", "host.example"))],
        );
        let lastlog = utmp::parse_lastlog(&data);
        assert_eq!(lastlog.layout, layout);
        assert_eq!(lastlog.entries.len(), 1, "{layout:?}");
        assert_eq!(lastlog.entries[0].uid, 42, "{layout:?}");
    }
}

#[test]
fn no_one_logged_in() {
    for data in [Vec::new(), vec![0; 292 * 296 * 4]] {
        let lastlog = utmp::parse_lastlog(&data);
        assert!(lastlog.entries.is_empty());
        assert!(lastlog.problems.is_empty(), "{:?}", lastlog.problems);
    }
}

#[test]
fn a_large_sparse_file() {
    // UID 65534 (`nobody`), as on a system where it has logged in.
    let data = file(
        Layout::Time32,
        65_535,
        &[(65_534, record(Layout::Time32, ROOT_LOGIN, "tty2", ""))],
    );
    let lastlog = utmp::parse_lastlog(&data);
    assert_eq!(lastlog.entries.len(), 1);
    assert_eq!(lastlog.entries[0].uid, 65_534);
}

#[test]
fn a_time_past_2038_in_32_bits() {
    // 2100-01-01T00:00:00Z less a second: negative as a signed 32-bit time.
    let seconds = 4_102_444_799;
    let data = file(
        Layout::Time32,
        1,
        &[(0, record(Layout::Time32, seconds, "pts/1", ""))],
    );
    let lastlog = utmp::parse_lastlog(&data);
    assert_eq!(
        lastlog.entries[0].time.to_iso8601().unwrap(),
        "2099-12-31T23:59:59.0000000Z"
    );
}

#[test]
fn full_width_text() {
    let line = "x".repeat(32);
    let host = "h".repeat(256);
    let data = record(Layout::Time32, ROOT_LOGIN, &line, &host);
    let entry = &utmp::parse_lastlog(&data).entries[0];
    assert_eq!((entry.line.as_str(), entry.host.as_str()), (&*line, &*host));
}

#[test]
fn damage_is_reported() {
    let mut data = two_logins(Layout::Time32);
    // UID 1: a time before 1990.
    data[292..296].copy_from_slice(&1_000u32.to_le_bytes());
    data.extend([0xff; 10]);
    let lastlog = utmp::parse_lastlog(&data);
    assert_eq!(lastlog.layout, Layout::Time32);
    let uids: Vec<u32> = lastlog.entries.iter().map(|e| e.uid).collect();
    assert_eq!(uids, [0, 1, 1_000]);
    assert_eq!(
        lastlog.problems,
        [
            "uid 1 (at 0x00000124): time 1000 out of range",
            "10 bytes after the last whole record (at 0x000475c4)",
        ]
    );
}

mod damage {
    use proptest::prelude::*;

    proptest! {
        /// Any bytes: read, never a panic.
        #[test]
        fn arbitrary_bytes(data in proptest::collection::vec(any::<u8>(), 0..3_000)) {
            let lastlog = utmp::parse_lastlog(&data);
            prop_assert!(lastlog.entries.len() * 292 <= data.len());
            prop_assert!(lastlog.entries.windows(2).all(|w| w[0].uid < w[1].uid));
        }

        /// A file of logins, damaged anywhere and cut anywhere.
        #[test]
        fn damaged_files(flips in proptest::collection::vec((0usize..292_292, any::<u8>()), 1..10), cut in 0usize..292_292) {
            let mut data = super::two_logins(utmp::Layout::Time32);
            for (at, byte) in flips {
                data[at] = byte;
            }
            data.truncate(cut);
            let lastlog = utmp::parse_lastlog(&data);
            prop_assert!(lastlog.entries.len() * 292 <= data.len());
        }
    }
}
