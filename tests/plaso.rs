//! plaso's utmp test files (Apache-2.0, `tests/fixtures/plaso/`):
//!
//! - the x86-64 ones (384-byte records), every field of every record
//!   against util-linux's `utmpdump` 2.38.1 (its output in `tests/oracle/`;
//!   it shows records of unknown types, which are skipped here);
//! - the aarch64 and s390x ones (400-byte records, little- and big-endian),
//!   against what plaso's own tests expect of them.

use std::fs;
use std::path::Path;

fn fixture(name: &str) -> Vec<u8> {
    fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/plaso")
            .join(name),
    )
    .unwrap()
}

/// A record's fields as `utmpdump` prints them, trimmed.
fn ours(record: &utmp::Record) -> Vec<String> {
    let kind = [
        utmp::Kind::Empty,
        utmp::Kind::RunLevel,
        utmp::Kind::BootTime,
        utmp::Kind::NewTime,
        utmp::Kind::OldTime,
        utmp::Kind::InitProcess,
        utmp::Kind::LoginProcess,
        utmp::Kind::UserProcess,
        utmp::Kind::DeadProcess,
        utmp::Kind::Accounting,
    ]
    .iter()
    .position(|k| *k == record.kind)
    .unwrap();
    // A zero time is no time here; utmpdump prints the epoch.
    let time = record
        .time()
        .to_iso8601()
        .unwrap_or_else(|| "1970-01-01T00:00:00.0000000Z".to_owned());
    vec![
        kind.to_string(),
        format!("{:05}", record.pid),
        record.id.clone(),
        record.user.clone(),
        record.line.clone(),
        record.host.clone(),
        record
            .address
            .map_or("0.0.0.0".to_owned(), |a| a.to_string()),
        // utmpdump: `2013-12-13T14:45:09,688666+00:00`.
        format!("{},{}+00:00", &time[..19], &time[20..26]),
    ]
}

fn utmpdump(name: &str) -> Vec<Vec<String>> {
    let text = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/oracle")
            .join(format!("{name}.utmpdump")),
    )
    .unwrap();
    text.lines()
        .map(|line| {
            line.trim_start_matches('[')
                .trim_end_matches(']')
                .split("] [")
                .map(|field| field.trim().to_owned())
                .collect()
        })
        .collect()
}

#[test]
fn x86_64_records_match_utmpdump() {
    let mut total = 0;
    for (name, problems) in [
        ("utmp", 0),
        ("utmp_x86_64", 0),
        ("wtmp.1", 1),
        ("utmp_corrupted", 3),
    ] {
        let records = utmp::parse(&fixture(name)).unwrap();
        assert_eq!(records.layout, utmp::Layout::Time32, "{name}");
        assert_eq!(
            records.problems.len(),
            problems,
            "{name}: {:?}",
            records.problems
        );
        // utmpdump also lists records of unknown types (99 here).
        let expected: Vec<Vec<String>> = utmpdump(name)
            .into_iter()
            .filter(|fields| fields[0] != "99")
            .collect();
        let got: Vec<Vec<String>> = records.records.iter().map(ours).collect();
        assert_eq!(got, expected, "{name}");
        total += got.len();
    }
    assert_eq!(total, 26);
}

#[test]
fn what_plaso_expects() {
    let records = utmp::parse(&fixture("utmp")).unwrap().records;
    let login = &records[2];
    assert_eq!(
        (
            login.kind,
            login.pid,
            login.line.as_str(),
            login.user.as_str()
        ),
        (utmp::Kind::LoginProcess, 1115, "tty4", "LOGIN")
    );
    assert_eq!(login.id_number, 52);
    let wtmp = utmp::parse(&fixture("wtmp.1")).unwrap().records;
    assert_eq!(wtmp[0].id_number, 842_084_211);
    assert_eq!(
        wtmp[0].time().to_iso8601().unwrap(),
        "2011-12-01T17:36:38.4329350Z"
    );

    for (name, layout, address) in [
        ("utmp_aarch64", utmp::Layout::Time64, "4.3.2.1"),
        ("utmp_s390", utmp::Layout::Time64BigEndian, "1.2.3.4"),
    ] {
        let records = utmp::parse(&fixture(name)).unwrap();
        assert_eq!(records.layout, layout, "{name}");
        assert!(
            records.problems.is_empty(),
            "{name}: {:?}",
            records.problems
        );
        let kinds: Vec<utmp::Kind> = records.records.iter().map(|r| r.kind).collect();
        assert_eq!(
            kinds,
            [
                utmp::Kind::Empty,
                utmp::Kind::DeadProcess,
                utmp::Kind::BootTime,
                utmp::Kind::RunLevel,
                utmp::Kind::OldTime,
                utmp::Kind::NewTime
            ],
            "{name}"
        );
        // The dead process: its offset shows records are 400 bytes.
        let dead = &records.records[1];
        assert_eq!((dead.offset, dead.line.as_str()), (400, "tty2"), "{name}");
        assert_eq!(dead.address.unwrap().to_string(), address, "{name}");
        // The clock was moved five minutes forward.
        let (old, new) = (&records.records[4], &records.records[5]);
        assert_eq!(new.seconds - old.seconds, 300, "{name}");
    }
}

mod damage {
    use proptest::prelude::*;

    proptest! {
        /// Any bytes: read or refused, never a panic.
        #[test]
        fn arbitrary_bytes(data in proptest::collection::vec(any::<u8>(), 0..2_000)) {
            let _ = utmp::parse(&data);
        }

        /// A real file, damaged anywhere and cut anywhere.
        #[test]
        fn damaged_files(flips in proptest::collection::vec((0usize..5_376, any::<u8>()), 1..10), cut in 0usize..5_376) {
            let mut data = super::fixture("utmp");
            for (at, byte) in flips {
                data[at] = byte;
            }
            data.truncate(cut);
            if let Ok(records) = utmp::parse(&data) {
                prop_assert!(records.records.len() * records.layout.record_size() <= data.len());
            }
        }
    }
}

/// plaso's x86-64 records with their numbers in big-endian order, as
/// ppc64 or sparc64 would write them: the same records.
#[test]
fn big_endian_32_bit_times() {
    let little = fixture("utmp_x86_64");
    let mut big = little.clone();
    for record in big.chunks_exact_mut(384) {
        // ut_type (and its padding) and ut_pid; ut_exit's two shorts;
        // ut_session and ut_tv's two words. ut_addr_v6 is in network
        // order either way.
        for (at, width) in [
            (0, 2),
            (4, 4),
            (332, 2),
            (334, 2),
            (336, 4),
            (340, 4),
            (344, 4),
        ] {
            record[at..at + width].reverse();
        }
    }
    let little = utmp::parse(&little).unwrap();
    let big = utmp::parse(&big).unwrap();
    assert_eq!(big.layout, utmp::Layout::Time32BigEndian);
    assert_eq!(big.records, little.records);
}
