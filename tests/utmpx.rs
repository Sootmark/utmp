//! plaso's macOS `utmpx` (Apache-2.0, `tests/fixtures/plaso/utmpx_mac`):
//! every record plaso's `utmpx` parser reads (all but the signature
//! record), read the same: pid, terminal, terminal id, user and time, as
//! plaso's output gives them.

use utmp::{parse, Kind, Layout};

#[test]
fn every_record_as_plaso_reads_it() {
    let data = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/plaso/utmpx_mac"
    ))
    .unwrap();
    let records = parse(&data).unwrap();
    assert_eq!(records.layout, Layout::MacUtmpx);
    assert_eq!(records.problems, Vec::<String>::new());
    assert_eq!(records.records[0].kind, Kind::Signature);
    let mut got: Vec<(i32, String, u32, String, i64)> = records.records[1..]
        .iter()
        .map(|r| {
            (
                r.pid,
                r.line.clone(),
                r.id_number,
                r.user.clone(),
                r.seconds * 1_000_000 + r.microseconds,
            )
        })
        .collect();
    got.sort();
    // plaso: pid, terminal, terminal identifier, user name, timestamp.
    let mut expected = vec![
        (6802, String::new(), 825_241_715, String::new(), 116_231),
        (1, String::new(), 0, String::new(), 1_384_365_154_000_000),
        (
            67,
            "console".to_owned(),
            65_583,
            "moxilo".to_owned(),
            1_384_365_161_736_713,
        ),
        (
            6343,
            "ttys003".to_owned(),
            858_796_147,
            "moxilo".to_owned(),
            1_384_400_234_718_830,
        ),
        (
            6761,
            "ttys000".to_owned(),
            808_464_499,
            "moxilo".to_owned(),
            1_384_400_842_428_014,
        ),
        (
            6899,
            "ttys002".to_owned(),
            842_018_931,
            "moxilo".to_owned(),
            1_384_403_576_641_464,
        ),
    ];
    expected.sort();
    assert_eq!(got, expected);
    let kinds: Vec<Kind> = records.records.iter().map(|r| r.kind).collect();
    assert!(kinds.contains(&Kind::BootTime) && kinds.contains(&Kind::DeadProcess));
}
