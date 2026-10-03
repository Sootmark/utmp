# utmp

Linux login records: `utmp` (who is logged in), `wtmp` (every login, logout and boot) and `btmp` (failed logins), glibc's `struct utmp`. One dependency, its sibling `sootmark-common` (times).

```toml
[dependencies]
sootmark-utmp = "0.1"
```

```rust
let records = utmp::parse(&std::fs::read("/var/log/wtmp")?)?;
for r in &records.records {
    println!("{} {} {} {} {:?}", r.time(), r.kind.name(), r.user, r.line, r.address);
}
```

## What you get

- `parse(bytes)`: every record, in file order, with the layout it was read with. The record has two sizes and two byte orders: 384 bytes where 64-bit glibc keeps 32-bit times for compatibility (x86-64, 32-bit systems), 400 bytes elsewhere (aarch64, s390x, ppc64…), little- or big-endian. The layout is told from the records themselves: the one under which they read as login records (known types, plausible times) is used.
- `Record`: kind (`USER_PROCESS` a login, `DEAD_PROCESS` a logout, `BOOT_TIME`, `RUN_LVL`, `OLD_TIME`/`NEW_TIME` a clock change, …), pid, terminal (`line`) and its short `id`, user, remote host, exit status, session, the time (UTC, to the microsecond) and the remote address (IPv4 or IPv6).
- Damage is reported, never a panic: a record of an unknown type is listed in `problems` and skipped, the records after it still read; bytes after the last whole record are reported.

Not yet: `lastlog`, and `wtmpdb` (the SQLite database newer distributions write instead of `wtmp`).

## How it's checked

- plaso's utmp test files (Apache-2.0, `tests/fixtures/plaso/`): the 26 records of the x86-64 ones match util-linux's `utmpdump` on every field (its output in `tests/oracle/`), including a file with two damaged records and a truncated end; the aarch64 and s390x files (400-byte records, little- and big-endian) as plaso's own tests expect them.
- Property tests: arbitrary bytes and real files damaged and cut anywhere read or are refused, never a panic.

## Licence

MIT or Apache-2.0, at your option. The test files are plaso's, under the Apache licence 2.0.
