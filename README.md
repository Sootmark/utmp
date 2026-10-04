# utmp

Linux login records: `utmp` (who is logged in), `wtmp` (every login, logout and boot) and `btmp` (failed logins), glibc's `struct utmp`; and `lastlog` (each account's last login), glibc's `struct lastlog`. One dependency, its sibling `sootmark-common` (times).

```toml
[dependencies]
sootmark-utmp = "0.2"
```

```rust
let records = utmp::parse(&std::fs::read("/var/log/wtmp")?)?;
for r in &records.records {
    println!("{} {} {} {} {:?}", r.time(), r.kind.name(), r.user, r.line, r.address);
}

let lastlog = utmp::parse_lastlog(&std::fs::read("/var/log/lastlog")?);
for login in &lastlog.entries {
    println!("{} {} {} {}", login.uid, login.time, login.line, login.host);
}
```

## What you get

- `parse(bytes)`: every record, in file order, with the layout it was read with. The record has two sizes and two byte orders: 384 bytes where glibc keeps 32-bit times (x86-64, ppc64, riscv64, mips, sparc64, 32-bit systems), 400 bytes elsewhere (aarch64, loongarch64, s390x), little- or big-endian. The layout is told from the records themselves: the one under which they read as login records (known types, plausible times) is used.
- `Record`: kind (`USER_PROCESS` a login, `DEAD_PROCESS` a logout, `BOOT_TIME`, `RUN_LVL`, `OLD_TIME`/`NEW_TIME` a clock change, …), pid, terminal (`line`) and its short `id`, user, remote host, exit status, session, the time (UTC, to the microsecond) and the remote address (IPv4 or IPv6).
- Damage is reported, never a panic: a record of an unknown type is listed in `problems` and skipped, the records after it still read; bytes after the last whole record are reported.
- `parse_lastlog(bytes)`: the last login of every account that has logged in (UID, time to the second, terminal, remote host), from the sparse file indexed by UID; accounts that never logged in (all-zero records) are skipped without allocating for them. The record follows `struct utmp`'s layouts: 292 bytes (a 32-bit time, unsigned in current glibc) where `utmp` is 384, 296 bytes (a 64-bit time, either byte order) where it is 400, told the same way (plausible times, text fields that end). A login at an implausible time is kept and reported in `problems`, as is a truncated end.

Not yet: `wtmpdb` (the SQLite database newer distributions write instead of `wtmp`).

## How it's checked

- plaso's utmp test files (Apache-2.0, `tests/fixtures/plaso/`): the 26 records of the x86-64 ones match util-linux's `utmpdump` on every field (its output in `tests/oracle/`), including a file with two damaged records and a truncated end; the aarch64 and s390x files (400-byte records, little- and big-endian) as plaso's own tests expect them.
- `lastlog`: no openly licensed sample exists (plaso has none), so the files are built in the tests, record by record, in each of the three layouts, per glibc's `bits/utmp.h`.
- Property tests: arbitrary bytes and real files damaged and cut anywhere read or are refused, never a panic; the same for `lastlog`.

## Licence

MIT or Apache-2.0, at your option. The test files are plaso's, under the Apache licence 2.0.
