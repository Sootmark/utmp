#!/bin/sh
# Recreates wtmp.db, wal/wtmp.db (+ -wal) and lastlog2.db: synthetic
# sessions in the tables wtmpdb 0.73 and util-linux 2.41's liblastlog2
# create (their CREATE TABLE statements, verbatim), written by the sqlite3
# shell. Addresses are documentation ranges (RFC 5737); no real data.
#
#   sudo apt-get install sqlite3 wtmpdb
#   sh tests/fixtures/sqlite/gen.sh
#
# wtmp.last is `wtmpdb last -F` reading wtmp.db (in UTC), for the tests.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

wtmp_table="CREATE TABLE IF NOT EXISTS wtmp(ID INTEGER PRIMARY KEY, Type INTEGER, User TEXT NOT NULL, Login INTEGER, Logout INTEGER, TTY TEXT, RemoteHost TEXT, Service TEXT) STRICT;"
# Microseconds: 2026-09-01 08:00:00 UTC is 1788249600.
sessions="
INSERT INTO wtmp (Type,User,Login,Logout,TTY,RemoteHost,Service) VALUES
 (1,'reboot',1788249600000000,NULL,'~','6.12.48+deb13-amd64',NULL),
 (3,'alice',1788249700123456,1788253300000000,'pts/0','192.0.2.15','sshd'),
 (3,'root',1788250000000000,NULL,'tty1',NULL,'login'),
 (3,'deploy',1788251000000000,1788251060000000,'pts/1','2001:db8::7','sshd');"

sqlite3 wtmp.db "$wtmp_table $sessions"
TZ=UTC wtmpdb last -F -f wtmp.db > wtmp.last

# The same, plus a session committed to the log and not yet checkpointed:
# both files copied while the connection holds them.
mkdir wal
sqlite3 wal-src.db "PRAGMA journal_mode=WAL; $wtmp_table $sessions" >/dev/null
sqlite3 wal-src.db <<'SQL'
PRAGMA wal_autocheckpoint=0;
PRAGMA wal_checkpoint(TRUNCATE);
INSERT INTO wtmp (Type,User,Login,Logout,TTY,RemoteHost,Service) VALUES (3,'mallory',1788260000000000,NULL,'pts/2','203.0.113.66','sshd');
.shell cp wal-src.db wal/wtmp.db && cp wal-src.db-wal wal/wtmp.db-wal
SQL

sqlite3 lastlog2.db "CREATE TABLE IF NOT EXISTS Lastlog2(Name TEXT PRIMARY KEY, Time INTEGER, TTY TEXT, RemoteHost TEXT, Service TEXT);
INSERT INTO Lastlog2 VALUES ('root',1788250000,'tty1',NULL,'login'),('alice',1788249700,'pts/0','192.0.2.15','sshd');"

cp wtmp.db wtmp.last lastlog2.db "$here/"
mkdir -p "$here/wal"
cp wal/wtmp.db wal/wtmp.db-wal "$here/wal/"
