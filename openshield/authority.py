"""Bounded SQLite authority for the owned synthetic quote experiment only."""

import hashlib
import json
import math
import os
import re
import secrets
import sqlite3
import stat
import time
from contextlib import contextmanager
from pathlib import Path


class AuthorityError(ValueError):
    def __init__(self):
        super().__init__("Synthetic authority unavailable")


class Authority:
    """Hash-only capabilities and atomic oracle spend; not a production identity service.

    shortcut: local SQLite and OS file access are trusted; use an accepted identity,
    protected durable storage and recovery policy before any production adoption.
    """

    def __init__(self, state_path, clock=time.time, quota=4, grant_ttl=30):
        if (type(quota) is not int or not 1 <= quota <= 100
                or type(grant_ttl) not in (int, float)
                or not math.isfinite(grant_ttl) or not 0 < grant_ttl <= 60
                or not callable(clock)):
            raise ValueError("Invalid synthetic authority configuration")
        value = os.fspath(state_path)
        if not isinstance(value, str) or not value or len(value) > 1024 or value.startswith(("\\\\", "//")):
            raise ValueError("Authority requires a local state file")
        self.path = Path(value).absolute()
        self.clock, self.quota, self.grant_ttl = clock, quota, grant_ttl
        self.config = json.dumps({"schema": 1, "scope": "synthetic-quote-alice-a-bob-b",
                                  "quota": quota, "grantTtl": float(grant_ttl)}, sort_keys=True)
        created = False
        try:
            descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(descriptor)
            created = True
        except FileExistsError:
            pass
        except OSError:
            raise AuthorityError() from None
        try:
            self.identity = self._file_identity(allow_empty=created)
            with self._transaction(initializing=created) as db:
                if created:
                    for statement in (
                        "CREATE TABLE meta(config TEXT NOT NULL, clock REAL NOT NULL)",
                        "CREATE TABLE principals(subject TEXT PRIMARY KEY, used INTEGER NOT NULL CHECK(used>=0))",
                        "CREATE TABLE sessions(digest TEXT PRIMARY KEY, subject TEXT NOT NULL REFERENCES principals(subject), revoked INTEGER NOT NULL CHECK(revoked IN(0,1)))",
                        "CREATE TABLE grants(digest TEXT PRIMARY KEY, session TEXT NOT NULL REFERENCES sessions(digest), operation TEXT NOT NULL, object TEXT NOT NULL, quantity INTEGER NOT NULL, expires REAL NOT NULL)",
                        "CREATE TABLE counters(name TEXT PRIMARY KEY, value INTEGER NOT NULL CHECK(value>=0))",
                    ):
                        db.execute(statement)
                    db.execute("INSERT INTO meta VALUES(?,?)", (self.config, self._now()))
                    db.executemany("INSERT INTO principals VALUES(?,0)", [("alice",), ("bob",)])
                    db.executemany("INSERT INTO counters VALUES(?,0)", [("denied",), ("accepted",), ("quotaDenied",)])
                elif db.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                    raise AuthorityError()
                self._time(db)
        except (OSError, sqlite3.Error, AuthorityError):
            raise AuthorityError() from None

    def _file_identity(self, allow_empty=False):
        info = self.path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or not allow_empty and info.st_size == 0 or info.st_size > 1048576):
            raise AuthorityError()
        return info.st_dev, info.st_ino

    @contextmanager
    def _transaction(self, initializing=False):
        db = None
        try:
            if self._file_identity(allow_empty=initializing) != self.identity:
                raise AuthorityError()
            db = sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True, timeout=2, isolation_level=None)
            db.execute("PRAGMA trusted_schema=OFF")
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("PRAGMA max_page_count=256")
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except (OSError, sqlite3.Error):
            raise AuthorityError() from None
        finally:
            if db is not None:
                db.close()

    def _now(self):
        try:
            now = self.clock()
        except Exception:
            raise AuthorityError() from None
        if type(now) not in (int, float) or not math.isfinite(now) or not 0 <= now <= 1e12:
            raise AuthorityError()
        return float(now)

    def _time(self, db):
        rows = db.execute("SELECT config,clock FROM meta").fetchall()
        now = self._now()
        if (len(rows) != 1 or rows[0][0] != self.config
                or type(rows[0][1]) not in (int, float) or not math.isfinite(rows[0][1])
                or now < rows[0][1]
                or db.execute("SELECT subject FROM principals ORDER BY subject").fetchall() != [("alice",), ("bob",)]):
            raise AuthorityError()
        db.execute("UPDATE meta SET clock=?", (now,))
        return now

    @staticmethod
    def _digest(token):
        if not isinstance(token, str) or re.fullmatch(r"[A-Za-z0-9_-]{43}", token) is None:
            return None
        return hashlib.sha256(token.encode("ascii")).hexdigest()

    def issue_session(self, subject="alice"):
        if not isinstance(subject, str) or subject not in {"alice", "bob"}:
            raise ValueError("Unknown synthetic identity")
        token = secrets.token_urlsafe(32)
        with self._transaction() as db:
            self._time(db)
            if db.execute("SELECT count(*) FROM sessions").fetchone()[0] >= 64:
                raise ValueError("Lab session bound reached")
            db.execute("INSERT INTO sessions VALUES(?,?,0)", (self._digest(token), subject))
        return token

    def revoke_session(self, token):
        with self._transaction() as db:
            self._time(db)
            result = db.execute("UPDATE sessions SET revoked=1 WHERE digest=? AND revoked=0", (self._digest(token),))
            return result.rowcount == 1

    @property
    def audit(self):
        with self._transaction() as db:
            self._time(db)
            rows = db.execute("SELECT name,value FROM counters").fetchall()
            if {name for name, _ in rows} != {"denied", "accepted", "quotaDenied"}:
                raise AuthorityError()
            return dict(rows)

    @staticmethod
    def _deny(db, quota=False):
        name = "quotaDenied" if quota else "denied"
        if db.execute("UPDATE counters SET value=value+1 WHERE name=?", (name,)).rowcount != 1:
            raise AuthorityError()
        return (429, {"error": "query_budget_exhausted"}) if quota else (403, {"error": "denied"})

    def operate(self, path, session, capability, obj, quantity):
        """Authorize one fixed operation; callers cannot select SQL or new authority."""
        if (not isinstance(path, str) or path not in {"/api/grants", "/api/quote"}
                or not isinstance(obj, str) or obj not in {"quote-a", "quote-b"}
                or type(quantity) is not int or not 1 <= quantity <= 100):
            return 400, {"error": "invalid_request"}
        with self._transaction() as db:
            now = self._time(db)
            session_hash = self._digest(session)
            record = db.execute("SELECT subject FROM sessions WHERE digest=? AND revoked=0", (session_hash,)).fetchone()
            if not record or {"quote-a": "alice", "quote-b": "bob"}[obj] != record[0]:
                return self._deny(db)
            subject = record[0]
            used = db.execute("SELECT used FROM principals WHERE subject=?", (subject,)).fetchone()[0]
            if type(used) is not int or not 0 <= used <= self.quota:
                raise AuthorityError()
            if used >= self.quota:
                return self._deny(db, quota=True)
            if path == "/api/grants":
                db.execute("DELETE FROM grants WHERE expires<=?", (now,))
                if db.execute("SELECT count(*) FROM grants").fetchone()[0] >= 64:
                    return 429, {"error": "grant_budget_exhausted"}
                token = secrets.token_urlsafe(32)
                db.execute("INSERT INTO grants VALUES(?,?,?,?,?,?)", (self._digest(token), session_hash, "quote", obj, quantity, now + self.grant_ttl))
                return 201, {"capability": token}
            digest = self._digest(capability)
            expected = db.execute("SELECT session,operation,object,quantity,expires FROM grants WHERE digest=?", (digest,)).fetchone()
            if (not expected or expected[:4] != (session_hash, "quote", obj, quantity)
                    or type(expected[4]) not in (int, float) or not math.isfinite(expected[4]) or expected[4] <= now):
                return self._deny(db)
            db.execute("DELETE FROM grants WHERE digest=?", (digest,))
            db.execute("UPDATE principals SET used=used+1 WHERE subject=?", (subject,))
            if db.execute("UPDATE counters SET value=value+1 WHERE name='accepted'").rowcount != 1:
                raise AuthorityError()
            # Only this synthetic pure calculation follows spend; external effects need reconciliation.
            return 200, {"totalCents": quantity * 137 + 29}
