"""Owned SQLite restore-readiness experiment; no external paths or production writes."""

import hashlib
import json
from contextlib import contextmanager
from pathlib import Path
import shutil
import sqlite3
import tempfile
import time


MAX_BYTES = 131072
CASES = ("clean", "no_backup", "digest_changed", "business_inconsistent",
         "foreign_key_violation", "untrusted_build", "missing_required_object")


def _digest(path):
    with path.open("rb") as source:
        body = source.read(MAX_BYTES + 1)
    if len(body) > MAX_BYTES:
        raise ValueError("SNAPSHOT_LIMIT")
    return hashlib.sha256(body).hexdigest()


@contextmanager
def _connect(path, readonly=False):
    connection = sqlite3.connect(path.as_uri() + "?mode=ro" if readonly else path,
                                 uri=readonly, timeout=1)
    try:
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("PRAGMA max_page_count=32")
        connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_BYTES)
        with connection:
            yield connection
    finally:
        connection.close()


def _seed(path):
    with _connect(path) as database:
        database.executescript("""
            CREATE TABLE accounts(id INTEGER PRIMARY KEY, balance INTEGER NOT NULL CHECK(balance>=0));
            INSERT INTO accounts VALUES(1,600),(2,400);
            CREATE TABLE ledger(id INTEGER PRIMARY KEY, debit INTEGER NOT NULL REFERENCES accounts(id),
                credit INTEGER NOT NULL REFERENCES accounts(id), units INTEGER NOT NULL CHECK(units>0));
            CREATE TABLE trust(name TEXT PRIMARY KEY, value TEXT NOT NULL);
            INSERT INTO trust VALUES('build','clean-fixture-v1');
        """)


def _observe(path):
    """Separate read connection observes the actual restored application's invariants."""
    try:
        with _connect(path, readonly=True) as database:
            tables = {row[0] for row in database.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if not {"accounts", "ledger", "trust"} <= tables:
                return {"status": "failed", "code": "MISSING_REQUIRED_OBJECT"}
            if database.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                return {"status": "failed", "code": "SQLITE_INTEGRITY_FAILED"}
            if database.execute("PRAGMA foreign_key_check").fetchone() is not None:
                return {"status": "failed", "code": "FOREIGN_KEY_FAILED"}
            accounts = dict(database.execute("SELECT id,balance FROM accounts LIMIT 3"))
            rows = database.execute("SELECT debit,credit,units FROM ledger LIMIT 33").fetchall()
            if set(accounts) != {1, 2} or len(rows) > 32:
                return {"status": "failed", "code": "BUSINESS_INVARIANT_FAILED"}
            expected = {1: 600, 2: 400}
            for debit, credit, units in rows:
                if debit not in expected or credit not in expected or type(units) is not int or units <= 0:
                    return {"status": "failed", "code": "BUSINESS_INVARIANT_FAILED"}
                expected[debit] -= units
                expected[credit] += units
            if accounts != expected or any(value < 0 for value in accounts.values()) or sum(accounts.values()) != 1000:
                return {"status": "failed", "code": "BUSINESS_INVARIANT_FAILED"}
            if dict(database.execute("SELECT name,value FROM trust LIMIT 3")) != {"build": "clean-fixture-v1"}:
                return {"status": "failed", "code": "UNTRUSTED_BUILD_MARKER"}
            return {"status": "usable", "code": "APPLICATION_INVARIANTS_PASSED",
                    "accounts": len(accounts), "ledgerRows": len(rows), "totalBalance": sum(accounts.values())}
    except (sqlite3.DatabaseError, OSError, ValueError, TypeError):
        return {"status": "failed", "code": "APPLICATION_READ_FAILED"}


def _transfer(database):
    if database.execute("UPDATE accounts SET balance=balance-1 WHERE id=1 AND balance>0").rowcount != 1:
        raise ValueError("APPLICATION_WRITE_FAILED")
    if database.execute("UPDATE accounts SET balance=balance+1 WHERE id=2").rowcount != 1:
        raise ValueError("APPLICATION_WRITE_FAILED")
    database.execute("INSERT INTO ledger(debit,credit,units) VALUES(1,2,1)")


def _exercise(path):
    before = _observe(path)
    if before["status"] != "usable":
        return before
    try:
        with _connect(path) as database:
            database.execute("BEGIN IMMEDIATE")
            _transfer(database)
            database.rollback()
        rolled_back = _observe(path)
        if rolled_back != before:
            return {"status": "failed", "code": "ROLLBACK_PROBE_FAILED"}
        with _connect(path) as database:
            _transfer(database)
        after = _observe(path)
        if after["status"] != "usable" or after["ledgerRows"] != before["ledgerRows"] + 1:
            return {"status": "failed", "code": "COMMITTED_TRANSACTION_NOT_OBSERVED"}
        return {**after, "rollbackVerified": True, "committedTransferObserved": True}
    except (sqlite3.DatabaseError, OSError, ValueError):
        return {"status": "failed", "code": "APPLICATION_WRITE_FAILED"}


def _snapshot(source, destination, variant):
    with _connect(source, readonly=True) as original, _connect(destination) as snapshot:
        original.backup(snapshot)
    # Each corruption is planted before pinning, except the explicit digest-drift case.
    with _connect(destination) as database:
        if variant == "business_inconsistent":
            database.execute("UPDATE accounts SET balance=CASE id WHEN 1 THEN 599 ELSE 401 END")
        elif variant == "untrusted_build":
            database.execute("UPDATE trust SET value='planted-contamination' WHERE name='build'")
        elif variant == "missing_required_object":
            database.execute("DROP TABLE ledger")
        elif variant == "foreign_key_violation":
            database.execute("PRAGMA foreign_keys=OFF")
            database.execute("INSERT INTO ledger(debit,credit,units) VALUES(999,2,1)")
    pin = _digest(destination)
    if variant == "digest_changed":
        with _connect(destination) as database:
            database.execute("UPDATE trust SET value='changed-after-pin' WHERE name='build'")
    return pin


def _restore(snapshot, pin, scratch_root):
    """Only called with an owned fresh scratch root from verify; no target-path API."""
    if snapshot is None:
        return {"status": "failed", "code": "BACKUP_UNAVAILABLE"}, None
    if _digest(snapshot) != pin:
        return {"status": "failed", "code": "SNAPSHOT_DIGEST_MISMATCH"}, None
    destination = Path(tempfile.mkdtemp(prefix="restore-", dir=scratch_root)) / "application.sqlite3"
    shutil.copyfile(snapshot, destination)
    if _digest(destination) != pin:
        return {"status": "failed", "code": "RESTORE_COPY_MISMATCH"}, destination
    return {"status": "copied", "code": "RESTORE_BYTES_COPIED"}, destination


def verify():
    """Run fixed owned fixtures, exporting counts and codes without database contents."""
    started = time.monotonic()
    checks, cases = [], []

    def check(code, condition):
        checks.append({"code": code, "passed": bool(condition)})

    expected = {"clean": "APPLICATION_INVARIANTS_PASSED", "no_backup": "BACKUP_UNAVAILABLE",
                "digest_changed": "SNAPSHOT_DIGEST_MISMATCH", "business_inconsistent": "BUSINESS_INVARIANT_FAILED",
                "foreign_key_violation": "FOREIGN_KEY_FAILED", "untrusted_build": "UNTRUSTED_BUILD_MARKER",
                "missing_required_object": "MISSING_REQUIRED_OBJECT"}
    with tempfile.TemporaryDirectory(prefix="openshield-recovery-") as directory:
        workspace = Path(directory)
        source, scratch_root = workspace / "source.sqlite3", workspace / "scratch"
        scratch_root.mkdir()
        _seed(source)
        original_digest = _digest(source)
        for variant in CASES:
            snapshot = None if variant == "no_backup" else workspace / (variant + ".sqlite3")
            pin = None if snapshot is None else _snapshot(source, snapshot, variant)
            before = None if snapshot is None else _digest(snapshot)
            metadata_ready = snapshot is not None
            receipt, restored = _restore(snapshot, pin, scratch_root)
            hash_ready = receipt["status"] == "copied"
            observation = _exercise(restored) if hash_ready else {"status": "not_checked", "code": receipt["code"]}
            code = observation["code"] if hash_ready else receipt["code"]
            check(variant.upper() + "_EXPECTED_OUTCOME", code == expected[variant])
            snapshot_unchanged = snapshot is None or _digest(snapshot) == before
            check(variant.upper() + "_PINNED_INPUT_UNCHANGED", snapshot_unchanged)
            check(variant.upper() + "_SOURCE_UNCHANGED", _digest(source) == original_digest)
            if hash_ready and variant != "clean":
                check(variant.upper() + "_HASH_ONLY_FALSE_READINESS", observation["status"] == "failed")
            cases.append({"caseId": variant, "metadataOnlyReady": metadata_ready, "copyHashOnlyReady": hash_ready,
                          "restoreReceipt": receipt, "independentApplicationObservation": observation,
                          "snapshotUnchanged": snapshot_unchanged, "sourceUnchanged": _digest(source) == original_digest,
                          "isolatedDestination": restored is None or restored.parent.parent == scratch_root,
                          "outcomeCode": code})
        check("CLEAN_RESTORED_APPLICATION_COMMIT_AND_ROLLBACK", cases[0]["independentApplicationObservation"].get("committedTransferObserved")
              and cases[0]["independentApplicationObservation"].get("rollbackVerified"))
        check("SOURCE_APPLICATION_REMAINS_USABLE", _observe(source)["status"] == "usable")
        check("EVERY_DESTINATION_FRESH_AND_ISOLATED", all(case["isolatedDestination"] for case in cases))
    return {"schemaVersion": "recovery_readiness_lab_v1", "status": "passed" if all(item["passed"] for item in checks) else "failed",
            "dataClass": "synthetic", "checks": checks, "cases": cases, "modelCalls": 0, "productionActions": False,
            "elapsedSeconds": round(time.monotonic() - started, 6),
            "limitations": ["Owned fixed SQLite application only; no production destination or restored code is executed",
                            "Local snapshot digest pins bytes relative to this trusted capture; it does not authenticate their source",
                            "Known ledger and build-marker checks do not prove malware eradication or universal application consistency",
                            "No encrypted backup, key availability, interrupted restore, production RPO/RTO or HTTP service was tested",
                            "Restore and observer use separate connections in one trusted process; no isolated observer identity",
                            "Recovery cannot reverse prior disclosure; real AI benefit is not measured"]}


if __name__ == "__main__":
    report = verify()
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report["status"] == "passed" else 1)
