"""Actual SQLite restore effects and counterexamples to metadata/hash-only readiness."""

import json
from pathlib import Path
import tempfile
import unittest

from lab.recovery_readiness import _connect, _digest, _exercise, _observe, _restore, _seed, _snapshot, verify


class RecoveryReadinessTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.source, self.snapshot, self.scratch = self.root / "source.db", self.root / "pinned.db", self.root / "scratch"
        self.scratch.mkdir()
        _seed(self.source)

    def tearDown(self):
        self.directory.cleanup()

    def test_all_seven_cases_and_false_readiness_controls_run_without_private_paths(self):
        report = verify()
        self.assertEqual(report["status"], "passed")
        self.assertEqual(len(report["checks"]), 28)
        self.assertTrue(all(item["passed"] for item in report["checks"]))
        self.assertEqual(len(report["cases"]), 7)
        cases = {case["caseId"]: case for case in report["cases"]}
        self.assertEqual(cases["clean"]["independentApplicationObservation"]["ledgerRows"], 1)
        self.assertTrue(cases["clean"]["independentApplicationObservation"]["rollbackVerified"])
        self.assertTrue(cases["clean"]["independentApplicationObservation"]["committedTransferObserved"])
        self.assertEqual(sum(case["metadataOnlyReady"] and case["caseId"] != "clean" for case in cases.values()), 5)
        self.assertEqual(sum(case["copyHashOnlyReady"] and case["caseId"] != "clean" for case in cases.values()), 4)
        self.assertTrue(all(case["sourceUnchanged"] and case["snapshotUnchanged"] and case["isolatedDestination"]
                            for case in cases.values()))
        self.assertEqual(report["modelCalls"], 0)
        self.assertFalse(report["productionActions"])
        serialized = json.dumps(report)
        for private in (str(self.root), "planted-contamination", "changed-after-pin", "clean-fixture-v1"):
            self.assertNotIn(private, serialized)

    def test_real_restore_is_fresh_and_source_snapshot_are_unchanged_after_durable_app_write(self):
        pin = _snapshot(self.source, self.snapshot, "clean")
        original_source = _digest(self.source)
        receipt, target = _restore(self.snapshot, pin, self.scratch)
        self.assertEqual(receipt["status"], "copied")
        self.assertEqual(target.parent.parent, self.scratch)
        self.assertNotIn(target, (self.source, self.snapshot))
        observed = _exercise(target)
        self.assertEqual(observed["status"], "usable")
        with _connect(target, readonly=True) as database:
            self.assertEqual(database.execute("SELECT id,balance FROM accounts ORDER BY id").fetchall(), [(1, 599), (2, 401)])
            self.assertEqual(database.execute("SELECT debit,credit,units FROM ledger").fetchall(), [(1, 2, 1)])
        self.assertEqual(_digest(self.snapshot), pin)
        self.assertEqual(_digest(self.source), original_source)
        second_receipt, second = _restore(self.snapshot, pin, self.scratch)
        self.assertEqual(second_receipt["status"], "copied")
        self.assertNotEqual(target, second)
        self.assertEqual(_observe(second)["ledgerRows"], 0)

    def test_equal_total_and_sqlite_integrity_do_not_establish_business_consistency(self):
        pin = _snapshot(self.source, self.snapshot, "business_inconsistent")
        receipt, target = _restore(self.snapshot, pin, self.scratch)
        self.assertEqual(receipt["status"], "copied")
        self.assertEqual(_digest(target), pin)
        with _connect(target, readonly=True) as database:
            self.assertEqual(database.execute("PRAGMA integrity_check").fetchone(), ("ok",))
            self.assertEqual(database.execute("SELECT sum(balance) FROM accounts").fetchone(), (1000,))
        self.assertEqual(_exercise(target)["code"], "BUSINESS_INVARIANT_FAILED")
        self.assertEqual(_digest(target), pin)

    def test_missing_or_changed_snapshot_never_allocates_a_restore_destination(self):
        receipt, target = _restore(None, None, self.scratch)
        self.assertEqual(receipt["code"], "BACKUP_UNAVAILABLE")
        self.assertIsNone(target)
        self.assertEqual(list(self.scratch.iterdir()), [])
        pin = _snapshot(self.source, self.snapshot, "digest_changed")
        receipt, target = _restore(self.snapshot, pin, self.scratch)
        self.assertEqual(receipt["code"], "SNAPSHOT_DIGEST_MISMATCH")
        self.assertIsNone(target)
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_sqlite_backup_includes_a_committed_wal_transaction(self):
        with _connect(self.source) as writer:
            writer.execute("PRAGMA journal_mode=WAL")
            writer.execute("UPDATE accounts SET balance=balance-1 WHERE id=1")
            writer.execute("UPDATE accounts SET balance=balance+1 WHERE id=2")
            writer.execute("INSERT INTO ledger(debit,credit,units) VALUES(1,2,1)")
            writer.commit()
            pin = _snapshot(self.source, self.snapshot, "clean")
            receipt, target = _restore(self.snapshot, pin, self.scratch)
            self.assertEqual(receipt["status"], "copied")
            self.assertEqual(_observe(target)["ledgerRows"], 1)
            with _connect(target, readonly=True) as reader:
                self.assertEqual(reader.execute("SELECT balance FROM accounts WHERE id=1").fetchone(), (599,))


if __name__ == "__main__":
    unittest.main()
