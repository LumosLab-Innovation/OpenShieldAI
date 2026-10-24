# D2/D3 application recovery-readiness experiment

Status: **S1 fixed synthetic SQLite application experiment**, run locally on 2026-10-24. This supplements the earlier [isolated restic/application drill](RESULTS.md), rather than replacing a backup product or extending production restore authority. The public entry point [recovery_readiness.py](../../lab/recovery_readiness.py) accepts no target paths or incident inputs and creates only its own temporary files.

## Mechanism and actual observations

The fixture preserves the existing account total of 1,000 and `clean-fixture-v1` trust marker. It adds a transfer ledger: each account's current balance must equal its known opening balance plus credits minus debits. A sum of 1,000 alone is insufficient. SQLite `Connection.backup` captures each snapshot, which is pinned by its exact digest before restore. Restore copies only into a newly allocated scratch directory. The source and pinned snapshot are hashed again after every attempt and remain unchanged.

A separate SQLite connection independently opens the restored file and checks required tables, SQLite integrity, foreign keys, exact account membership, the ledger equation and the trusted marker. On the clean restoration, a genuine debit/credit/ledger transaction is written then rolled back, and a new connection confirms no change. A subsequent legitimate transfer commits; a fresh connection observes its durable ledger row and the 599/401 balances. The copy receipt does not set the application's usability verdict.

| Owned scenario | Metadata says backup available | Exact copy/hash accepted | Actual application observation |
|---|---|---|---|
| Clean pinned snapshot | Yes | Yes | Usable; rollback preserved state and a committed transfer was independently observed |
| No backup | No | No | `BACKUP_UNAVAILABLE`; no restore target allocated |
| Snapshot changed after pin | Yes | No | `SNAPSHOT_DIGEST_MISMATCH`; no restore target allocated |
| Balanced but ledger-inconsistent data | Yes | Yes | `BUSINESS_INVARIANT_FAILED`; SQLite integrity and total balance still pass |
| Foreign-key violation | Yes | Yes | `FOREIGN_KEY_FAILED` |
| Planted untrusted build marker | Yes | Yes | `UNTRUSTED_BUILD_MARKER` |
| Missing required ledger object | Yes | Yes | `MISSING_REQUIRED_OBJECT` |

The availability-only comparator incorrectly calls five unusable/digest-drift cases ready. Exact copied bytes and hash comparison still incorrectly accept four unusable applications. These are selected counterexamples, not prevalence or production accuracy estimates. The full application checks reject those cases while preserving useful clean recovery.

## Reproduction and measured boundary

```text
python -m lab.recovery_readiness
python -m unittest discover -s tests -p test_recovery_readiness.py -v
```

The lab passed **28 named assertions across seven cases**. Its **five tests** additionally inspect the actual restored account and ledger values, prove a second restore receives a fresh target, establish that hash-valid/SQLite-valid/total-balanced data can remain unusable, and verify the SQLite backup includes a committed WAL transaction while the source connection remains open. These checks are not independent incident samples. No model is called and no production action occurs.

## Limits and challenge

This is a local database application probe, not a running HTTP-service recovery, encrypted backup test, key-management test, production RPO/RTO measurement, reconnection procedure or crash/interrupted-restore test. Missing/wrong-key evidence belongs to the separately documented prior restic drill and is not claimed by this increment. No dependency is installed.

Known application equations and a planted marker detect these selected corruptions; they do not prove absence of malware, persistence or every semantic defect. A digest establishes agreement with this trusted capture, not authenticity or a clean historical recovery point. The observer uses separate connections in the same trusted process, without an isolated identity or off-host custody. An untrusted administrator can still alter the fixture and its purported expectations. Restore cannot reverse earlier disclosure, and these deterministic effects establish no incremental AI benefit.
