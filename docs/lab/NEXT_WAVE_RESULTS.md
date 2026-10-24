# Next-wave effects and real Codex comparison

Observed **2026-10-24**. Stage: **S1 owned engineering experiments**, with actual Go/HTTP and SQLite effects. [Implementation and complete coverage ledger](../NEXT_WAVE.md), [independent challenge](../research/NEXT_WAVE_CHALLENGE.md), [final machine-readable record](evidence/next-wave.json), [frozen corpus](evidence/next-wave-corpus.json), [operator proxy setup](../CLIPROXY_SETUP.md).

## Independently observed effects

The combined controller runs **103 named effect assertions**: 48 flow, 27 promotion and 28 restore-readiness checks. These are assertions over known fixtures, not 103 independent attacks or an estimated prevention rate. No model is on the fixture's enforcement path, and no model can grant, approve or execute an operation.

| Family | Unsafe/insufficient comparison | Protected or independently checked result |
|---|---|---|
| I1/I2 identity | Synthetic accepted proof after a failure burst creates a session; a warmed unsafe verifier still reads after revocation; a paused request can commit after revoke | Principal throttle stops the next authenticator call, with an explicitly observed legitimate lockout cost. Both declared protected verifiers reject revoked sessions; final pre-effect recheck prevents the paused mutation. Unrelated identity and post-window login work |
| W3 object/transaction | A caller reads another object's actual synthetic value; one idempotency key produces two charge rows | No cross-object bytes/read effect; sixteen concurrent distinct grants for the same transaction produce one independently observed commit; changed payload conflicts, new valid transactions work |
| W4/D4 outbound path | Two actual synthetic payloads reach a separate forbidden HTTP receiver | Zero requests to that receiver through the declared protected path; an approved receipt reaches its allowed receiver; redirect refusal prevents forwarding to the forbidden receiver |
| W2/C2/C3 promotion/cache | Four private-canary representations are delivered. After clean origin promotion, the edge still delivers four cached leaks | Exact approved immutable snapshot is installed; separately approved retirement purges eight cached representations. Edge/origin then show zero private deliveries, six required GET successes and both map encodings denied. Historical downloaded bytes remain disclosed |
| D2/D3 usable recovery | Metadata declares five unusable cases ready; copy/hash alone still accepts four application failures | Fresh isolated scratch restores are reopened independently. Foreign keys, required objects, per-account ledger equations, trust marker, rollback and committed transactions are checked. Clean restored application works; source/snapshot remain unchanged |

Detailed mechanics and limits: [flow](FLOW_LAB_RESULTS.md), [promotion](PROMOTION_RESULTS.md), [restore readiness](RECOVERY_READINESS_RESULTS.md). V1 covers fixed principal/concurrency/body bounds only; it supplies no Internet DDoS or sustained workload claim. The Go and promotion controllers are ephemeral, while the earlier SQLite quote authority has its separate local durability scope.

## Equal-input AI experiment

CLIProxyAPI **8.0.41** was installed separately from the repository with the captured release SHA-256 verified. The operator completed fresh Codex device OAuth. The actual listener was `127.0.0.1:8317`; unauthenticated model access returned 401, authenticated access 200 and disabled management access 404. [Safe setup evidence](evidence/cliproxy-local-setup.json) contains no credential/account material. The selected route alias was `gpt-6.1-sol`; upstream identity is reported by the proxy, not independently attested.

The 16-case corpus contains four observed unsafe effects, four benign workloads and eight unknown cases. Two different holder narratives deliberately have identical observable auth facts and unknown truth. Case/event IDs and evaluation order are deterministically shuffled. Scenario names, expected decisions, truth, provenance and control-arm labels stay outside prompts. Recovery inputs do not invent a key-availability result or independent observation where none occurred.

The corpus was captured before inference. Both arms receive the same accepted facts, frozen source roles, catalog and **zero mutation capabilities**. Each case has the existing call/read/time bounds; the selected run-wide visible-token reservation ceiling is 192,000. Successful baseline fallback is never credited as successful AI. A required hypothesis match means **presence of a registered code**, not hypothesis precision or independent semantic verification.

This is a **public engineering regression**, not an unseen/representative held-out efficacy sample. Many facts already resolve the fixture effect before inference; the baseline is frozen v1. Even better code-presence or proposal scores would require comparison with a stronger rules-plus-lookup baseline, fresh ambiguous incidents and a blinded operator trial before any incremental-value claim.

## All trial attempts and protocol repairs

The first attempt on the older 48-case corpus was interrupted by a local `PermissionError` before a scored artifact was retained. It is excluded from quality totals, with no claimed score or known complete usage accounting. Review found that exceptional case paths could leave SQLite open before Windows temporary-directory cleanup; the evaluator now always closes the connection and preserves the original exception.

The first completed 16-case trial used the original catalog projection: **3 valid decisions, 13 degraded cases**, 25 reserved calls and 93,386 conservative reserved tokens, 165.141 seconds for the AI arm. Baseline accepted decisions were 16/16. [Full first record](evidence/next-wave-first.json).

A separate one-case [contract diagnostic](evidence/proxy-diagnostic.json) received a valid model completion asking for catalog reads. It exposed a real adapter mismatch: `access_patterns` returns derived candidates/coverage, while the gateway expected an `events` list. Previous gateway doubles had bypassed that adapter. The production gateway now validates and projects bounded candidate codes/known references/gaps/limitations. Raw entity labels, counts and arbitrary fields do not enter this derived context.

The second full trial, with that catalog repair and explicit failure codes, retained the same corpus and grading: **3 valid decisions, 13 `READ_ROUND_LIMIT` cases**, 42 calls, 166,021 conservative reserved tokens and 308.313 seconds. [Full second record](evidence/next-wave-catalog-fixed.json). The fresh stateless prompts had not exposed the remaining investigation rounds, so the model repeatedly requested reads until the hard cap.

The final protocol supplies the runtime-owned `readRoundsRemaining` value **2 → 1 → 0**, states that finalization must preserve uncertainty and requires `readRequests: []` at zero. Models that still request reads are rejected/degraded. This changes no evidence, truth, scoring or execution authority. The protocol route version changes, and all earlier trials remain published; the final rerun is not presented as a first unseen trial or a best-of sample.

The final run completed all sixteen cases with the same frozen corpus hash. Its captured source hashes match the final core/gateway/evaluator files. [All attempts and artifact hashes](evidence/next-wave-trials.json) retain the interrupted attempt, diagnostic and both earlier completed trials.

Intermediate adapter/evaluator versions were not separately committed; their captured hashes identify those runs, while the final sources in this delivery support the final reproduction. Exact historical source/binary reconstruction and exact upstream model reproducibility are not established by a digest alone.

| Final registered metric | Frozen baseline v1 | Actual Codex through CLIProxyAPI |
|---|---:|---:|
| Valid completed decisions | 16/16 | 16/16 |
| Policy-acceptable assessments | 16/16 | 16/16 |
| Supported-effect cases identified | 4/4 | 4/4 |
| False suspicious assessments among four benign cases | 0 | 0 |
| Correct unknown outcomes | 8/8 | 8/8 |
| Decisive benign / benign abstentions | 2 / 2 | 4 / 0 |
| Acceptable next-step proposals | 12/16 | 16/16 |
| Registered required-code presence | 13/16 | 14/16 |
| Degraded cases | 0 | 0 |
| Model calls | 0 | 41 |
| Conservative reserved visible tokens | 0 | 171,631 |
| Triage-arm wall time | 4.078 seconds | 318.469 seconds |

**Disposition: real provider integration works after the recorded repairs; incremental operational AI value is not established.** Coarse assessment quality ties the baseline. The four-proposal difference and one additional required-code match are narrow curator-registered checks on public, partly observer-resolved facts. They are neither independent semantic accuracy nor proof that AI prevented more harm. A small deterministic recovery/control lookup could close these baseline gaps and must be evaluated before claiming an AI advantage. The model arm is materially slower and has additional usage cost; no analyst-time saving or human comparison was measured. No further provider rerun was selected to improve this final score.

## Validation and reproduction

The local Python suite ran **227 tests: 223 passed, four explicit skips**. Three require the separately opted-in Docker lab; Windows did not grant the remaining symlink test. Go package tests/vet and ten offline script-gate tests pass. Independent additions include ten actual effect/fairness challenges, eleven evaluator/orchestrator tests and seven actual HTTP catalog/budget tests. Catalogue peers are explicitly labelled completion doubles; only the published Codex trials use a real provider.

The independent reviewer found and verified fixes for real object-byte observation, an absolute header-trickle deadline, exceptional SQLite cleanup, input/output overwrite, corpus mutation/hash races, the derived-catalog adapter mismatch and hidden remaining-round state. No case-specific expected answer or label was added to a prompt. Root and a separate agent also inspected the recovery overwrite/invariant boundary.

```powershell
go -C runtime-go build -trimpath -o ../artifacts/runtime-go/shield-correlate.exe ./cmd/shield-correlate
go -C runtime-go build -trimpath -o ../artifacts/runtime-go/shield-tool-lab.exe ./cmd/shield-tool-lab
go -C runtime-go build -trimpath -o ../artifacts/runtime-go/shield-flow-lab.exe ./cmd/shield-flow-lab
python -m unittest discover -s tests -p 'test_*.py' -v
python -m openshield next-wave-lab --output output/next-wave-offline.json
# After the separate operator proxy setup:
python -m openshield next-wave-lab --with-ai --output output/next-wave-real-ai.json
```

Omit `.exe` on Linux/macOS. CI runs only the offline arm. Reproduction can have different model choices/latency even with the same alias; corpus/source/binary hashes and safe provenance are retained. Reported per-call model usage is incomplete run accounting; conservative reservations are not billed/account-wide usage and exclude unknown proxy-hidden costs.

## Remaining limits

The [24-case ledger](../NEXT_WAVE.md) distinguishes eleven newly exercised slices, three earlier tool-authority slices, three limited existing proofs and seven unsupported cases. No production identity, cloud/host adapter, external source authentication or full portfolio acceptance is established. Cache experiments cover fixed owned origin/edge paths and identity/gzip, not a real CDN/browser. Restore checks cover a fixed unencrypted SQLite application, not key recovery, malware eradication, interrupted restore, production RPO/RTO or reversal of disclosure. Protection continues independently of AI failure; model availability is not evidence of better defense.
