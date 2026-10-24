# Stronger deterministic comparator after the real AI trial

Observed **2026-10-24**. This is an **offline post-hoc public regression**, introduced after the [actual Codex result and review](NEXT_WAVE_RESULTS.md). It is not an independent held-out test, a new attack-effect experiment or a change to the runtime's frozen baseline v1. [Machine-readable record](evidence/baseline-v2.json), [decision code](../../openshield/baseline_v2.py), [comparison harness](../../lab/baseline_v2_comparison.py), [focused tests](../../tests/test_baseline_v2.py).

## Minimal method

The separate comparator reuses v1 and adds two generic lookup rules:

1. An application-restore verification that is `not_verified` or `inconclusive` produces the evidence-linked `recovery_gap` hypothesis. It does not identify the failure cause or imply compromise.
2. An existing recovery gap or a recorded visibility/freshness/observer gap requires `needs_human` review. It grants no action and requests no new observation.

This is **case-level human review of historical failures, not reconciled current readiness**. The event schema has no restoration-episode identity or closure record. A failed restore followed by a later verified restore therefore keeps the earlier failure reference and `needs_human`; it does not declare that the latest restore failed, infer compromise or automatically close the historical concern. An independent regression makes this conservative limit explicit. The machine-readable record's limitations received this review annotation after capture; the decision code, captured metrics and 2.375-second run are unchanged.

The decision function receives only the accepted `Store` snapshot. Scenario names, truth, groups, source-fact provenance and expected answers remain outside it. Both arms have the same accepted facts, source roles, available read catalog and zero mutation capabilities; v2 requests no catalog reads. The original baseline code, 16-case corpus and retained actual AI record are unchanged. No provider call occurs in this study.

## Results

| Registered check | Frozen baseline v1, retained | Separate rules + lookup v2 | Actual Codex, retained |
|---|---:|---:|---:|
| Policy-acceptable assessments | 16/16 | 16/16 | 16/16 |
| Supported-effect cases identified | 4/4 | 4/4 | 4/4 |
| False suspicious assessments among four benign cases | 0 | 0 | 0 |
| Correct unknown outcomes | 8/8 | 8/8 | 8/8 |
| Decisive benign / benign abstentions | 2 / 2 | 2 / 2 | 4 / 0 |
| Acceptable next-step proposals | 12/16 | 16/16 | 16/16 |
| Required hypothesis-code presence | 13/16 | 16/16 | 14/16 |
| Model calls | 0 | 0 | 41 |
| Conservative reserved visible tokens | 0 | 0 | 171,631 |

The two lookup rules close all four proposal differences: three failed/unverified application recoveries and one source-loss ablation. They also supply all three missing recovery-gap codes. The AI arm still makes two more decisive benign classifications. The scorer permits conservative benign abstention and exposes it separately; no further rule was added merely to remove those abstentions.

**Disposition:** the public proposal/code gains do not establish that AI is necessary or operationally better. A small non-AI extension closes them on these already examined cases. This also does not prove v2 generalizes or outperforms AI: v2 was explicitly tuned after the public results, while code presence and next-step membership remain curator checks rather than semantic precision.

## Timing and reproducibility limits

The v2 run took **2.375 seconds** for one 16-case pass, including isolated SQLite Store creation, enrollment, intake, snapshot extraction and direct decision calls. It omits resident Supervisor episode persistence. Historical v1 and AI arms took **4.078** and **318.469 seconds** through their original full triage harness. These are different harnesses/run times, so **no matched speedup ratio** is claimed. Retained AI usage is a conservative reservation rather than billing, and hidden/interrupted usage remains subject to the original trial's limitations.

The report binds the exact corpus, retained real-run artifact, v2/harness/core source hashes, Python version and platform. Digests establish relative integrity, not authenticity. Input drift is rejected after evaluation, and output is guarded against replacing either frozen input before evaluation begins.

```text
python -m unittest discover -s tests -p test_baseline_v2.py -v
python -m lab.baseline_v2_comparison --output output/baseline-v2.json
```

Eight focused tests cover non-independent and inconclusive restore observations, failed-then-verified historical review, healthy/benign positive controls, malformed or missing verification facts, changed IDs and event/case ordering, unused evaluator-label poisoning, immutable inputs and output-overwrite rejection. They are engineering checks, not eight independent attacks.

No new model call, analyst-time trial, fresh ambiguous incident sample or production validation was performed. Next useful evidence is a separately frozen ambiguous corpus with the stronger comparator registered before inference and an operator workflow trial; enforcement, containment and recovery effects remain identical with and without AI.
