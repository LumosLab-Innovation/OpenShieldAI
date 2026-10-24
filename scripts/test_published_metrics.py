"""Offline checks that public benchmark claims agree with frozen measurements."""

import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "docs/lab/evidence"


def record(name):
    return json.loads((EVIDENCE / name).read_text(encoding="utf-8"))


class PublishedCells(HTMLParser):
    def __init__(self):
        super().__init__()
        self.cells = {}
        self.current = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "td" and "data-metric" in attrs:
            key = (attrs["data-arm"], attrs["data-metric"])
            if key in self.cells:
                raise ValueError(f"Duplicate published metric: {key}")
            self.cells[key] = {"value": float(attrs["data-value"]), "text": ""}
            self.current = key

    def handle_data(self, data):
        if self.current is not None:
            self.cells[self.current]["text"] += data

    def handle_endtag(self, tag):
        if tag == "td":
            self.current = None


class PublishedMetricsTests(unittest.TestCase):
    def test_readme_ai_table_matches_frozen_record(self):
        text = (ROOT / "README.md").read_text(encoding="utf-8")
        table = text.split("| Final registered metric |", 1)[1].split("**Assessment quality", 1)[0]
        rows = {parts[0].strip(): [part.strip() for part in parts[1:]]
                for line in table.splitlines() if line.startswith("|")
                for parts in [line.strip("|").split("|")]}
        arms = record("next-wave.json")["comparison"]["arms"]
        for index, arm in enumerate(("baseline", "ai")):
            metrics = arms[arm]["metrics"]
            expected = {
                "Valid completed decisions": f'{metrics["cases"] - metrics["providerUnavailableCases"]}/{metrics["cases"]}',
                "Policy-acceptable assessments": f'{metrics["policyAcceptableDecisions"]}/{metrics["comparisonCases"]}',
                "Supported-effect cases identified": f'{metrics["truePositives"]}/{metrics["supportedCases"]}',
                "False suspicious among four benign cases": f'{metrics["falsePositives"]}/{metrics["negativeCases"]}',
                "Correct unknown outcomes": f'{metrics["correctUnknown"]}/{metrics["unknownCases"]}',
                "Decisive benign / benign abstentions": f'{metrics["decisiveBenign"]} / {metrics["negativeAbstentions"]}',
                "Acceptable next-step proposals": f'{metrics["acceptableProposals"]}/{metrics["proposalScoredCases"]}',
                "Registered required-code presence": f'{metrics["requiredHypothesisMatches"]}/{metrics["hypothesisScoredCases"]}',
                "Degraded cases": str(metrics["providerUnavailableCases"]),
                "Model calls": str(metrics["calls"]),
                "Conservative reserved visible tokens": f'{metrics["tokens"]:,}',
                "Triage-arm wall time": f'{metrics["wallSeconds"]:.3f} s',
            }
            for label, value in expected.items():
                with self.subTest(arm=arm, label=label):
                    self.assertEqual(rows[label][index], value)

    def test_landing_visible_ai_values_match_evidence(self):
        parser = PublishedCells()
        parser.feed((ROOT / "site/index.html").read_text(encoding="utf-8"))
        keys = {"validDecisions": "cases", "acceptableAssessments": "policyAcceptableDecisions",
                "supportedEffect": "truePositives", "falseSuspicious": "falsePositives",
                "correctUnknown": "correctUnknown", "acceptableProposals": "acceptableProposals",
                "requiredCodes": "requiredHypothesisMatches", "degraded": "providerUnavailableCases",
                "modelCalls": "calls", "reservedTokens": "tokens", "wallSeconds": "wallSeconds"}
        for arm, result in record("next-wave.json")["comparison"]["arms"].items():
            for published, source in keys.items():
                with self.subTest(arm=arm, metric=published):
                    cell = parser.cells[(arm, published)]
                    expected = round(result["metrics"][source], 3)
                    self.assertEqual(cell["value"], expected)
                    # Check rendered text as well as hidden metadata; ratios display their numerator first.
                    visible = re.search(r"[\d,]+(?:\.\d+)?", cell["text"])
                    self.assertIsNotNone(visible)
                    self.assertEqual(float(visible.group().replace(",", "")), expected)

    def test_public_surfaces_retain_failed_trials_and_all_measurement_families(self):
        paths = {"next-wave-first.json", "next-wave-catalog-fixed.json", "next-wave.json",
                 "next-wave-trials.json", "proxy-diagnostic.json", "parallel-defense.json",
                 "go-correlation.json", "decision-comparison.json", "anti-rea.json",
                 "approved-runtime-response.json", "prevention.json", "response.json", "recovery.json"}
        for path in (ROOT / "README.md", ROOT / "site/index.html"):
            text = path.read_text(encoding="utf-8")
            for name in paths:
                with self.subTest(path=path.name, artifact=name):
                    self.assertIn(name, text)
            self.assertIn("171,631", text)
            self.assertIn("held-out", text)
            self.assertNotIn("no real endpoint configured yet", text.lower())
            self.assertNotIn("ai evaluation pending", text.lower())

    def test_completed_trial_files_still_match_captured_normalized_hashes(self):
        manifest = record("next-wave-trials.json")
        self.assertFalse(manifest["factsTruthAndGradingChangedBetweenTrials"])
        self.assertTrue(manifest["allThreeCompletedTrialsIncluded"])
        for trial in manifest["trials"]:
            path = EVIDENCE / trial["artifact"]
            digest = hashlib.sha256(path.read_text(encoding="utf-8").encode()).hexdigest()
            self.assertEqual(digest, trial["artifactSha256"])


if __name__ == "__main__":
    unittest.main()
