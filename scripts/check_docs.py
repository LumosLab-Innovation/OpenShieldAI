"""Offline documentation-path and S0 research-provenance checks; no efficacy claims."""

import json
import re
import sys
from datetime import date
from pathlib import Path
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
REQUIRED = (
    "README.md", "AGENTS.md", "CONTEXT.md", "LICENSE", "LICENSING.md",
    "SECURITY.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md",
    "docs/PRD.md", "docs/ARCHITECTURE.md", "docs/SECURITY_GUARDRAILS.md",
    "docs/ACCEPTANCE_CRITERIA.md", "docs/WORKER_SPEC.md",
    "docs/LLM_PROVIDER_SPEC.md", "docs/PRODUCTION_READINESS.md",
    "docs/EVALUATION.md", "docs/DATA_CONTRACTS.md", "docs/ROADMAP.md",
    "docs/THREAT_MODEL.md", "docs/OPENHUNTER_COLLABORATION.md",
    "docs/research/UPSTREAM_EVALUATION.md", "docs/research/AI_DEFENSE_EVIDENCE.md",
    "docs/research/SKEPTICAL_REVIEW.md", "docs/playbooks/INCIDENT_RESPONSE.md",
)


def local_targets(markdown):
    """Inspect inline Markdown/image and HTML links, ignoring fenced examples.

    Reference-style links and fragment IDs are not validated by this small checker.
    """
    text = re.sub(r"(?ms)^(```|~~~)[^\n]*\n.*?^\1[ \t]*$", "", markdown)
    targets = re.findall(r"!?\[[^\]\n]*\]\(([^)\n]+)\)", text)
    targets += re.findall(r'''(?:href|src)=["']([^"']+)["']''', text)
    for target in targets:
        parsed = urlsplit(target.strip().strip("<>"))
        if not parsed.scheme and not parsed.netloc and parsed.path:
            yield unquote(parsed.path)


def validate_registry(data):
    errors = []
    if not isinstance(data, dict):
        return ["registry root must be an object"]
    expected = {
        "schemaVersion": "1.0", "status": "design_research",
        "integrationStatus": "not_implemented", "updatePolicy": "manual_review_only",
        "vendoredContent": False, "capabilityStage": "S0",
    }
    for key, value in expected.items():
        if data.get(key) != value:
            errors.append(f"registry {key}: expected {value!r}")
    try:
        reviewed = date.fromisoformat(data["reviewedAt"])
    except (KeyError, ValueError, TypeError):
        errors.append("registry needs an ISO reviewedAt date")
        reviewed = None
    entries = data.get("upstreams")
    if not isinstance(entries, list) or not entries:
        return errors + ["registry needs nonempty upstreams array"]
    ids = set()
    decisions = {"reference", "evaluate", "integrate_candidate", "reject_as_core"}
    for item in entries:
        if not isinstance(item, dict):
            errors.append("upstream must be an object")
            continue
        uid = item.get("id", "")
        if not isinstance(uid, str) or not uid or uid in ids:
            errors.append(f"invalid/duplicate upstream id: {uid!r}")
        else:
            ids.add(uid)
        ref = item.get("reviewedCommit", "")
        repo = item.get("repository", "")
        if not isinstance(ref, str) or not re.fullmatch(r"[0-9a-f]{40}", ref):
            errors.append(f"{uid}: missing immutable 40-character commit")
        prefix = f"https://github.com/{repo}"
        if not isinstance(repo, str) or not re.fullmatch(r"[\w.-]+/[\w.-]+", repo):
            errors.append(f"{uid}: invalid repository")
        if item.get("url") != prefix:
            errors.append(f"{uid}: repository URL mismatch")
        if not str(item.get("licenseEvidenceUrl", "")).startswith(f"{prefix}/blob/{ref}/"):
            errors.append(f"{uid}: license evidence must use reviewed commit")
        if not item.get("licenseDeclared") or not item.get("boundary"):
            errors.append(f"{uid}: license and integration boundary required")
        if item.get("decision") not in decisions:
            errors.append(f"{uid}: unknown adoption decision")
        if item.get("integrationStatus") != "not_implemented":
            errors.append(f"{uid}: S0 cannot claim an implemented integration")
        validations = item.get("requiredValidation")
        if not isinstance(validations, list) or not validations:
            errors.append(f"{uid}: requiredValidation must be nonempty")
        try:
            observed = date.fromisoformat(item["observedCommitDate"][:10])
            if reviewed and observed > reviewed:
                errors.append(f"{uid}: commit date exceeds review snapshot")
        except (KeyError, TypeError, ValueError):
            errors.append(f"{uid}: invalid observed commit date")
    return errors


def check(root):
    root = root.resolve()
    errors = [f"missing required file: {name}" for name in REQUIRED if not (root / name).is_file()]
    markdown = sorted(path for path in root.rglob("*.md") if ".git" not in path.relative_to(root).parts)
    for path in markdown:
        for target in local_targets(path.read_text(encoding="utf-8-sig")):
            resolved = (path.parent / target).resolve()
            if not resolved.is_relative_to(root) or not resolved.exists():
                errors.append(f"{path.relative_to(root)}: missing/outside local target {target}")
    try:
        registry = json.loads((root / "docs/research/upstreams.json").read_text(encoding="utf-8-sig"))
        errors.extend(validate_registry(registry))
    except (OSError, ValueError) as exc:
        errors.append(f"cannot read registry: {exc}")
        registry = {}
    return errors, len(markdown), len(registry.get("upstreams", [])) if isinstance(registry, dict) else 0


if __name__ == "__main__":
    failures, docs, upstreams = check(ROOT)
    for failure in failures:
        print(f"ERROR: {failure}")
    print(f"Checked {docs} Markdown files and {upstreams} pinned upstream records; {len(failures)} error(s).")
    print("Offline structural check only: no remote-link, runtime, security-efficacy or license-compatibility validation.")
    sys.exit(bool(failures))
