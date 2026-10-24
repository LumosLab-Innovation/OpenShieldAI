"""Optional installed Playwright/Chrome probe: python -m scripts.check_anti_rea_browser."""

import json
import os
import subprocess
from pathlib import Path

from lab.anti_rea import AntiReaLab


def main():
    with AntiReaLab(protected=False) as before, AntiReaLab() as after:
        env = dict(os.environ)
        env["LAB_PROBE_CONFIG"] = json.dumps([
            {"arm": "before", "url": before.url, "session": before.issue_session()},
            {"arm": "after", "url": after.url, "session": after.issue_session()}])
        try:
            result = subprocess.run(["node", str(Path(__file__).with_name("anti_rea_browser.cjs"))],
                                    env=env, capture_output=True, text=True, timeout=30, check=False)
            if result.returncode:
                raise ValueError()
            record = json.loads(result.stdout)
            print(json.dumps(record, indent=2))
            return 0 if record["status"] == "pass" else 1
        except (ValueError, OSError, subprocess.SubprocessError):
            print(json.dumps({"status": "failed", "code": "browser_probe_unavailable_or_failed",
                              "requires": "Installed node, playwright resolvable via NODE_PATH, and Chrome"}))
            return 1


if __name__ == "__main__":
    raise SystemExit(main())
