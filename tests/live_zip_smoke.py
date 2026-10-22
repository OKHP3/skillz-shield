"""Verify whole-ZIP submission with real pinned engines and inert fixtures."""
import argparse
import json
from pathlib import Path
import sys
import tempfile
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from skill_security.submission import scan_zip, render_html
from live_smoke import _FIXTURES


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", type=Path, required=True)
    args = parser.parse_args()
    evidence = {"kind": "live-zip-smoke", "passed": False, "reports": [], "checks": {}}
    try:
        with tempfile.TemporaryDirectory(prefix="shield-zip-smoke-") as temporary:
            for package in ("supporting-draft", "security-canary"):
                archive = Path(temporary) / (package + ".zip")
                prefix = "smoke/" + package + "/"
                with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zipped:
                    for path, body in _FIXTURES.items():
                        if path.startswith(prefix):
                            zipped.writestr(path[len(prefix):], body)
                report = scan_zip(archive, args.state.resolve())
                rendered = render_html(report)
                evidence["reports"].append(report)
                evidence["checks"][package + "-complete"] = report["complete"] is True
                evidence["checks"][package + "-report"] = report["decision"] in rendered
            draft, canary = evidence["reports"]
            evidence["checks"]["draft-wrapper-recorded"] = draft["source"]["metadata_generated"] is True
            evidence["checks"]["canary-original-preserved"] = canary["source"]["metadata_generated"] is False
            evidence["checks"]["canary-detected"] = canary["high_or_critical_findings"] > 0
            evidence["checks"]["canary-not-pass"] = canary["decision"] == "review-required"
            evidence["passed"] = all(evidence["checks"].values())
    except (ValueError, OSError, KeyError, TypeError):
        evidence["error"] = "zip-smoke-incomplete"
    (args.state / "zip-smoke-report.json").write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print("ZIP smoke: " + ("passed" if evidence["passed"] else "failed; inspect sanitized evidence"))
    return 0 if evidence["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
