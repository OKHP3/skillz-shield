"""End-to-end ZIP orchestration with inert engine doubles and escaped reports."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from skill_security import submission


class SubmissionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.archive = self.root / "package.zip"
        self.script = b"raise SystemExit('THIS SUBMITTED CODE MUST NOT RUN')\n"
        with zipfile.ZipFile(self.archive, "w") as archive:
            archive.writestr("SKILL.md", "# A draft\n")
            archive.writestr("scripts/helper.py", self.script)
        self.pins = {"engines": {name: {"version": "1.2.3"} for name in ("cisco", "nvidia")}}
        self.executables = {name: self.root / name for name in ("cisco", "nvidia")}

    def result(self, name, status="no-findings", findings=None):
        return {"engine": name, "status": status, "findings": findings or [],
                "coverage": {"complete": status != "incomplete"},
                "errors": ["analysis_incomplete"] if status == "incomplete" else [],
                "finding_diagnostics": {"locations": [], "unavailable": 0, "truncated": False}}

    def scan(self, results):
        staged = []
        def engine(name, executable, package, target, work, pin):
            self.assertEqual((target / "scripts/helper.py").read_bytes(), self.script)
            self.assertEqual(package, "submitted-package")
            staged.append(target)
            return copy.deepcopy(results[name])
        with patch.object(submission, "read_state", return_value=(self.pins, self.executables)), \
                patch.object(submission, "scan_engine", side_effect=engine):
            report = submission.scan_zip(self.archive, self.root)
        self.assertEqual(len(staged), 2)
        self.assertTrue(all(not path.exists() for path in staged))
        self.assertEqual(report["source"]["files"], 2)
        self.assertEqual(len(report["source"]["archive_sha256"]), 64)
        return report

    def test_both_engines_receive_whole_package_and_temporary_files_are_removed(self):
        report = self.scan({name: self.result(name) for name in self.executables})
        self.assertEqual(report["decision"], "pass")
        self.assertTrue(report["complete"])
        self.assertNotIn("source_commit", report)

    def test_high_findings_require_review_but_incomplete_takes_precedence(self):
        finding = {"rule_id": "P1", "severity": "high"}
        results = {"cisco": self.result("cisco"), "nvidia": self.result("nvidia", "findings", [finding])}
        self.assertEqual(self.scan(results)["decision"], "review-required")
        results["cisco"] = self.result("cisco", "incomplete")
        report = self.scan(results)
        self.assertEqual(report["decision"], "incomplete")
        self.assertEqual(report["high_or_critical_findings"], 1)
        self.assertEqual(report["engines"][1]["findings"], [finding])

    def test_render_has_actionable_guidance_locations_and_escapes_all_evidence(self):
        finding = {"rule_id": "P1", "severity": "high"}
        result = self.result("nvidia", "findings", [finding])
        result["finding_diagnostics"]["locations"] = [{**finding, "file": "<script>alert(1)</script>.md", "line": 2}]
        report = self.scan({"cisco": self.result("cisco"), "nvidia": result})
        report["toolchain"]["test"] = "</pre><script>SECRET</script>"
        html = submission.render_html(report)
        self.assertIn("Suggested action:", html)
        self.assertIn("Why review:", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn("<script>", html)
        self.assertNotIn(self.script.decode(), html)

    def test_state_must_match_installed_versions_and_executable_files(self):
        (self.root / "pins.json").write_text(json.dumps(self.pins))
        (self.root / "installed.json").write_text(json.dumps({name: "1.2.2" for name in self.executables}))
        with self.assertRaisesRegex(ValueError, "installed-version-mismatch"):
            submission.read_state(self.root)
        (self.root / "installed.json").write_text(json.dumps({name: "1.2.3" for name in self.executables}))
        with self.assertRaisesRegex(ValueError, "scanner-not-installed"):
            submission.read_state(self.root)

    def test_existing_report_destination_is_not_overwritten_or_scanned(self):
        output = self.root / "existing"
        output.mkdir()
        sentinel = output / "report.json"
        sentinel.write_text("prior evidence")
        with patch("sys.argv", ["submission", str(self.archive), "--state", str(self.root), "--output", str(output)]), \
                patch.object(submission, "scan_zip") as scan:
            self.assertEqual(submission.main(), 2)
            scan.assert_not_called()
        self.assertEqual(sentinel.read_text(), "prior evidence")

    def test_delivery_failure_does_not_leave_a_partial_passing_report(self):
        report = self.scan({name: self.result(name) for name in self.executables})
        output = self.root / "results"
        original = Path.write_text
        def fail_html(path, *args, **kwargs):
            if path.name == "report.html":
                raise OSError("disk full")
            return original(path, *args, **kwargs)
        with patch("sys.argv", ["submission", str(self.archive), "--state", str(self.root), "--output", str(output)]), \
                patch.object(submission, "scan_zip", return_value=report), patch.object(Path, "write_text", fail_html):
            self.assertEqual(submission.main(), 2)
        self.assertFalse(output.exists())
        self.assertEqual(list(self.root.glob(".shield-report-*")), [])

    def test_repeated_findings_group_locations_once_and_bound_html(self):
        finding = {"rule_id": "P1", "severity": "high"}
        engine = self.result("nvidia", "findings", [finding] * 100)
        engine["finding_diagnostics"]["locations"] = [{**finding, "file": "references/" + "a" * 200 + ".md", "line": i + 1} for i in range(100)]
        report = self.scan({"cisco": self.result("cisco"), "nvidia": engine})
        rendered = submission.render_html(report)
        self.assertLess(len(rendered), 50000)
        self.assertEqual(rendered.count("Suggested action:"), 1)
        self.assertIn("100 finding(s)", rendered)
        self.assertEqual(len(report["engines"][1]["findings"]), 100)

    def test_presentation_truncation_is_explicit_and_json_findings_remain(self):
        engine = self.result("nvidia", "findings", [{"rule_id": f"RULE{i}", "severity": "low"} for i in range(501)])
        report = self.scan({"cisco": self.result("cisco"), "nvidia": engine})
        self.assertIn("Full findings remain in report.json", submission.render_html(report))
        self.assertEqual(len(report["engines"][1]["findings"]), 501)
        self.assertTrue(report["review_guidance"][1]["truncated"])

    def test_success_publishes_both_reports_together(self):
        report = self.scan({name: self.result(name) for name in self.executables})
        output = self.root / "results"
        with patch("sys.argv", ["submission", str(self.archive), "--state", str(self.root), "--output", str(output)]), \
                patch.object(submission, "scan_zip", return_value=report):
            self.assertEqual(submission.main(), 0)
        self.assertEqual(json.loads((output / "report.json").read_text())["decision"], "pass")
        self.assertIn("Skillz Shield: pass", (output / "report.html").read_text())
        self.assertEqual(list(self.root.glob(".shield-report-*")), [])


if __name__ == "__main__":
    unittest.main()
