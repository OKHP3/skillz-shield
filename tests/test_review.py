"""Review policy must match every blocker without changing scanner evidence."""
import copy
import datetime as dt
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import entrypoint
from skill_security.review import evaluate


class ExactReviewTests(unittest.TestCase):
    def setUp(self):
        self.today = dt.date(2026, 10, 22)
        cisco = {
            "engine": "cisco", "status": "findings", "errors": [],
            "findings": [{"rule_id": "YARA_sql_injection_generic", "severity": "critical"}],
            "finding_diagnostics": {"locations": [{"rule_id": "YARA_sql_injection_generic",
                                                   "severity": "critical", "file": "scripts/reconcile.py", "line": 90}],
                                    "unavailable": 0},
        }
        nvidia = {
            "engine": "nvidia", "status": "incomplete", "errors": ["analysis_incomplete"],
            "findings": [], "finding_diagnostics": {"locations": [], "unavailable": 0},
            "coverage": {"complete": False, "execution_successful": True, "coverage_percent": 100.0,
                         "total_components": 3, "scanned_components": 3,
                         "fully_inspected_files": 3,
                         "partially_inspected_files": 0, "entirely_uninspected_files": 0,
                         "ledger_fatal_count": 0, "exclusion_count": 0, "limitation_count": 0,
                         "ledger_exception_count": 1, "ledger_reason_counts": {"reference_missing": 1},
                         "incomplete_reasons": ["ledger_exceptions", "vendor_declared_incomplete"],
                         "analyzer_details_truncated": False,
                         "analyzer_details": [{"status": "completed", "partial": 0, "skipped": 0,
                                               "failed": 0, "unaccounted": 0}]},
            "coverage_diagnostics": {"locations": [{"reason_code": "reference_missing",
                                                    "file": "SKILL.md", "line": 23}],
                                     "unavailable": 0, "truncated": False},
        }
        self.report = {
            "decision": "incomplete", "complete": False, "expected_packages": 1,
            "high_or_critical_findings": 1,
            "toolchain": {"fingerprint": "a" * 64},
            "packages": [{"package": "community/sql-server-table-reconciliation",
                          "content": {"sha256": "b" * 64, "metadata_generated": False}, "engines": [cisco, nvidia]}],
        }
        self.ledger = {"schema": 1, "reviews": [{
            "package": "community/sql-server-table-reconciliation",
            "content_sha256": "b" * 64, "toolchain_fingerprint": "a" * 64,
            "expires": "2026-11-21", "reviewer": "repository owner",
            "rationale": "Parameterized metadata query and illustrative documentation tokens manually reviewed.",
            "findings": [{"engine": "cisco", "rule_id": "YARA_sql_injection_generic",
                          "severity": "critical", "file": "scripts/reconcile.py", "line": 90}],
            "coverage_gaps": [{"engine": "nvidia", "reason_code": "reference_missing",
                               "file": "SKILL.md", "line": 23}],
        }]}

    def decision(self, report=None, ledger=None):
        return evaluate(report or self.report, ledger or self.ledger, today=self.today)["decision"]

    def test_exact_review_keeps_raw_report_incomplete(self):
        before = copy.deepcopy(self.report)
        self.assertEqual(self.decision(), "reviewed-limitation")
        self.assertEqual(self.report, before)

    def test_source_vendor_line_and_expiry_drift_invalidate_review(self):
        for field, value in (("content_sha256", "c" * 64),
                             ("toolchain_fingerprint", "c" * 64),
                             ("expires", "2026-10-21"),
                             ("expires", "2027-01-22")):
            with self.subTest(field=field, value=value):
                ledger = copy.deepcopy(self.ledger)
                ledger["reviews"][0][field] = value
                self.assertEqual(self.decision(ledger=ledger), "review-required")
        for field in ("findings", "coverage_gaps"):
            ledger = copy.deepcopy(self.ledger)
            ledger["reviews"][0][field][0]["line"] += 1
            self.assertEqual(self.decision(ledger=ledger), "review-required")

    def test_new_finding_or_missing_location_cannot_be_reviewed(self):
        report = copy.deepcopy(self.report)
        report["packages"][0]["engines"][0]["findings"].append(
            {"rule_id": "NEW_RISK", "severity": "high"})
        self.assertEqual(self.decision(report=report), "review-required")
        report = copy.deepcopy(self.report)
        report["packages"][0]["engines"][0]["finding_diagnostics"]["unavailable"] = 1
        self.assertEqual(self.decision(report=report), "review-required")

    def test_uninspected_or_other_incomplete_evidence_cannot_be_reviewed(self):
        for key, value in (("coverage_percent", 99.0), ("entirely_uninspected_files", 1),
                           ("ledger_fatal_count", 1), ("exclusion_count", 1)):
            with self.subTest(key=key):
                report = copy.deepcopy(self.report)
                report["packages"][0]["engines"][1]["coverage"][key] = value
                self.assertEqual(self.decision(report=report), "review-required")
        report = copy.deepcopy(self.report)
        report["packages"][0]["engines"][1]["coverage"]["ledger_reason_counts"] = {"read_error": 1}
        self.assertEqual(self.decision(report=report), "review-required")

    def test_all_blocked_packages_must_be_reviewed(self):
        report = copy.deepcopy(self.report)
        other = copy.deepcopy(report["packages"][0])
        other["package"] = "other/example"
        report["packages"].append(other)
        report["expected_packages"] = 2
        self.assertEqual(self.decision(report=report), "review-required")

    def test_raw_pass_needs_no_review(self):
        report = {"decision": "pass", "complete": True}
        self.assertEqual(self.decision(report=report, ledger={"schema": 1, "reviews": []}), "raw-pass")

    def test_action_reads_review_ledger_from_pr_base_commit(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            report = copy.deepcopy(self.report)
            report["source_commit"] = "b" * 40
            (state / "report.json").write_text(json.dumps(report), encoding="utf-8")
            (state / "plan.json").write_text(json.dumps({
                "source_commit": "b" * 40, "packages": [report["packages"][0]["package"]],
            }), encoding="utf-8")
            args = ["entrypoint.py", "review", "--root", temporary, "--state", temporary,
                    "--base", "a" * 40]
            live_ledger = copy.deepcopy(self.ledger)
            live_ledger["reviews"][0]["expires"] = (
                dt.datetime.now(dt.timezone.utc).date() + dt.timedelta(days=30)).isoformat()
            with patch("sys.argv", args), patch("entrypoint.discovery._revision", return_value="a" * 40), \
                    patch("skill_security.staging.git", return_value=json.dumps(live_ledger).encode()) as read:
                self.assertEqual(entrypoint.main(), 0)
            self.assertEqual(read.call_args.args[2], "a" * 40 + ":.github/skill-security-reviews.json")
            self.assertEqual(json.loads((state / "review.json").read_text())["decision"], "reviewed-limitation")


if __name__ == "__main__":
    unittest.main()
