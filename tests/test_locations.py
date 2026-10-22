import copy
import json
from pathlib import Path
import tempfile
import unittest

from skill_security import locations


class LocationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.staged = Path(self.temporary.name)
        (self.staged / "SKILL.md").write_text("one\ntwo\n", encoding="utf-8")
        self.files = locations.inventory(self.staged)
        self.normalized = {"status": "incomplete", "errors": ["analysis_incomplete"],
                           "coverage": {"package_path_bound": True},
                           "findings": [{"rule_id": "P1", "severity": "high"}]}

    def report(self, **extra):
        return {"issues": [{"id": "P1", "severity": "HIGH", "message": "PRIVATE-SENTINEL",
                            "location": {"file": "SKILL.md", "start_line": 2}, **extra}]}

    def test_known_locations_without_messages_or_absolute_paths_and_no_verdict_changes(self):
        before = copy.deepcopy(self.normalized)
        report = self.report(location={"file": (self.staged / "SKILL.md").as_posix(), "start_line": 2})
        output = locations.diagnostics("nvidia", report, self.normalized, self.files)
        self.assertEqual(output["locations"], [{"rule_id": "P1", "severity": "high", "file": "SKILL.md", "line": 2}])
        self.assertNotIn("PRIVATE-SENTINEL", json.dumps(output))
        self.assertNotIn(str(self.staged), json.dumps(output))
        self.assertEqual(self.normalized, before)

    def test_unknown_outside_traversal_and_out_of_bounds_lines_are_unavailable(self):
        for path, line in [("../SKILL.md", 1), ("/etc/passwd", 1), ("missing.md", 1),
                           ("SKILL.md", 0), ("SKILL.md", 3), ("SKILL.md", True), ("SKILL.md", "2")]:
            with self.subTest(path=path, line=line):
                output = locations.diagnostics("nvidia", self.report(location={"file": path, "start_line": line}), self.normalized, self.files)
                self.assertEqual(output["locations"], [])
                self.assertEqual(output["unavailable"], 1)

    def test_transitive_or_unbound_report_cannot_borrow_local_identity(self):
        output = locations.diagnostics("nvidia", self.report(source_identity="remote"), self.normalized, self.files)
        self.assertEqual(output["locations"], [])
        self.normalized["coverage"]["package_path_bound"] = False
        self.assertEqual(locations.diagnostics("nvidia", self.report(), self.normalized, self.files)["locations"], [])

    def test_occurrences_deduplicate_and_bound_work(self):
        occurrence = {"file": "SKILL.md", "start_line": 1}
        output = locations.diagnostics("nvidia", self.report(occurrences=[occurrence] * 1001), self.normalized, self.files)
        self.assertEqual(len(output["locations"]), 1)
        self.assertTrue(output["truncated"])

    def test_cisco_excludes_unaccepted_rule_and_maps_line(self):
        report = {"findings": [{"rule_id": rule, "severity": "HIGH", "file_path": "SKILL.md", "line_number": 1}
                               for rule in ["METADATA", "P1"]]}
        output = locations.diagnostics("cisco", report, self.normalized, self.files)
        self.assertEqual(len(output["locations"]), 1)
        self.assertEqual(output["locations"][0]["rule_id"], "P1")

    def test_no_findings_and_malformed_vendor_records_do_not_create_evidence(self):
        self.normalized["findings"] = []
        self.assertEqual(locations.diagnostics("nvidia", self.report(), self.normalized, self.files)["locations"], [])
        for report in ({"issues": None}, {"issues": [None, [], {"id": [], "severity": []}]}, {}):
            self.assertEqual(locations.diagnostics("nvidia", report, self.normalized, self.files)["locations"], [])
        # An adapter rejecting the report cannot grant any source binding.
        self.assertEqual(locations.diagnostics("nvidia", None, {"coverage": {}}, self.files)["locations"], [])


if __name__ == "__main__":
    unittest.main()
