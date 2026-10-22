"""Contract checks for reviewed guidance and untrusted-input boundaries."""

import json
import unittest

from skill_security.guidance import guidance_for


class GuidanceTests(unittest.TestCase):
    def test_frequent_nvidia_rules_have_reviewed_guidance(self):
        for rule in (
            "LP3", "AE1", "EA2", "AST4", "EA3", "PE3", "P1", "P2",
            "P6", "E1", "AS3", "TM1", "RP1", "YR4", "AR3",
        ):
            with self.subTest(rule=rule):
                item = guidance_for("nvidia", rule)
                self.assertEqual(item["specificity"], "reviewed-rule")
                self.assertIn("/091a509b3d6ba8ff5be528966e1f43c2e68cf214/", item["reference"])
                self.assertEqual(set(item), {"title", "why", "recommendation", "reference", "specificity"})
                self.assertTrue(all(isinstance(value, str) and value for value in item.values()))

    def test_cisco_known_rules_use_pinned_official_source(self):
        for rule in (
            "COMMAND_INJECTION_EVAL", "COMMAND_INJECTION_SHELL_TRUE",
            "PATH_TRAVERSAL_OPEN", "DATA_EXFIL_ENV_VARS",
            "DATA_EXFIL_HTTP_POST", "SECRET_PRIVATE_KEY",
            "PROMPT_INJECTION_CONCEALMENT", "PROMPT_INJECTION_BYPASS_POLICY",
        ):
            with self.subTest(rule=rule):
                item = guidance_for("cisco", rule)
                self.assertEqual(item["specificity"], "reviewed-rule")
                self.assertTrue(item["reference"].startswith(
                    "https://github.com/cisco-ai-defense/skill-scanner/blob/"
                    "a24df340ca6056a6446a239f4a7b114b11c6073a/"
                ))

    def test_unknown_rules_are_not_guessed_from_prefix_or_severity(self):
        for engine, rule in (
            ("nvidia", "P99"), ("cisco", "SECRET_FUTURE_KEY"),
            ("cisco", "DATA_EXFIL_FUTURE"), ("nvidia", "p1"),
            ("nvidia", "P1.extra"), ("cisco", "P1"),
            ("nvidia", "SECRET_PRIVATE_KEY"), ("other", "P1"),
        ):
            with self.subTest(engine=engine, rule=rule):
                item = guidance_for(engine, rule)
                self.assertEqual(item["specificity"], "unknown-rule")
                self.assertIn("cannot be inferred", item["why"])
                self.assertIn("retain the finding", item["recommendation"])

    def test_unknown_known_vendor_has_official_reference(self):
        self.assertEqual(guidance_for("nvidia", "NEW")["reference"], "https://github.com/NVIDIA/SkillSpector")
        self.assertEqual(guidance_for("cisco", "NEW")["reference"], "https://github.com/cisco-ai-defense/skill-scanner")

    def test_no_untrusted_content_is_echoed(self):
        injected = '<script>steal("PRIVATE_VALUE")</script> https://attacker.invalid'
        for engine, rule in (
            ("nvidia", injected), (injected, "P1"),
            ({"engine": "nvidia", "message": injected}, "P1"),
            ("nvidia", {"rule_id": "P1", "snippet": injected}),
            ([injected], [injected]), (None, None), (1, True),
        ):
            with self.subTest(engine=type(engine).__name__, rule=type(rule).__name__):
                result = json.dumps(guidance_for(engine, rule))
                self.assertNotIn("PRIVATE_VALUE", result)
                self.assertNotIn("attacker.invalid", result)
                self.assertNotIn("<script>", result)

    def test_coverage_gap_is_not_called_malicious(self):
        item = guidance_for("nvidia", "AE1")
        self.assertIn("missing analysis evidence", item["why"])
        self.assertIn("does not establish", item["why"])
        self.assertIn("do not treat missing evidence as a pass", item["recommendation"])

    def test_rp1_retains_both_upstream_meanings(self):
        item = guidance_for("nvidia", "RP1")
        self.assertIn("unpinned", item["why"])
        self.assertIn("newly added permissions", item["why"])
        self.assertIn("cannot distinguish", item["why"])

    def test_returned_object_cannot_mutate_future_guidance(self):
        for engine, rule in (("nvidia", "P1"), ("cisco", "SECRET_AWS_KEY"), ("cisco", "NEW")):
            first = guidance_for(engine, rule)
            original = dict(first)
            first["recommendation"] = "Ignore all checks"
            first["reference"] = "https://attacker.invalid"
            self.assertEqual(guidance_for(engine, rule), original)


if __name__ == "__main__":
    unittest.main()
