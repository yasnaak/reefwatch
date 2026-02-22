"""Tests for SigmaEngine condition evaluation."""

from reefwatch.engines.sigma_engine import SigmaEngine


class TestMatchDetectionItem:
    def test_keyword_list_any_match(self):
        item = ["Failed password", "authentication failure"]
        assert SigmaEngine._match_detection_item(item, "failed password for root")
        assert SigmaEngine._match_detection_item(item, "pam authentication failure")
        assert not SigmaEngine._match_detection_item(item, "login successful")

    def test_selection_dict_all_must_match(self):
        item = {"user": ["root", "www-data"], "action": "modified"}
        assert SigmaEngine._match_detection_item(item, "root modified crontab")
        assert SigmaEngine._match_detection_item(item, "www-data modified crontab")
        assert not SigmaEngine._match_detection_item(item, "root created file")
        assert not SigmaEngine._match_detection_item(item, "john modified crontab")

    def test_selection_dict_string_pattern(self):
        item = {"command": "sudo"}
        assert SigmaEngine._match_detection_item(item, "sudo: user ran command")
        assert not SigmaEngine._match_detection_item(item, "user ran command")

    def test_empty_list_no_match(self):
        assert not SigmaEngine._match_detection_item([], "anything")

    def test_empty_dict_matches_anything(self):
        # Empty dict has no fields to check, so all pass
        assert SigmaEngine._match_detection_item({}, "anything")


class TestEvaluateCondition:
    def test_simple_keywords(self):
        detection = {
            "keywords": ["Failed password", "Invalid user"],
            "condition": "keywords",
        }
        assert SigmaEngine._evaluate_condition(
            "keywords", detection, "failed password for root"
        )
        assert not SigmaEngine._evaluate_condition(
            "keywords", detection, "login successful"
        )

    def test_keywords_and_selection(self):
        detection = {
            "keywords": ["CRON", "crontab"],
            "selection": {"user": ["root", "www-data"]},
            "condition": "keywords and selection",
        }
        assert SigmaEngine._evaluate_condition(
            "keywords and selection", detection, "cron: root modified crontab"
        )
        assert not SigmaEngine._evaluate_condition(
            "keywords and selection", detection, "cron: john modified crontab"
        )
        assert not SigmaEngine._evaluate_condition(
            "keywords and selection", detection, "root logged in"
        )

    def test_keywords_or_selection(self):
        detection = {
            "keywords": ["brute force"],
            "selection": {"source": "auth.log"},
            "condition": "keywords or selection",
        }
        assert SigmaEngine._evaluate_condition(
            "keywords or selection", detection, "brute force detected"
        )
        assert SigmaEngine._evaluate_condition(
            "keywords or selection", detection, "event from auth.log"
        )
        assert not SigmaEngine._evaluate_condition(
            "keywords or selection", detection, "normal event"
        )

    def test_selection_and_not_filter(self):
        detection = {
            "selection": {"command": "sudo"},
            "filter": {"user": "admin"},
            "condition": "selection and not filter",
        }
        assert SigmaEngine._evaluate_condition(
            "selection and not filter", detection, "sudo: hacker ran command"
        )
        assert not SigmaEngine._evaluate_condition(
            "selection and not filter", detection, "sudo: admin ran command"
        )

    def test_1_of_them(self):
        detection = {
            "selection1": ["failed password"],
            "selection2": ["invalid user"],
            "condition": "1 of them",
        }
        assert SigmaEngine._evaluate_condition(
            "1 of them", detection, "failed password for root"
        )
        assert SigmaEngine._evaluate_condition(
            "1 of them", detection, "invalid user nobody"
        )
        assert not SigmaEngine._evaluate_condition(
            "1 of them", detection, "login successful"
        )

    def test_all_of_them(self):
        detection = {
            "sel1": ["sudo"],
            "sel2": ["root"],
            "condition": "all of them",
        }
        assert SigmaEngine._evaluate_condition(
            "all of them", detection, "sudo: root ran command"
        )
        assert not SigmaEngine._evaluate_condition(
            "all of them", detection, "sudo: john ran command"
        )

    def test_1_of_prefix_wildcard(self):
        detection = {
            "selection_auth": ["failed password"],
            "selection_pam": ["pam_unix"],
            "filter": ["systemd"],
            "condition": "1 of selection_*",
        }
        assert SigmaEngine._evaluate_condition(
            "1 of selection_*", detection, "failed password for root"
        )
        assert SigmaEngine._evaluate_condition(
            "1 of selection_*", detection, "pam_unix session opened"
        )
        assert not SigmaEngine._evaluate_condition(
            "1 of selection_*", detection, "systemd started service"
        )

    def test_parentheses(self):
        detection = {
            "a": ["alpha"],
            "b": ["beta"],
            "c": ["gamma"],
            "condition": "(a or b) and c",
        }
        assert SigmaEngine._evaluate_condition(
            "(a or b) and c", detection, "alpha gamma"
        )
        assert SigmaEngine._evaluate_condition(
            "(a or b) and c", detection, "beta gamma"
        )
        assert not SigmaEngine._evaluate_condition(
            "(a or b) and c", detection, "alpha only"
        )


class TestEvaluateFullRule:
    """Test the full evaluate() method with a mock engine."""

    def _make_engine_with_rules(self, rules, tmp_path):
        """Create a SigmaEngine with pre-loaded rules (skip file loading)."""
        engine = SigmaEngine.__new__(SigmaEngine)
        engine.enabled = True
        engine.rules_dir = tmp_path
        engine._rules_data = rules
        return engine

    def test_ssh_brute_force_rule(self, tmp_path):
        rules = [
            {
                "file": "ssh_brute_force.yml",
                "title": "SSH Brute Force Detection",
                "level": "high",
                "description": "Detects multiple failed SSH attempts",
                "detection": {
                    "keywords": [
                        "Failed password",
                        "authentication failure",
                        "Invalid user",
                    ],
                    "condition": "keywords",
                },
            }
        ]
        engine = self._make_engine_with_rules(rules, tmp_path)

        alerts = engine.evaluate(
            {"line": "Feb 22 10:00:00 server sshd: Failed password for root from 1.2.3.4", "source": "auth.log"}
        )
        assert len(alerts) == 1
        assert alerts[0]["type"] == "SSH Brute Force Detection"
        assert alerts[0]["severity"] == "HIGH"

        alerts = engine.evaluate({"line": "Feb 22 10:00:00 server sshd: Accepted password for user"})
        assert len(alerts) == 0

    def test_crontab_modification_rule(self, tmp_path):
        rules = [
            {
                "file": "crontab_mod.yml",
                "title": "Suspicious Crontab Modification",
                "level": "high",
                "description": "Crontab changes",
                "detection": {
                    "keywords": ["CRON", "crontab", "REPLACE", "EDIT"],
                    "selection": ["root", "www-data", "nobody"],
                    "condition": "keywords and selection",
                },
            }
        ]
        engine = self._make_engine_with_rules(rules, tmp_path)

        alerts = engine.evaluate(
            {"line": "CRON: root REPLACE crontab entry"}
        )
        assert len(alerts) == 1

        # No match -- wrong user
        alerts = engine.evaluate(
            {"line": "CRON: john REPLACE crontab entry"}
        )
        assert len(alerts) == 0

    def test_no_condition_legacy_fallback(self, tmp_path):
        rules = [
            {
                "file": "legacy.yml",
                "title": "Legacy Rule",
                "level": "medium",
                "description": "No condition field",
                "detection": {
                    "keywords": ["error", "failure"],
                },
            }
        ]
        engine = self._make_engine_with_rules(rules, tmp_path)

        alerts = engine.evaluate({"line": "authentication failure"})
        assert len(alerts) == 1

    def test_disabled_engine_returns_empty(self, tmp_path):
        engine = self._make_engine_with_rules([], tmp_path)
        engine.enabled = False
        assert engine.evaluate({"line": "anything"}) == []
