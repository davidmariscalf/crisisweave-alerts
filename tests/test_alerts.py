import math
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from alerts import (
    MAX_EVENT_LINE_CHARS,
    _load_rules,
    evaluate,
    matches,
    parse_event_line,
    validate_rules,
)


class AlertTests(unittest.TestCase):
    def event(self, **overrides):
        base = {
            "id": "e1",
            "kind": "flood",
            "title": "Flood",
            "description": "Water rising",
            "severity": 0.9,
            "confidence": 0.8,
            "official": False,
            "area": "Madrid",
            "tags": ["river"],
            "source": {"name": "test"},
        }
        base.update(overrides)
        return base

    def rule(self, **overrides):
        base = {
            "id": "r1",
            "kinds": ["flood"],
            "min_severity": 0.7,
            "min_confidence": 0.7,
            "area_contains": ["Madrid"],
        }
        base.update(overrides)
        return validate_rules([base])[0]

    def test_normal_match(self):
        out = evaluate(self.event(), [self.rule()])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["rule_id"], "r1")

    def test_nan_and_infinity_do_not_pass_thresholds(self):
        for value in (math.nan, math.inf, -math.inf):
            with self.subTest(value=value):
                ok, _ = matches(self.event(severity=value), self.rule())
                self.assertFalse(ok)
                ok, _ = matches(self.event(confidence=value), self.rule())
                self.assertFalse(ok)

    def test_string_false_does_not_pass_official_only(self):
        rule = self.rule(official_only=True)
        ok, _ = matches(self.event(official="false"), rule)
        self.assertFalse(ok)
        ok, _ = matches(self.event(official="true"), rule)
        self.assertTrue(ok)

    def test_duplicate_rule_ids_are_rejected(self):
        with self.assertRaises(ValueError):
            validate_rules([{"id": "same"}, {"id": "same"}])

    def test_missing_rule_id_is_rejected(self):
        with self.assertRaises(ValueError):
            validate_rules([{"min_severity": 0.5}])

    def test_invalid_rule_threshold_is_rejected(self):
        with self.assertRaises(ValueError):
            validate_rules([{"id": "bad", "min_severity": 2}])

    def test_matching_is_case_insensitive_for_kind_tags_and_area(self):
        rule = validate_rules([
            {
                "id": "r2",
                "kinds": ["FLOOD"],
                "tags_any": ["RIVER"],
                "area_contains": ["MADRID"],
            }
        ])[0]
        ok, reasons = matches(self.event(kind="Flood", tags=["River"], area="madrid"), rule)
        self.assertTrue(ok)
        self.assertTrue(any(reason.startswith("tags=") for reason in reasons))

    def test_max_age_rule_blocks_stale_report(self):
        as_of = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
        rule = self.rule(max_age_hours=2)
        stale = self.event(observed_at="2026-01-01T08:00:00Z")
        fresh = self.event(observed_at="2026-01-01T11:30:00Z")
        self.assertFalse(matches(stale, rule, as_of=as_of)[0])
        ok, reasons = matches(fresh, rule, as_of=as_of)
        self.assertTrue(ok)
        self.assertTrue(any(reason.startswith("age_hours=") for reason in reasons))

    def test_expired_event_does_not_alert(self):
        as_of = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
        event = self.event(
            observed_at="2026-01-01T11:30:00Z",
            expires_at="2026-01-01T11:45:00Z",
        )
        self.assertEqual(evaluate(event, [self.rule()], as_of=as_of), [])

    def test_alert_preserves_verification_context(self):
        event = self.event(
            evidence=[{"source": "Agency A", "event_id": "a"}],
            verification={"report_count": 2, "confidence_note": "ranking signal, not probability of truth"},
        )
        out = evaluate(event, [self.rule()])
        self.assertEqual(out[0]["evidence"][0]["event_id"], "a")
        self.assertEqual(out[0]["verification"]["report_count"], 2)

    def test_fingerprint_is_idempotent(self):
        rules = [self.rule()]
        first = evaluate(self.event(), rules)
        second = evaluate(self.event(), rules)
        self.assertEqual(first, second)

    def test_cli_parser_rejects_non_object_records(self):
        with self.assertRaises(ValueError):
            parse_event_line('["not", "an", "event"]', 1)

    def test_cli_parser_rejects_non_standard_json_constants(self):
        with self.assertRaises(ValueError):
            parse_event_line('{"id":"e1","severity":NaN}', 1)

    def test_cli_parser_rejects_oversized_line(self):
        with self.assertRaises(ValueError):
            parse_event_line("x" * (MAX_EVENT_LINE_CHARS + 1), 7)

    def test_rule_loader_rejects_non_standard_json_constants(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rules.json"
            path.write_text('[{"id":"r1","min_severity":NaN}]', encoding="utf-8")
            with self.assertRaises(ValueError):
                _load_rules(str(path))


if __name__ == "__main__":
    unittest.main()
