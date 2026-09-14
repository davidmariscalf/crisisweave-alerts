from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from pathlib import Path
from typing import Any

MAX_RULES = 1000
MAX_RULE_FILE_BYTES = 1024 * 1024
MAX_EVENT_LINE_CHARS = 2 * 1024 * 1024


def _score(value: Any) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(number) or not 0.0 <= number <= 1.0:
        return None
    return number


def _strict_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().casefold()
        if lowered in {"true", "yes", "1"}:
            return True
        if lowered in {"false", "no", "0"}:
            return False
    if isinstance(value, (int, float)) and value in {0, 1}:
        return bool(value)
    return None


def _norm_strings(value: Any, field: str, *, max_items: int = 100, max_chars: int = 256) -> list[str]:
    if value in (None, []):
        return []
    if not isinstance(value, list) or len(value) > max_items:
        raise ValueError(f"{field} must be a list with at most {max_items} entries")
    out = []
    for item in value:
        text = str(item or "").strip()
        if not text or len(text) > max_chars:
            raise ValueError(f"{field} contains an empty or oversized value")
        out.append(text)
    return out


def validate_rules(rules: Any) -> list[dict[str, Any]]:
    if not isinstance(rules, list):
        raise ValueError("rules file must contain a JSON array")
    if len(rules) > MAX_RULES:
        raise ValueError(f"rules file exceeds {MAX_RULES} rules")

    seen: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for index, raw in enumerate(rules):
        if not isinstance(raw, dict):
            raise ValueError(f"rule {index + 1} must be an object")
        rule_id = str(raw.get("id") or "").strip()
        if not rule_id or len(rule_id) > 128:
            raise ValueError(f"rule {index + 1} requires id <= 128 characters")
        if rule_id in seen:
            raise ValueError(f"duplicate rule id: {rule_id}")
        seen.add(rule_id)

        min_severity = _score(raw.get("min_severity", 0.0))
        min_confidence = _score(raw.get("min_confidence", 0.0))
        if min_severity is None:
            raise ValueError(f"rule {rule_id} min_severity must be finite and between 0 and 1")
        if min_confidence is None:
            raise ValueError(f"rule {rule_id} min_confidence must be finite and between 0 and 1")

        official_raw = raw.get("official_only", False)
        official_only = _strict_bool(official_raw)
        if official_only is None:
            raise ValueError(f"rule {rule_id} official_only must be boolean")

        normalized.append(
            {
                **raw,
                "id": rule_id,
                "kinds": [x.casefold() for x in _norm_strings(raw.get("kinds"), f"rule {rule_id} kinds", max_items=64, max_chars=64)],
                "min_severity": min_severity,
                "min_confidence": min_confidence,
                "official_only": official_only,
                "area_contains": [x.casefold() for x in _norm_strings(raw.get("area_contains"), f"rule {rule_id} area_contains", max_items=100, max_chars=256)],
                "tags_any": [x.casefold() for x in _norm_strings(raw.get("tags_any"), f"rule {rule_id} tags_any", max_items=100, max_chars=128)],
            }
        )
    return normalized


def matches(event: dict[str, Any], rule: dict[str, Any]) -> tuple[bool, list[str]]:
    if not isinstance(event, dict) or not str(event.get("id") or "").strip():
        return False, []

    reasons: list[str] = []

    kinds = rule.get("kinds") or []
    event_kind = str(event.get("kind") or "other").casefold()
    if kinds and event_kind not in kinds:
        return False, []
    if kinds:
        reasons.append(f"kind={event_kind}")

    severity = _score(event.get("severity"))
    min_severity = _score(rule.get("min_severity"))
    if severity is None or min_severity is None or severity < min_severity:
        return False, []
    reasons.append(f"severity={severity:.3f}>={min_severity:.3f}")

    confidence = _score(event.get("confidence"))
    min_confidence = _score(rule.get("min_confidence"))
    if confidence is None or min_confidence is None or confidence < min_confidence:
        return False, []
    reasons.append(f"confidence={confidence:.3f}>={min_confidence:.3f}")

    official = _strict_bool(event.get("official", False))
    if official is None:
        return False, []
    if rule.get("official_only") and not official:
        return False, []
    if rule.get("official_only"):
        reasons.append("official=true")

    areas = rule.get("area_contains") or []
    if areas:
        haystack = f"{event.get('area') or ''} {event.get('title') or ''} {event.get('description') or ''}".casefold()
        matched = [area for area in areas if area in haystack]
        if not matched:
            return False, []
        reasons.append("area=" + ",".join(sorted(matched)))

    tags_any = set(rule.get("tags_any") or [])
    if tags_any:
        raw_tags = event.get("tags") or []
        if not isinstance(raw_tags, list):
            return False, []
        event_tags = {str(tag).casefold() for tag in raw_tags if str(tag).strip()}
        overlap = sorted(tags_any & event_tags)
        if not overlap:
            return False, []
        reasons.append("tags=" + ",".join(overlap))

    return True, reasons


def alert_for(event: dict[str, Any], rule: dict[str, Any], reasons: list[str]) -> dict[str, Any]:
    rule_id = str(rule["id"])
    event_id = str(event["id"])
    digest = hashlib.sha256(f"{rule_id}\x1f{event_id}".encode()).hexdigest()[:24]
    return {
        "fingerprint": digest,
        "rule_id": rule_id,
        "event_id": event_id,
        "title": event.get("title"),
        "kind": event.get("kind"),
        "severity": _score(event.get("severity")),
        "confidence": _score(event.get("confidence")),
        "official": bool(_strict_bool(event.get("official", False))),
        "area": event.get("area"),
        "source": event.get("source"),
        "observed_at": event.get("observed_at"),
        "reasons": list(reasons),
    }


def evaluate(event: dict[str, Any], rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for rule in rules:
        ok, reasons = matches(event, rule)
        if ok:
            out.append(alert_for(event, rule, reasons))
    return out


def _load_rules(path: str) -> list[dict[str, Any]]:
    rule_path = Path(path)
    if rule_path.stat().st_size > MAX_RULE_FILE_BYTES:
        raise ValueError(f"rules file exceeds {MAX_RULE_FILE_BYTES} bytes")
    return validate_rules(json.loads(rule_path.read_text(encoding="utf-8")))


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate CrisisWeave events against transparent alert rules")
    parser.add_argument("rules", help="JSON file containing a list of rules")
    args = parser.parse_args()

    try:
        rules = _load_rules(args.rules)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(str(exc)) from exc

    for number, line in enumerate(sys.stdin, 1):
        if len(line) > MAX_EVENT_LINE_CHARS:
            raise SystemExit(f"stdin line {number} exceeds {MAX_EVENT_LINE_CHARS} characters")
        if not line.strip():
            continue
        event = json.loads(line)
        for alert in evaluate(event, rules):
            print(json.dumps(alert, ensure_ascii=False, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
