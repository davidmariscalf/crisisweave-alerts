from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


def _number(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def matches(event: dict[str, Any], rule: dict[str, Any]) -> tuple[bool, list[str]]:
    reasons: list[str] = []

    kinds = rule.get("kinds") or []
    if kinds and event.get("kind") not in kinds:
        return False, []
    if kinds:
        reasons.append(f"kind={event.get('kind')}")

    severity = _number(event.get("severity"), 0.0)
    min_severity = _number(rule.get("min_severity"), 0.0)
    if severity < min_severity:
        return False, []
    reasons.append(f"severity={severity:.3f}>={min_severity:.3f}")

    confidence = _number(event.get("confidence"), 0.0)
    min_confidence = _number(rule.get("min_confidence"), 0.0)
    if confidence < min_confidence:
        return False, []
    reasons.append(f"confidence={confidence:.3f}>={min_confidence:.3f}")

    if rule.get("official_only") and not bool(event.get("official")):
        return False, []
    if rule.get("official_only"):
        reasons.append("official=true")

    areas = [str(x).casefold() for x in (rule.get("area_contains") or [])]
    if areas:
        haystack = f"{event.get('area') or ''} {event.get('title') or ''} {event.get('description') or ''}".casefold()
        matched = [a for a in areas if a in haystack]
        if not matched:
            return False, []
        reasons.append("area=" + ",".join(matched))

    tags_any = set(rule.get("tags_any") or [])
    if tags_any:
        event_tags = set(event.get("tags") or [])
        overlap = sorted(tags_any & event_tags)
        if not overlap:
            return False, []
        reasons.append("tags=" + ",".join(overlap))

    return True, reasons


def alert_for(event: dict[str, Any], rule: dict[str, Any], reasons: list[str]) -> dict[str, Any]:
    rule_id = str(rule.get("id") or "rule")
    event_id = str(event.get("id") or "event")
    digest = hashlib.sha256(f"{rule_id}\x1f{event_id}".encode()).hexdigest()[:24]
    return {
        "fingerprint": digest,
        "rule_id": rule_id,
        "event_id": event_id,
        "title": event.get("title"),
        "kind": event.get("kind"),
        "severity": event.get("severity"),
        "confidence": event.get("confidence"),
        "official": bool(event.get("official")),
        "area": event.get("area"),
        "source": event.get("source"),
        "observed_at": event.get("observed_at"),
        "reasons": reasons,
    }


def evaluate(event: dict[str, Any], rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for rule in rules:
        ok, reasons = matches(event, rule)
        if ok:
            out.append(alert_for(event, rule, reasons))
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate CrisisWeave events against transparent alert rules")
    parser.add_argument("rules", help="JSON file containing a list of rules")
    args = parser.parse_args()

    rules = json.loads(Path(args.rules).read_text(encoding="utf-8"))
    if not isinstance(rules, list):
        raise SystemExit("rules file must contain a JSON array")

    for line in sys.stdin:
        if not line.strip():
            continue
        event = json.loads(line)
        for alert in evaluate(event, rules):
            print(json.dumps(alert, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
