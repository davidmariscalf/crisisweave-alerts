# crisisweave-alerts

Transparent rule evaluation for CrisisWeave events.

This module intentionally separates **detection** from **delivery**. It decides whether an event matches a user-defined rule and emits alert objects. Email/SMS/push delivery can then be attached by a deployment without hiding the matching logic inside a vendor service.

## Rule example

```json
[
  {
    "id": "severe-flood",
    "kinds": ["flood"],
    "min_severity": 0.7,
    "min_confidence": 0.75,
    "official_only": false,
    "area_contains": ["Madrid", "Valencia"]
  }
]
```

## Run

```bash
cat verified.jsonl | python alerts.py rules.json > alerts.jsonl
```

Each emitted alert includes the matching rule ID, event ID and a stable fingerprint that downstream delivery systems can use for deduplication.

## Safety

Rules are decision-support filters, not evacuation or rescue orders. Production deployments should preserve links to the original source and distinguish official instructions from CrisisWeave-generated notifications.

## Freshness-aware rules

Rules may include `max_age_hours`. When a rule uses it, the evaluator requires a valid `observed_at` and rejects reports older than the configured window. Expired events are also rejected when an evaluation time is supplied. The CLI evaluates against the current UTC time by default and accepts `--as-of <ISO-8601>` for deterministic drills and tests. Alert records carry the incident's evidence and verification context forward so downstream users can inspect why corroboration and confidence exist instead of seeing only a threshold result.
