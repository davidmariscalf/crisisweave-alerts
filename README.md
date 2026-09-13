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
