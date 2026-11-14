import json
from collections import defaultdict
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).resolve().parent
DATA_FILE = BASE_DIR / "data" / "synthetic_alerts.json"
RULE_FILE = BASE_DIR / "rules" / "detection_rules.json"
OUTPUT_DIR = BASE_DIR / "outputs"


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def dedup_key(alert):
    # Repeated events with the same signal and same entities are grouped.
    return (
        alert.get("event_type", "unknown"),
        alert.get("source_ip", "unknown"),
        alert.get("username", "unknown"),
        alert.get("host", "unknown"),
    )


def severity_for(alert, rules):
    event_type = alert.get("event_type", "")
    rule = rules.get(event_type, {})
    return rule.get("severity", "Medium")


def recommendation_for(alert, severity):
    suggestions = {
        "Low": "Review the event and keep it under routine monitoring.",
        "Medium": "Review related authentication or endpoint logs; verify whether activity is expected.",
        "High": "Prioritize analyst review; validate the account, source IP, and affected host.",
        "Critical": "Escalate to the incident-response lead immediately; preserve relevant logs and investigate scope.",
    }
    return suggestions.get(severity, "Send to an analyst for manual review.")


def run_triage(alerts, rules):
    groups = defaultdict(list)
    for alert in alerts:
        groups[dedup_key(alert)].append(alert)

    results = []
    for key, events in groups.items():
        # Use the highest severity represented by the configured rule.
        rank = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
        representative = events[-1]
        severity = max((severity_for(a, rules) for a in events), key=lambda s: rank.get(s, 0))
        results.append({
            "alert_id": representative.get("alert_id", "N/A"),
            "event_type": representative.get("event_type", "unknown"),
            "source_ip": representative.get("source_ip", "unknown"),
            "username": representative.get("username", "unknown"),
            "host": representative.get("host", "unknown"),
            "severity": severity,
            "occurrences": len(events),
            "first_seen": min(a.get("timestamp", "") for a in events),
            "last_seen": max(a.get("timestamp", "") for a in events),
            "recommendation": recommendation_for(representative, severity),
            "response_mode": "Recommendation only - no system changes performed",
        })
    return sorted(results, key=lambda x: ({"Critical": 0, "High": 1, "Medium": 2, "Low": 3}.get(x["severity"], 4), x["first_seen"]))


def write_outputs(results):
    OUTPUT_DIR.mkdir(exist_ok=True)
    with open(OUTPUT_DIR / "triage_output.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    lines = ["# Incident Timeline", "", "Generated from the synthetic alert dataset.", ""]
    for item in sorted(results, key=lambda x: x["first_seen"]):
        lines += [
            f"## {item['first_seen']} – {item['event_type']}",
            f"- Severity: **{item['severity']}**",
            f"- Entity: `{item['username']}` on `{item['host']}` from `{item['source_ip']}`",
            f"- Repeated events grouped: **{item['occurrences']}**",
            f"- Analyst recommendation: {item['recommendation']}",
            ""
        ]
    lines += ["## Analyst note", "This is synthetic data. Recommendations are non-destructive and require human validation."]
    (OUTPUT_DIR / "incident_timeline.md").write_text("\n".join(lines), encoding="utf-8")

    with open(OUTPUT_DIR / "sample_alert_output.txt", "w", encoding="utf-8") as f:
        f.write("SOC ALERT TRIAGE SUMMARY\n")
        f.write("========================\n")
        f.write(f"Unique alert groups: {len(results)}\n\n")
        for item in results:
            f.write(f"[{item['severity']}] {item['event_type']} | {item['source_ip']} | user={item['username']} | host={item['host']} | repeats={item['occurrences']}\n")
            f.write(f"Recommendation: {item['recommendation']}\n\n")


def main():
    alerts = load_json(DATA_FILE)
    rules = load_json(RULE_FILE)
    results = run_triage(alerts, rules)
    write_outputs(results)

    print("\n=== SOC ALERT TRIAGE SYSTEM ===")
    print(f"Input events: {len(alerts)}")
    print(f"Unique alert groups after deduplication: {len(results)}")
    print("\n--- TRIAGED ALERTS ---")
    for item in results:
        print(f"\n[{item['severity']}] {item['event_type']} ({item['occurrences']} occurrence(s))")
        print(f"Source: {item['source_ip']} | User: {item['username']} | Host: {item['host']}")
        print(f"Recommendation: {item['recommendation']}")
        print(item["response_mode"])
    print("\nFiles created: outputs/triage_output.json, outputs/incident_timeline.md, outputs/sample_alert_output.txt")


if __name__ == "__main__":
    main()
