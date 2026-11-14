# Technical Report: SOC Alert Deduplication and Triage System

## 1. Objective
Build a defensive tool that processes synthetic security alerts, groups repeated events, assigns severity, and provides non-destructive analyst recommendations.

## 2. Problem
Security monitoring systems can generate repeated alerts for the same underlying activity. Repetition increases alert noise and can make analyst prioritization harder.

## 3. Design
The Python CLI loads JSON alerts and JSON detection rules. It groups alerts using the combination of event type, source IP, username, and host. It assigns the configured severity and keeps the earliest and latest timestamps and occurrence count.

## 4. Severity model
- Critical: suspected malware detection; immediate escalation for human review.
- High: burst of failed logins, suspicious PowerShell, or unexpected privileged-account creation.
- Medium: fallback severity for unknown event types.
- Low: ordinary successful login event.

Severity is a prioritization aid, not proof of compromise.

## 5. Non-destructive response
The tool only recommends review, log preservation, validation, and escalation. It does not block addresses, disable accounts, delete files, or modify endpoints.

## 6. Testing
The test matrix covers duplicate grouping, separation of different sources, severity assignment, safe recommendations, and output generation. Automated unit tests are included.

## 7. Limitations
The dataset is synthetic. Deduplication uses exact matching fields and a simple rule map. A production system would need time-window correlation, trusted asset/user context, authentication, audit logging, and integration testing.

## 8. References
- Wazuh documentation: https://documentation.wazuh.com/current/
- MITRE ATT&CK: https://attack.mitre.org/
- Sigma: https://sigmahq.io/
- NIST SP 800-61 Rev. 2: https://csrc.nist.gov/pubs/sp/800/61/r2/final
