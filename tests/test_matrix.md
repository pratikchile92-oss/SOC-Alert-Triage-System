# Test Matrix

| Test ID | Scenario | Expected result | Status |
|---|---|---|---|
| T01 | Three matching failed-login events | One group with 3 occurrences | Pass |
| T02 | Same event but different source IP | Separate alert groups | Pass |
| T03 | Malware detection | Critical severity | Pass |
| T04 | Successful login | Low severity | Pass |
| T05 | Alert recommendation | Advisory only; no host/account changes | Pass |
| T06 | Output generation | JSON, TXT and timeline files created | Pass |

Run automated tests with `python -m unittest discover -s tests -v`.
