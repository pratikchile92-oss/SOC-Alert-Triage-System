# SOC Alert Triage System

A beginner-friendly defensive security project that reads synthetic alerts, groups duplicates, assigns severity, and recommends safe, non-destructive response actions.

## Requirements
- Python 3.9+
- No third-party packages required

## Run
Open this folder in VS Code, open Terminal, and run:

```bash
python soc_triage.py
```

To run tests:

```bash
python -m unittest discover -s tests -v
```

## What it does
- Reads `data/synthetic_alerts.json`
- Deduplicates events using alert type + source IP + username + host
- Assigns severity using `rules/detection_rules.json`
- Prints triage results and safe recommendations
- Writes `outputs/triage_output.json` and `outputs/incident_timeline.md`

## Safety
This tool is analysis-only. It does not block IPs, disable accounts, delete files, kill processes, or change systems. Recommendations are for an authorized analyst to review.

## Project deliverables
- Synthetic dataset: `data/synthetic_alerts.json`
- Detection rules: `rules/detection_rules.json`
- Runnable CLI: `soc_triage.py`
- Sample output: `outputs/sample_alert_output.txt`
- Test matrix: `tests/test_matrix.md`
- Automated tests: `tests/test_soc_triage.py`
- Incident timeline: `outputs/incident_timeline.md`
- Technical report: `technical_report.md`
- Learning journal: `learning_journal.md`
- Demo video: Record the terminal run and upload it; add the link below.

## Demo video
Add your video link here: `PASTE_DEMO_VIDEO_LINK`

## References
- Wazuh: https://documentation.wazuh.com/current/
- MITRE ATT&CK: https://attack.mitre.org/
- Sigma: https://sigmahq.io/
- NIST SP 800-61 Rev. 2: https://csrc.nist.gov/pubs/sp/800/61/r2/final
