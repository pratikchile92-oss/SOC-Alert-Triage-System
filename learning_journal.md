# Learning Journal

## Session 1 – Project setup
I learned how a Python CLI project is organized and how JSON can be used as a simple synthetic alert dataset.

## Session 2 – Alert deduplication
I learned that repeated alerts can be grouped using common fields such as event type, source IP, username, and host. The occurrence count helps show how often the event repeated.

## Session 3 – Severity and triage
I learned to map alert types to severity levels using detection rules. Severity helps analysts prioritize investigation but does not independently confirm an incident.

## Session 4 – Safe response
I learned the difference between a recommendation and an automated response. This project is non-destructive and leaves decisions to a human analyst.

## Session 5 – Testing and improvements
I tested duplicate grouping, severity, and safe recommendations. Future improvements could include time-window correlation, a dashboard, Wazuh alert ingestion, and Sigma rule parsing.
