---
description: Export a BinaryStrike finding report
agent: binary-security
subagent: false
---

Review the evidence and findings in this session. Use `record_finding` to persist each candidate, compare the returned similar candidates, and use `triage_finding` to approve a distinct finding or link a duplicate. Then export a durable report with `export_report` using `finding_ids`. Use `confirmed`, `likely`, or `unverified` confidence labels and do not promote hypotheses to vulnerabilities.

Include request, response, and artifact evidence as structured `evidence` entries when it is available. Keep each entry tied to a stable identifier so the exporter can persist it under the report directory.
