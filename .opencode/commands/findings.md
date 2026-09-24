---
description: Review and triage BinaryStrike finding candidates
agent: binary-security
subagent: false
---

Use `get_findings` to inspect the project-local finding ledger and
`blackboard_read` to inspect its causal context. `record_finding` also writes
the candidate as an unverified blackboard `hint`; it is not evidence yet.
Compare similar candidates before deciding. If a relevant FGS Goal exists,
pass its `goal_id` when recording the candidate. Use `triage_finding` with
`status: open` to create a linked FGS verification `step` (and compatibility
`intent`), `status: approved` for a distinct, evidenced finding (completes the
step and promotes the candidate to a blackboard `fact`), or `status: duplicate`
plus `duplicate_of` for the same issue. `fixed` and `ignored` close linked work
without claiming a vulnerability. Findings are never deleted. Export selected
records with `export_report` and their `finding_ids`.
