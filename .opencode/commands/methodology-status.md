---
description: Inspect BinaryStrike progress without invoking a scheduler
agent: binary-security
subagent: false
---

Call `methodology_status` before choosing the next investigation branch. Treat
the result as an observational projection of the Fact/Intent/Hint graph,
coverage facts, and finding ledger—not as a mandatory phase order. Request
`include_validation: true` when reviewing pending triage or evidence quality.
