---
description: Inspect graph-derived BinaryStrike attack-chain candidates
agent: binary-security
subagent: false
---

Use `get_chains` after recording related Intel and VRT facts. Treat each result
as a hypothesis and write an explicit blackboard `intent` before testing it;
chain detection never dispatches work or promotes a candidate to a finding.
