---
description: Execute one authorized BinaryStrike FGS step and submit its fact
agent: binary-security-execute
subagent: false
---

Read the graph with `fgs_read`, select one active authorized Step, perform only
that bounded action, and call `submit_fact` with the Step ID and evidence. Do
not create an unbounded workflow or promote hypotheses without provenance.
