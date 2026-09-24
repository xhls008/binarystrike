---
description: Generate a read-only cloud or Kubernetes inventory plan
agent: binary-security
subagent: false
---

Use `cloud_plan` with `provider: aws`, `azure`, or `kubernetes` and an explicit
authorized `scope`. Start with the complete plan, then use `focus` for one
bounded step. The command only produces commands and evidence guidance; it
does not execute them. Record results as blackboard Facts and unresolved leads
as Hints before proposing verification Intents.
