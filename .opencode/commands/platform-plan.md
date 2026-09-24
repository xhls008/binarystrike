---
description: Generate a read-only host, eBPF, or CI/CD posture plan
agent: binary-security
subagent: false
---

Use `platform_plan` with `platform: linux-ebpf`, `cicd`, `macos`, or `windows`
and an explicit authorized `scope`. Use `focus` for one bounded step. The
command only produces an inventory plan; record results as blackboard Facts and
do not access credentials or change host controls.
