---
name: platform-readonly-planning
description: Plan authorized Linux eBPF, CI/CD, macOS, and Windows posture reviews without active host changes
category: platform-security
version: "1.0"
---

# Platform Read-only Planning

Use `platform_plan` to generate a bounded posture and inventory plan for
`linux-ebpf`, `cicd`, `macos`, or `windows`. The tool returns commands and
evidence expectations only; it never runs them, attaches eBPF probes, starts a
CI job, accesses credential stores, patches security controls, or clears logs.

Declare the authorized host, repository, or CI scope. Treat collected metadata
as project evidence: write sourced observations as Facts, unresolved exposure
indicators as Hints, and bounded follow-up checks as Intents.

The V1 eBPF and host hooks that capture credentials, keys, process memory,
keystrokes, or bypass security controls are intentionally not imported. Any
active instrumentation requires an independently reviewed permissioned slice.
