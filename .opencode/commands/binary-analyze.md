---
description: Run first-pass binary vulnerability analysis
agent: binary-security
---

Analyze the authorized binary at $ARGUMENTS. Start with `analyze_binary`, then use the relevant firmware, reverse-engineering, dynamic-debugging, or symbolic-exploration tools when the first-pass result justifies them. Preserve evidence and clearly separate confirmed, likely, and unverified findings.

The first pass records the file hash, format, architecture, printable strings, risky API indicators, embedded-secret indicators, and available local tooling. It is triage only: use `binary_re_toolkit`, `dynamic_debug`, or the `decompileai-lite` and `dynamic-debugging` skills for follow-up evidence instead of treating indicators as vulnerabilities.
