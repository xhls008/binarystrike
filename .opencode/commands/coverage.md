---
description: Review BinaryStrike coverage notes before testing
agent: binary-security
subagent: false
---

Query project-local coverage facts with `get_coverage_notes` before starting a
new vulnerability-class branch. After an authorized test reaches a verdict,
record the result with `record_coverage_note`, including clean results. Keep
`scope: wide` for deployment/account/host-wide conclusions and `scope: local`
for one asset.

When a note belongs to a structured Intel entry, prefer `record_vrt_check` and
link it with `intel_id`. A `tested_vulnerable` verdict must include evidence;
clean and not-applicable verdicts are also retained as Facts.
