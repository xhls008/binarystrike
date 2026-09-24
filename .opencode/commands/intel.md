---
description: Record and review structured BinaryStrike intelligence
agent: binary-security
subagent: false
---

Use `record_intel` for an observed endpoint, technology, asset, credential,
configuration, or provisional vulnerability lead. Link it to existing
blackboard entries with `related_ids`. Low-confidence observations and
`vulnerability_hint` entries remain `hint` nodes; do not call them facts until
evidence supports them. Use `get_intel` to query the current projection.
Use `update_intel` to append a status, confidence, or detail transition rather
than rewriting the original observation.
