---
description: Review project-local HTTP observations
agent: binary-security
subagent: false
---

Use `get_http_observations` to inspect the bounded request catalog. Use
`include_body: true` only when the raw request or response is needed. Capture
browser/proxy observations with `record_http_observation`; it never sends a
request. Pass `scope_items` when recording data from an authorized target.
