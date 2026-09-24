---
name: browser-observation
description: Import captured browser network events as passive, scope-checked HTTP observations
category: web-observation
version: "1.0"
---

# Browser Observation

Use `record_browser_observation` when a browser, proxy, or DevTools capture has
already produced a request/response event. The adapter only normalizes the
event into `.binarystrike/requests/events.jsonl`; it never navigates, injects,
replays, or intercepts browser traffic.

Provide an explicit `scope_items` list for authorized targets. Keep response
bodies bounded and redact cookies, authorization headers, tokens, and other
secrets before recording. Use `get_http_observations` to review the shared
ledger and link relevant records to blackboard Facts or finding Hints.

Active replay must use `retest_request`, after a separate scope check and
explicit permission. A captured event is evidence of an observation, not proof
of exploitability.
