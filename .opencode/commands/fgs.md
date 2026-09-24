---
description: Inspect and evolve the Fact-Goal-Step search graph
agent: binary-security
subagent: false
---

Use `fgs_read` before choosing work. `fgs_create_goal` records a completion
condition, and `fgs_add_step` records a prioritized candidate action under that
Goal; neither tool executes work. After Execute performs an authorized Step,
use `submit_fact` with the Step ID and evidence source. Update lifecycle state
explicitly with `fgs_update_step` or `fgs_update_goal`. The graph is external
memory and causal history, not an automatic scheduler.
