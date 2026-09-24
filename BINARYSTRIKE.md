# BinaryStrike on OpenCode V2

This branch keeps OpenCode `v2.0.15` as the upstream base and adds BinaryStrike as a native V2 product layer instead of carrying the old V1 fork forward.

## What moved

- Binary analysis lives in `packages/binarystrike` and is exposed through the V2 plugin API.
- The server plugin at `.opencode/plugins/binarystrike.ts` registers:
  - `analyze_binary`
  - `binary_re_toolkit`
  - `analyze_firmware`
  - `cloud_plan` for read-only AWS, Azure, and Kubernetes inventory/RBAC/logging plans
  - `platform_plan` for read-only Linux eBPF, CI/CD, macOS, and Windows posture plans
  - `dynamic_debug`
  - `angr_explore`
  - `export_report`
  - `record_finding`, `get_findings`, and `triage_finding`
  - `fgs_read`, `fgs_create_goal`, `fgs_add_step`, `fgs_update_goal`, `fgs_update_step`, and `submit_fact`
  - `methodology_status` for a read-only progress/coverage projection
  - `get_chains` for read-only graph-derived attack-chain candidates
  - `record_intel`, `get_intel`, and `update_intel` for structured observations projected into the blackboard
  - `retest_request`
  - `record_http_observation`, `get_http_observations`, and `update_http_observation` for passive project-local request observations
  - `record_browser_observation` to normalize captured browser network events into the same passive request ledger
  - `blackboard_write`, `blackboard_read`, and `blackboard_update`
  - `record_coverage_note` and `get_coverage_notes`
  - `record_vrt_check` for evidence-backed tested-vulnerable/clean verdicts
  - `scope_check` for explicit domain/wildcard/CIDR authorization checks
- `binary-security` is a V2 file-based primary/subagent with native permission rules.
- `binary-security-decide` and `binary-security-execute` provide explicit FGS graph-only and bounded execution activities; neither activity owns hidden cross-session memory.
- `/binary-analyze`, `/binary-report`, `/methodology-status`, `/intel`, `/chains`, and `/requests` are V2 file-based commands.
- Dynamic debugging and DecompileAI Lite/AIDA methodology are V2 skills under `.opencode/skills/`.
- Cloud/Kubernetes post-exploitation is represented by the read-only `cloud_plan` boundary and `cloud-readonly-planning` skill; mutation, secret extraction, persistence, and credential-harvesting hooks are not imported from V1.
- eBPF, CI/CD, macOS, and Windows post-exploitation is represented by the read-only `platform_plan` boundary and `platform-readonly-planning` skill; active probes, credential access, bypasses, and persistence are not imported from V1.
- A reviewed subset of the V1 methodology corpus (recon, IDOR, SSRF, JWT, CORS, open redirect, request smuggling, XXE, and SSTI) is now available as V2 skills. The full generated V1 skill corpus is intentionally not copied until it has a versioned import policy.
- The migrated `bun-file-io` skill documents project confinement and bounded Bun-based artifact I/O for new tools.
- Reverse-engineering MCP servers are configured with the V2 `mcp.servers` shape and remain disabled by default.
- Reports and retests persist under `.binarystrike/reports/` inside the active project; reports include the current methodology projection and derived chain candidates.
- Fact, intent, and hint coordination persists as an append-only graph under `.binarystrike/blackboard/`.
- FGS coordination adds explicit Goal and prioritized Step nodes plus `submit_fact`; the graph is external memory and causal history, not an automatic scheduler.
- Finding candidates are projected into that graph as unverified hints; opening a candidate with an explicit `goal_id` also creates a linked FGS verification Step. Approval then submits a Fact parented by that Step (while retaining the compatibility Intent). Duplicate, fixed, and ignored transitions close the linked work without silently claiming evidence. This keeps findings, evidence, and next actions in one causal context while retaining the report-oriented finding ledger.

### Finding → Hint/Intent/Fact lifecycle

The finding ledger is a report-oriented projection; the blackboard is the shared
coordination graph. `record_finding` always appends a `new` candidate and creates
an unverified **Hint** (even when no similar candidate exists). Triage is explicit:

| Finding transition | Blackboard effect |
| --- | --- |
| `open` | Add a linked FGS **Step** when `goal_id` is supplied (plus a compatibility **Intent**); mark work active. |
| `approved` | Complete linked work and append a high-confidence **Fact** parented by the Step when present. |
| `duplicate` | Link to `duplicate_of`, reject the Intent, supersede the Hint. |
| `ignored` | Reject the Intent without creating a Fact. |
| `fixed` | Complete the Intent and supersede any previous Fact. |

All writes are append-only events under `.binarystrike/`; no candidate is
silently discarded by similarity matching, and pending/confirmed states are
injected as untrusted context rather than scheduler instructions.

## V2 migration decisions

- The V1 plugin map and global tool registry are gone. Tools now register through `ctx.tool.transform`.
- The project plugin is a server-only standalone `.opencode/plugins/binarystrike.ts` entrypoint, matching OpenCode V2 discovery rules; it is not a V1 directory plugin or TUI plugin.
- File paths are resolved against `ctx.location.directory` and confined to that project.
- Raw HTTP retests are passed explicitly to the V2 tool instead of depending on the V1 request database.
- Report generation accepts structured findings and evidence artifacts at the tool boundary instead of reading V1 vulnerability tables.
- Finding metadata preserves V1 report context (endpoint, attack vector, source lines, PoC, and business impact) without importing the V1 database.
- The blackboard replaces V1 session-bound intelligence coupling with explicit project-local context and causal links.
- Blackboard, finding, methodology, and request snapshots are injected as marked ordinary user messages (not system instructions); the plugin uses private message metadata for idempotence so project text cannot spoof the context guard.
- The upstream OpenCode CLI and server remain unchanged, which reduces future merge conflict surface.

## Development

```bash
bun install
cd packages/binarystrike
bun test --timeout 30000
bun run typecheck
cd ../cli
bun src/index.ts serve
```

OpenCode V2 requires Bun `1.4.2`, matching this branch's `packageManager` field. In an installed client, run OpenCode from the target project and select the agent with `opencode run --agent binary-security` or invoke `@binary-security` from a session.

BinaryStrike is an independent security project built on OpenCode. It is not built by or affiliated with the OpenCode team.

See [`V1_V2_CAPABILITY_MATRIX.md`](V1_V2_CAPABILITY_MATRIX.md) for the
current migration boundary and [`V1_SKILL_IMPORT_POLICY.md`](V1_SKILL_IMPORT_POLICY.md)
for the reviewed skill import rules.
