# BinaryStrike V1 → V2 capability matrix

The migration keeps OpenCode V2's server, session, database, and package
boundaries intact. V1 capabilities are either implemented through a V2 plugin
surface or explicitly deferred; no V1 global registry is copied into V2.

| V1 capability | V2 surface | Status | Notes |
| --- | --- | --- | --- |
| Binary metadata, strings, format triage | `analyze_binary` | Migrated | Project-confined, read-only first pass |
| RE tool planning | `binary_re_toolkit` | Migrated | Ghidra, IDA, Binary Ninja, radare2/Rizin, capa, YARA, JADX |
| Firmware triage | `analyze_firmware` | Migrated | Binwalk/EMBA/SBOM/filesystem plans; execution remains explicit |
| Dynamic debugging | `dynamic_debug` | Migrated | GDB, LLDB, strace/ltrace, Frida, Qiling plans |
| Symbolic exploration | `angr_explore` | Migrated | Generates a bounded angr harness; does not run the target |
| Raw request retest | `retest_request` | Migrated | Evidence is stored inside `.binarystrike/reports/` |
| Request/session observation catalog | `record_http_observation`, `get_http_observations`, `update_http_observation` | Migrated | Append-only project-local ledger replaces V1 RequestTable/session coupling; recording is passive |
| Scope validation | `scope_check` + retest `scope_items` | Migrated | Exact, wildcard, and IPv4 CIDR checks before active retests |
| Vulnerability report export | `export_report` | Migrated | V1 finding metadata, structured evidence, methodology snapshot, and derived chain candidates preserved |
| Vulnerability finding ledger/triage | `record_finding`, `get_findings`, `triage_finding` | Migrated | Append-only project ledger; similar candidates require explicit triage; optional `goal_id` links Hint → FGS Step → Fact |
| Methodology status/progress | `methodology_status` + `/methodology-status` | Migrated | Read-only projection from the Fact/Intent/Hint graph; no V1 scheduler or session database |
| Chain candidates | `get_chains` and `methodology_status.chains` | Migrated | Derived on demand from Intel/VRT graph edges; no persisted chain table or implicit dispatch |
| Intel/fact coordination | Fact/Goal/Step/Intent/Hint blackboard | Migrated | Append-only project graph replaces session-bound Intel DB; Goals and Steps externalize search state without a scheduler |
| Structured Intel entries | `record_intel`, `get_intel`, `update_intel` | Migrated | Type/asset/severity/confidence metadata is encoded as blackboard tags; low-confidence and vulnerability hints stay Hint nodes |
| Coverage notes and VRT verdicts | `record_coverage_note`, `get_coverage_notes`, `record_vrt_check` | Migrated | Tagged Fact entries with local/wide scope; VRT verdicts link to Intel and require evidence for vulnerable results |
| Memory files | Blackboard | Replaced | Durable evidence and coordination live in one graph |
| Recon and high-signal web methodology skills | V2 `.opencode/skills/` | Migrated (selected) | Recon, IDOR, SSRF, JWT, CORS, open redirect, request smuggling, XXE, and SSTI procedures are project-local skills; active network execution remains permission-gated |
| Full V1 7,300+ skill index and generated framework corpus | Reviewed V2 skill sources + `V1_SKILL_IMPORT_POLICY.md` | Policy-bound | The generated corpus remains source-only; each future import requires a V2 boundary, permission policy, and test |
| V1 server/database/session registries | OpenCode V2 core | Intentionally omitted | Avoids crossing V2 module boundaries |
| Cloud/Kubernetes post-exploitation hooks | `cloud_plan` + `cloud-readonly-planning` | Migrated (read-only) | AWS, Azure, and Kubernetes inventory/RBAC/logging plans only; no credential harvesting, secret reads, persistence, or mutation |
| eBPF, CI/CD, macOS, and Windows hooks | `platform_plan` + `platform-readonly-planning` | Migrated (read-only) | Kernel/runner/host posture plans only; no probes, credential access, bypasses, persistence, or log clearing |
| Web proxy, browser observation | `record_browser_observation` + request ledger | Migrated (passive) | Captured browser events are normalized into the same append-only ledger; no browser navigation or proxy interception is performed |
| V1 TUI and HTTP routes | OpenCode V2 CLI/server | Deferred | V2 client/server behavior remains upstream-owned |

Deferred capabilities must be migrated as project-local V2 plugins, commands,
skills, or MCP integrations rather than by importing V1 server modules.
