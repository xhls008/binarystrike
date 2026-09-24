# BinaryStrike V2 migration

## Reference

OpenCode V2 is kept as a clean reference clone at:

```text
/home/flybear/flybear_data/llm_tools/ref/opencode-v2-source
```

The reference is currently `v2.0.15` (`6f3639d82`). BinaryStrike V2 must preserve
the upstream package boundaries and add security behavior through the supported
plugin, command, and skill surfaces.

## Target

Move BinaryStrike capabilities from the V1 runtime into native OpenCode V2
surfaces without copying the V1 server, database, session, or global tool
registries into the V2 tree.

## Migration order

1. **V2 foundation — complete**
   - `packages/binarystrike` workspace package
   - V2 plugin registration through `ctx.tool.transform`
   - binary, firmware, dynamic-debugging, and angr planning tools
   - report export and authorized request retest tools
   - file-based agent, commands, and focused skills
2. **Evidence and workflow parity — in progress**
   - report export now accepts structured request, response, and artifact evidence
     and stores each artifact under the project report directory
   - finding metadata includes endpoint, attack vector, source lines, PoC, and
     business impact fields from the V1 vulnerability model
   - continue adding fixture-driven tests for path confinement and tool plans
   - keep execution opt-in and permission-scoped
3. **Blackboard coordination — started**
   - project-local append-only Fact / Intent / Hint event stream
   - explicit FGS Goal / Step nodes, Decide graph-only activity, Execute bounded activity, and `submit_fact` world-state commits
   - current graph snapshots with parent edges and chronological history
   - V2 read, write, and update tools with explicit permissions
   - binary-security context hook injects a bounded, untrusted blackboard snapshot before model dispatch
   - context snapshots use ordinary user messages plus private metadata for idempotence; project data never becomes a system instruction
   - focused tests for causal links, lifecycle updates, orphan rejection, and cycle prevention
   - report export validates every referenced blackboard ID before writing an artifact
   - V1 coverage notes now map to tagged Fact entries with wide/local scope and duplicate suppression
   - V1 vulnerability recording and triage now use an append-only project finding ledger
   - finding candidates are projected as unverified Hint nodes; supplying an explicit `goal_id` and opening a candidate appends a linked FGS Step (plus the compatibility Intent), approval completes the Step and appends a linked Fact, while duplicate/fixed/ignored triage closes the linked work without claiming evidence
   - `methodology_status` provides a read-only phase, coverage, finding, graph, and validation projection without persisting scheduler state
   - V1 chain candidates are now derived on demand from Intel/VRT graph edges through `get_chains`; no chain table or implicit dispatch is copied
   - structured V1 Intel fields now use `record_intel`/`get_intel` as a tagged Fact/Hint projection with causal parent links
   - VRT-style verdicts now use `record_vrt_check` and append causal coverage facts; vulnerable verdicts require evidence
   - V1 scope checks now support exact hosts, wildcard domains, and IPv4 CIDRs; retests can enforce `scope_items`
   - passive request observations now use an append-only `.binarystrike/requests/events.jsonl` ledger with bounded context injection; no RequestTable or session ID is copied
4. **Operational capability migration**
   - migrate selected V1 skills and helper scripts as V2 skills/tools (recon plus IDOR, SSRF, JWT, CORS, open redirect, request smuggling, XXE, and SSTI procedures are now project-local V2 skills)
   - cloud/Kubernetes hooks now have a safe `cloud_plan` read-only planning surface for AWS, Azure, and Kubernetes inventory, authorization, and logging posture; V1 mutation/post-exploitation hooks remain intentionally excluded
   - eBPF, CI/CD, macOS, and Windows hooks now have a safe `platform_plan` read-only posture surface; V1 credential capture, probes, bypasses, persistence, and log-clearing programs remain intentionally excluded
   - browser captures now have a passive `record_browser_observation` adapter into the request ledger; browser navigation, proxy interception, and active replay remain permissioned boundaries
   - coverage notes are now implemented as project-local tagged blackboard facts
   - replace V1 session/database coupling with project-local artifacts
5. **Release hardening**
   - run package checks and the repository check
   - verify the plugin from a clean OpenCode V2 checkout (standalone server discovery is verified with `bun run --cwd packages/cli src/index.ts plugin list --builtin`; a root-launched V2 server with Bun 1.4.2 and `--jsx-import-source=@opentui/solid` served `/api/skill` and exposed all 12 BinaryStrike project skills)
   - document any intentionally omitted V1 behavior (including the versioned skill import policy in `V1_SKILL_IMPORT_POLICY.md`)

The first active slice is **Evidence and workflow parity**. Each migrated
capability must have a V2 boundary, a test or fixture, and an explicit
permission policy before it is considered complete.
