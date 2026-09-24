import path from "path"
import { realpath } from "fs/promises"
import { Message } from "@opencode/ai"
import { Plugin } from "@opencode/plugin"
import { Schema } from "effect"
import { BinaryAnalysis } from "./analysis.js"
import { Blackboard } from "./blackboard.js"
import { Chain } from "./chain.js"
import { CloudPlan } from "./cloud.js"
import { Coverage } from "./coverage.js"
import { Finding as FindingLedger } from "./finding.js"
import { FGS } from "./fgs.js"
import { Intel } from "./intel.js"
import { Methodology } from "./methodology.js"
import { Report } from "./report.js"
import { Request } from "./request.js"
import { Retest } from "./retest.js"
import { PlatformPlan } from "./platform.js"
import { check as checkScope } from "./scope.js"

const Finding = Schema.Struct({
  id: Schema.optionalKey(Schema.String),
  severity: Schema.Literals(["critical", "high", "medium", "low", "info"]),
  status: Schema.String,
  title: Schema.String,
  description: Schema.String,
  cwe: Schema.optionalKey(Schema.String),
  location: Schema.optionalKey(Schema.String),
  line_start: Schema.optionalKey(Schema.Int),
  line_end: Schema.optionalKey(Schema.Int),
  endpoint: Schema.optionalKey(Schema.String),
  attack_vector: Schema.optionalKey(Schema.String),
  blackboard_ids: Schema.optionalKey(Schema.Array(Schema.String)),
  blackboard_id: Schema.optionalKey(Schema.String),
  intent_id: Schema.optionalKey(Schema.String),
  goal_id: Schema.optionalKey(Schema.String),
  step_id: Schema.optionalKey(Schema.String),
  fact_id: Schema.optionalKey(Schema.String),
  confidence: Schema.optionalKey(Schema.Literals(["confirmed", "likely", "unverified"])),
  evidence: Schema.Array(Schema.String),
  reproduction: Schema.optionalKey(Schema.String),
  poc: Schema.optionalKey(Schema.String),
  impact: Schema.optionalKey(Schema.String),
  business_impact: Schema.optionalKey(Schema.String),
  recommendation: Schema.optionalKey(Schema.String),
})

const FindingInput = Schema.Struct({
  severity: Schema.Literals(["critical", "high", "medium", "low", "info"]),
  title: Schema.String,
  description: Schema.String,
  cwe: Schema.optionalKey(Schema.String),
  location: Schema.optionalKey(Schema.String),
  line_start: Schema.optionalKey(Schema.Int),
  line_end: Schema.optionalKey(Schema.Int),
  endpoint: Schema.optionalKey(Schema.String),
  attack_vector: Schema.optionalKey(Schema.String),
  blackboard_ids: Schema.optionalKey(Schema.Array(Schema.String)),
  goal_id: Schema.optionalKey(Schema.String),
  evidence: Schema.optionalKey(Schema.Array(Schema.String)),
  reproduction: Schema.optionalKey(Schema.String),
  poc: Schema.optionalKey(Schema.String),
  impact: Schema.optionalKey(Schema.String),
  business_impact: Schema.optionalKey(Schema.String),
  recommendation: Schema.optionalKey(Schema.String),
})

const Evidence = Schema.Struct({
  id: Schema.String,
  kind: Schema.Literals(["request", "response", "artifact"]),
  label: Schema.optionalKey(Schema.String),
  content: Schema.String,
})

const BlackboardKind = Schema.Literals(["fact", "goal", "step", "hint", "intent"])
const BlackboardStatus = Schema.Literals(["open", "active", "completed", "rejected", "superseded"])
const BlackboardConfidence = Schema.Literals(["unverified", "low", "medium", "high", "confirmed"])
const CoverageScope = Schema.Literals(["wide", "local"])
const CoverageVerdict = Schema.Literals(["tested_vulnerable", "tested_not_vulnerable", "not_applicable"])
const CloudProvider = Schema.Literals(["aws", "azure", "kubernetes"])
const Platform = Schema.Literals(["linux-ebpf", "cicd", "macos", "windows"])
const RequestStatus = Schema.Literals(["queued", "processing", "processed"])
const IntelType = Schema.Literals([
  "endpoint",
  "subdomain",
  "technology",
  "credential",
  "parameter",
  "vulnerability_hint",
  "configuration",
  "api_schema",
  "authentication_flow",
  "business_rule",
  "sensitive_data",
  "infrastructure",
])
const IntelConfidence = Schema.Literals(["confirmed", "high", "medium", "low"])
const IntelSeverity = Schema.Literals(["critical", "high", "medium", "low", "info"])
const IntelStatus = Schema.Literals(["new", "investigating", "tested", "exploited", "reported"])

function inside(root: string, target: string) {
  const relative = path.relative(root, target)
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative))
}

async function resolve(root: string, file: string) {
  const target = path.resolve(root, file)
  const actual = await realpath(target)
  if (!inside(root, actual)) throw new Error(`BinaryStrike paths must stay inside ${root}`)
  return actual
}

function json(output: unknown) {
  return { output, content: JSON.stringify(output, null, 2) }
}

const ContextMetadata = "binarystrike.context"

function contextMessage(text: string) {
  return Message.make({ role: "user", content: text, metadata: { [ContextMetadata]: true } })
}

export default Plugin.define({
  id: "binarystrike",
  async setup(ctx) {
    const root = ctx.location.directory

    await ctx.session.hook("context", async (event) => {
      if (!["binary-security", "binary-security-decide", "binary-security-execute"].includes(String(event.agent))) return
      if (event.messages.some((message) => message.metadata?.[ContextMetadata] === true)) return
      const [context, fgs, findings, methodology, requests] = await Promise.all([
        Blackboard.context(root),
        FGS.context(root),
        FindingLedger.context(root),
        Methodology.status({ root, include_validation: true }),
        Request.context(root),
      ])
      // Project-local entries are untrusted evidence.  Keep them in the
      // ordinary conversation channel so a malicious file cannot masquerade
      // as an operator-authored system instruction.
      if (context) event.messages.push(contextMessage(context))
      if (fgs) event.messages.push(contextMessage(fgs))
      if (findings) event.messages.push(contextMessage(findings))
      event.messages.push(contextMessage(`${Blackboard.Marker}\n${Methodology.format(methodology)}\n${Blackboard.Marker}`))
      if (requests) event.messages.push(contextMessage(requests))
    })

    await ctx.tool.transform((editor) => {
      editor.add({
        name: "analyze_binary",
        description:
          "Analyze a local ELF, PE, Mach-O, APK, ZIP, firmware-like, or unknown binary. Returns identity, strings, risk indicators, reverse-engineering availability, and safe workflow plans.",
        options: { permission: "read" },
        input: Schema.Struct({
          file: Schema.String,
          min_string: Schema.optionalKey(Schema.Int.check(Schema.isBetween({ minimum: 3, maximum: 32 }))),
          limit: Schema.optionalKey(Schema.Int.check(Schema.isBetween({ minimum: 10, maximum: 5_000 }))),
        }),
        async execute(input) {
          return json(
            await BinaryAnalysis.analyze({
              file: await resolve(root, input.file),
              minString: input.min_string,
              limit: input.limit,
            }),
          )
        },
      })

      editor.add({
        name: "binary_re_toolkit",
        description:
          "Plan Ghidra, IDA, Binary Ninja, radare2, Rizin, capa, YARA, and JADX workflows without executing them.",
        options: { permission: "read" },
        input: Schema.Struct({ file: Schema.String }),
        async execute(input) {
          return json(await BinaryAnalysis.toolchain({ file: await resolve(root, input.file) }))
        },
      })

      editor.add({
        name: "analyze_firmware",
        description:
          "Plan authorized firmware extraction, filesystem triage, SBOM generation, and CVE scanning workflows.",
        options: { permission: "read" },
        input: Schema.Struct({ file: Schema.String }),
        async execute(input) {
          return json(await BinaryAnalysis.analyzeFirmware({ file: await resolve(root, input.file) }))
        },
      })

      editor.add({
        name: "dynamic_debug",
        description:
          "Plan gdb, lldb, strace, ltrace, Frida, and Qiling debugging for an authorized binary or supplied crash.",
        options: { permission: "read" },
        input: Schema.Struct({
          file: Schema.String,
          arg: Schema.optionalKey(Schema.Array(Schema.String)),
          stdin: Schema.optionalKey(Schema.String),
        }),
        async execute(input) {
          return json(
            await BinaryAnalysis.dynamicDebug({
              file: await resolve(root, input.file),
              args: input.arg,
              stdin: input.stdin ? await resolve(root, input.stdin) : undefined,
            }),
          )
        },
      })

      editor.add({
        name: "angr_explore",
        description: "Generate an angr symbolic-exploration harness for an authorized native binary.",
        options: { permission: "read" },
        input: Schema.Struct({
          file: Schema.String,
          find: Schema.optionalKey(Schema.Array(Schema.String)),
          avoid: Schema.optionalKey(Schema.Array(Schema.String)),
          arg: Schema.optionalKey(Schema.Array(Schema.String)),
          stdin: Schema.optionalKey(Schema.String),
        }),
        async execute(input) {
          return json(
            await BinaryAnalysis.angrExplore({
              file: await resolve(root, input.file),
              find: input.find,
              avoid: input.avoid,
              argv: input.arg,
              stdin: input.stdin,
            }),
          )
        },
      })

      editor.add({
        name: "export_report",
        description:
          "Write a durable JSON, Markdown, and HTML BinaryStrike finding report under .binarystrike/reports/.",
        options: { permission: "export_report" },
        input: Schema.Struct({
          session_id: Schema.optionalKey(Schema.String),
          findings: Schema.optionalKey(Schema.Array(Finding)),
          finding_ids: Schema.optionalKey(Schema.Array(Schema.String)),
          evidence: Schema.optionalKey(Schema.Array(Evidence)),
          format: Schema.optionalKey(Schema.Array(Schema.Literals(["json", "markdown", "html"]))),
          output_dir: Schema.optionalKey(Schema.String),
        }),
        async execute(input) {
          return json(
            await Report.generate({
              root,
              session: input.session_id ?? ctx.location.workspaceID,
              findings: input.findings,
              finding_ids: input.finding_ids,
              evidence: input.evidence,
              format: input.format,
              dir: input.output_dir,
            }),
          )
        },
      })

      editor.add({
        name: "record_finding",
        description:
          "Record a BinaryStrike finding candidate durably. Similar findings are returned for explicit agent triage; nothing is silently discarded.",
        options: { permission: "record_finding" },
        input: FindingInput,
        async execute(input) {
          return json(await FindingLedger.record({ root, ...input }))
        },
      })

      editor.add({
        name: "get_findings",
        description: "Read the project-local BinaryStrike finding ledger, including triage status and similar candidates.",
        options: { permission: "read" },
        input: Schema.Struct({
          id: Schema.optionalKey(Schema.String),
          status: Schema.optionalKey(Schema.Literals(["new", "approved", "duplicate", "open", "fixed", "ignored"])),
          limit: Schema.optionalKey(Schema.Int.check(Schema.isBetween({ minimum: 1, maximum: 200 }))),
          include_history: Schema.optionalKey(Schema.Boolean),
        }),
        async execute(input) {
          return json({
            findings: await FindingLedger.read({ root, ...input }),
            history: input.include_history ? await FindingLedger.history(root) : undefined,
          })
        },
      })

      editor.add({
        name: "triage_finding",
        description:
          "Open a finding for verification, approve it into a blackboard fact, or close it as duplicate, fixed, or ignored without deleting the record.",
        options: { permission: "triage_finding" },
        input: Schema.Struct({
          id: Schema.String,
          status: Schema.Literals(["open", "approved", "duplicate", "fixed", "ignored"]),
          duplicate_of: Schema.optionalKey(Schema.String),
        }),
        async execute(input) {
          return json(await FindingLedger.update({ root, ...input }))
        },
      })

      editor.add({
        name: "methodology_status",
        description:
          "Read the current BinaryStrike methodology projection from the blackboard and finding ledger. This is observational context, not a scheduler.",
        options: { permission: "read" },
        input: Schema.Struct({ include_validation: Schema.optionalKey(Schema.Boolean) }),
        async execute(input) {
          const result = await Methodology.status({ root, include_validation: input.include_validation })
          return json({ ...result, context: Methodology.format(result) })
        },
      })

      editor.add({
        name: "fgs_read",
        description:
          "Read the append-only Fact-Goal-Step search graph. This is observational context, not a scheduler.",
        options: { permission: "read" },
        input: Schema.Struct({
          limit: Schema.optionalKey(Schema.Int.check(Schema.isBetween({ minimum: 1, maximum: 200 }))),
        }),
        async execute(input) {
          const graph = await FGS.read({ root, limit: input.limit ?? 100 })
          return json({ ...graph, context: await FGS.context(root) })
        },
      })

      editor.add({
        name: "fgs_create_goal",
        description: "Append a Goal to the project-local Fact-Goal-Step graph.",
        options: { permission: "fgs_write" },
        input: Schema.Struct({
          title: Schema.String,
          body: Schema.String,
          source: Schema.optionalKey(Schema.String),
          parent_ids: Schema.optionalKey(Schema.Array(Schema.String)),
          tags: Schema.optionalKey(Schema.Array(Schema.String)),
        }),
        async execute(input) {
          return json(await FGS.goal({ root, ...input }))
        },
      })

      editor.add({
        name: "fgs_add_step",
        description: "Append a prioritized candidate Step under an existing Goal; it does not execute the Step.",
        options: { permission: "fgs_write" },
        input: Schema.Struct({
          title: Schema.String,
          body: Schema.String,
          goal_id: Schema.String,
          priority: Schema.optionalKey(Schema.Int.check(Schema.isBetween({ minimum: 0, maximum: 100 }))),
          source: Schema.optionalKey(Schema.String),
          parent_ids: Schema.optionalKey(Schema.Array(Schema.String)),
          tags: Schema.optionalKey(Schema.Array(Schema.String)),
        }),
        async execute(input) {
          return json(await FGS.step({ root, ...input }))
        },
      })

      editor.add({
        name: "fgs_update_goal",
        description: "Update Goal lifecycle state without deleting its history.",
        options: { permission: "fgs_write" },
        input: Schema.Struct({
          id: Schema.String,
          status: BlackboardStatus,
          body: Schema.optionalKey(Schema.String),
        }),
        async execute(input) {
          return json(await FGS.updateGoal({ root, ...input }))
        },
      })

      editor.add({
        name: "fgs_update_step",
        description: "Update or reprioritize a Step without executing it.",
        options: { permission: "fgs_write" },
        input: Schema.Struct({
          id: Schema.String,
          status: BlackboardStatus,
          priority: Schema.optionalKey(Schema.Int.check(Schema.isBetween({ minimum: 0, maximum: 100 }))),
        }),
        async execute(input) {
          return json(await FGS.updateStep({ root, ...input }))
        },
      })

      editor.add({
        name: "submit_fact",
        description:
          "Append a confirmed Fact produced by executing a bounded Step. A Step ID is required so the world-state change remains causally linked.",
        options: { permission: "submit_fact" },
        input: Schema.Struct({
          title: Schema.String,
          body: Schema.String,
          step_id: Schema.String,
          source: Schema.optionalKey(Schema.String),
          confidence: Schema.optionalKey(BlackboardConfidence),
          parent_ids: Schema.optionalKey(Schema.Array(Schema.String)),
          tags: Schema.optionalKey(Schema.Array(Schema.String)),
        }),
        async execute(input) {
          return json(await FGS.fact({ root, ...input }))
        },
      })

      editor.add({
        name: "get_chains",
        description:
          "Detect read-only attack-chain candidates from related Intel and VRT facts. Candidates are suggestions, not scheduled actions.",
        options: { permission: "read" },
        input: Schema.Struct({}),
        async execute() {
          const chains = await Chain.detect(root)
          return json({ chains, context: Chain.format(chains) })
        },
      })

      editor.add({
        name: "cloud_plan",
        description:
          "Generate a read-only AWS, Azure, or Kubernetes inventory and authorization plan. This tool never invokes cloud or cluster APIs.",
        options: { permission: "cloud_plan" },
        input: Schema.Struct({
          provider: CloudProvider,
          scope: Schema.optionalKey(Schema.String),
          focus: Schema.optionalKey(Schema.String),
        }),
        async execute(input) {
          return json(CloudPlan.plan(input))
        },
      })

      editor.add({
        name: "platform_plan",
        description:
          "Generate a read-only Linux eBPF, CI/CD, macOS, or Windows posture plan. This tool never attaches probes or changes the host.",
        options: { permission: "platform_plan" },
        input: Schema.Struct({
          platform: Platform,
          scope: Schema.optionalKey(Schema.String),
          focus: Schema.optionalKey(Schema.String),
        }),
        async execute(input) {
          return json(PlatformPlan.plan(input))
        },
      })

      editor.add({
        name: "record_intel",
        description:
          "Record structured project intelligence as a blackboard fact or hint. This replaces V1 session Intel without a database or scheduler.",
        options: { permission: "record_intel" },
        input: Schema.Struct({
          type: IntelType,
          title: Schema.String,
          asset: Schema.String,
          detail: Schema.optionalKey(Schema.String),
          source: Schema.optionalKey(Schema.String),
          severity: Schema.optionalKey(IntelSeverity),
          confidence: Schema.optionalKey(IntelConfidence),
          tags: Schema.optionalKey(Schema.Array(Schema.String)),
          related_ids: Schema.optionalKey(Schema.Array(Schema.String)),
          status: Schema.optionalKey(IntelStatus),
          target_class: Schema.optionalKey(Schema.String),
        }),
        async execute(input) {
          return json(await Intel.record({ root, ...input }))
        },
      })

      editor.add({
        name: "get_intel",
        description: "Read structured intelligence projected from the project-local Fact/Hint blackboard.",
        options: { permission: "read" },
        input: Schema.Struct({
          asset: Schema.optionalKey(Schema.String),
          type: Schema.optionalKey(IntelType),
          limit: Schema.optionalKey(Schema.Int.check(Schema.isBetween({ minimum: 1, maximum: 200 }))),
        }),
        async execute(input) {
          return json({ entries: await Intel.read({ root, ...input }) })
        },
      })

      editor.add({
        name: "update_intel",
        description: "Append a lifecycle, confidence, or detail update to a structured Intel blackboard entry.",
        options: { permission: "update_intel" },
        input: Schema.Struct({
          id: Schema.String,
          status: Schema.optionalKey(IntelStatus),
          confidence: Schema.optionalKey(IntelConfidence),
          detail: Schema.optionalKey(Schema.String),
        }),
        async execute(input) {
          const { id, ...patch } = input
          return json(await Intel.update({ root, id, ...patch }))
        },
      })

      editor.add({
        name: "retest_request",
        description:
          "Replay one authorized raw HTTP request and persist request, response, and comparison evidence to disk.",
        options: { permission: "webfetch" },
        input: Schema.Struct({
          raw_request: Schema.String,
          scheme: Schema.optionalKey(Schema.Literals(["http", "https"])),
          baseline_status: Schema.optionalKey(Schema.Number),
          scope_items: Schema.optionalKey(Schema.Array(Schema.String)),
          output_dir: Schema.optionalKey(Schema.String),
        }),
        async execute(input, context) {
          return json(
            await Retest.run({
              root,
              raw_request: input.raw_request,
              scheme: input.scheme,
              baseline_status: input.baseline_status,
              scope_items: input.scope_items,
              output_dir: input.output_dir,
              signal: context.signal,
            }),
          )
        },
      })

      editor.add({
        name: "record_http_observation",
        description:
          "Persist an observed raw HTTP request and optional response in the project-local request ledger without sending network traffic.",
        options: { permission: "record_http_observation" },
        input: Schema.Struct({
          raw_request: Schema.String,
          scheme: Schema.optionalKey(Schema.Literals(["http", "https"])),
          scope_items: Schema.optionalKey(Schema.Array(Schema.String)),
          source: Schema.optionalKey(Schema.String),
          credential_id: Schema.optionalKey(Schema.String),
          tags: Schema.optionalKey(Schema.Array(Schema.String)),
          response: Schema.optionalKey(
            Schema.Struct({
              status: Schema.Int,
              headers: Schema.optionalKey(Schema.Record(Schema.String, Schema.String)),
              body: Schema.optionalKey(Schema.String),
            }),
          ),
        }),
        async execute(input) {
          return json(await Request.record({ root, ...input }))
        },
      })

      editor.add({
        name: "record_browser_observation",
        description:
          "Normalize a captured browser network event into the passive HTTP observation ledger without sending a request.",
        options: { permission: "record_browser_observation" },
        input: Schema.Struct({
          url: Schema.String,
          method: Schema.optionalKey(Schema.String),
          request_headers: Schema.optionalKey(Schema.Record(Schema.String, Schema.String)),
          request_body: Schema.optionalKey(Schema.String),
          scope_items: Schema.optionalKey(Schema.Array(Schema.String)),
          source: Schema.optionalKey(Schema.String),
          credential_id: Schema.optionalKey(Schema.String),
          tags: Schema.optionalKey(Schema.Array(Schema.String)),
          response: Schema.optionalKey(
            Schema.Struct({
              status: Schema.Int,
              headers: Schema.optionalKey(Schema.Record(Schema.String, Schema.String)),
              body: Schema.optionalKey(Schema.String),
            }),
          ),
        }),
        async execute(input) {
          return json(await Request.recordBrowser({ root, ...input }))
        },
      })

      editor.add({
        name: "get_http_observations",
        description: "Read bounded project-local HTTP observations and optional raw request/response details.",
        options: { permission: "read" },
        input: Schema.Struct({
          id: Schema.optionalKey(Schema.String),
          host: Schema.optionalKey(Schema.String),
          method: Schema.optionalKey(Schema.String),
          status: Schema.optionalKey(RequestStatus),
          limit: Schema.optionalKey(Schema.Int.check(Schema.isBetween({ minimum: 1, maximum: 200 }))),
          include_body: Schema.optionalKey(Schema.Boolean),
          include_history: Schema.optionalKey(Schema.Boolean),
        }),
        async execute(input) {
          return json({
            entries: await Request.read({ root, ...input }),
            history: input.include_history ? await Request.history(root) : undefined,
          })
        },
      })

      editor.add({
        name: "update_http_observation",
        description: "Append a processing lifecycle update to a project-local HTTP observation.",
        options: { permission: "update_http_observation" },
        input: Schema.Struct({ id: Schema.String, status: RequestStatus }),
        async execute(input) {
          return json(await Request.update({ root, ...input }))
        },
      })

      editor.add({
        name: "scope_check",
        description:
          "Validate a domain, URL, IPv4 address, wildcard domain, or CIDR against an explicit authorized scope before active testing.",
        options: { permission: "read" },
        input: Schema.Struct({ target: Schema.String, scope_items: Schema.Array(Schema.String) }),
        async execute(input) {
          return json(checkScope(input.target, input.scope_items))
        },
      })

      editor.add({
        name: "blackboard_write",
        description:
          "Append a Fact, Goal, Step, Intent, or Hint to the project-local BinaryStrike blackboard and link it to prior entries.",
        options: { permission: "blackboard_write" },
        input: Schema.Struct({
          kind: BlackboardKind,
          title: Schema.String,
          body: Schema.String,
          source: Schema.optionalKey(Schema.String),
          confidence: Schema.optionalKey(BlackboardConfidence),
          tags: Schema.optionalKey(Schema.Array(Schema.String)),
          parent_ids: Schema.optionalKey(Schema.Array(Schema.String)),
          status: Schema.optionalKey(BlackboardStatus),
          priority: Schema.optionalKey(Schema.Int.check(Schema.isBetween({ minimum: 0, maximum: 100 }))),
        }),
        async execute(input) {
          return json(await Blackboard.write({ root, ...input }))
        },
      })

      editor.add({
        name: "blackboard_read",
        description:
          "Read the current BinaryStrike Fact-Goal-Step-Intent-Hint blackboard as a filtered graph and context snapshot.",
        options: { permission: "read" },
        input: Schema.Struct({
          kind: Schema.optionalKey(Schema.Array(BlackboardKind)),
          status: Schema.optionalKey(BlackboardStatus),
          query: Schema.optionalKey(Schema.String),
          limit: Schema.optionalKey(Schema.Int.check(Schema.isBetween({ minimum: 1, maximum: 200 }))),
          include_history: Schema.optionalKey(Schema.Boolean),
        }),
        async execute(input) {
          const query = {
            root,
            kind: input.kind,
            status: input.status,
            query: input.query,
            limit: input.limit ?? 100,
          }
          const entries = await Blackboard.read(query)
          const graph = await Blackboard.graph(query)
          const context = await Blackboard.render(query)
          return json({
            entries,
            graph,
            context,
            history: input.include_history ? await Blackboard.history(root) : undefined,
          })
        },
      })

      editor.add({
        name: "blackboard_update",
        description: "Update lifecycle, evidence, or causal links on a BinaryStrike blackboard entry.",
        options: { permission: "blackboard_update" },
        input: Schema.Struct({
          id: Schema.String,
          title: Schema.optionalKey(Schema.String),
          body: Schema.optionalKey(Schema.String),
          source: Schema.optionalKey(Schema.String),
          tags: Schema.optionalKey(Schema.Array(Schema.String)),
          parent_ids: Schema.optionalKey(Schema.Array(Schema.String)),
          confidence: Schema.optionalKey(BlackboardConfidence),
          status: Schema.optionalKey(BlackboardStatus),
        }),
        async execute(input) {
          const { id, ...patch } = input
          return json(await Blackboard.update({ root, id, patch }))
        },
      })

      editor.add({
        name: "record_coverage_note",
        description:
          "Record a tested vulnerability class and verdict as a durable blackboard fact so later analysis can avoid repeating it.",
        options: { permission: "record_coverage_note" },
        input: Schema.Struct({
          asset: Schema.String,
          class: Schema.String,
          scope: CoverageScope,
          note: Schema.String,
          request_id: Schema.optionalKey(Schema.String),
          verdict: Schema.optionalKey(CoverageVerdict),
        }),
        async execute(input) {
          return json(await Coverage.record({ root, ...input }))
        },
      })

      editor.add({
        name: "get_coverage_notes",
        description: "Query project-local coverage facts by asset, vulnerability class, or scope.",
        options: { permission: "read" },
        input: Schema.Struct({
          asset: Schema.optionalKey(Schema.String),
          class: Schema.optionalKey(Schema.String),
          scope: Schema.optionalKey(CoverageScope),
          limit: Schema.optionalKey(Schema.Int.check(Schema.isBetween({ minimum: 1, maximum: 200 }))),
        }),
        async execute(input) {
          return json(await Coverage.query({ root, ...input }))
        },
      })

      editor.add({
        name: "record_vrt_check",
        description:
          "Record a VRT-style test verdict as a coverage fact linked to a structured Intel entry. Vulnerable verdicts require evidence.",
        options: { permission: "record_vrt_check" },
        input: Schema.Struct({
          intel_id: Schema.String,
          asset: Schema.String,
          class: Schema.String,
          scope: CoverageScope,
          status: CoverageVerdict,
          technique: Schema.optionalKey(Schema.String),
          evidence: Schema.optionalKey(Schema.String),
        }),
        async execute(input) {
          return json(await Coverage.recordCheck({ root, ...input }))
        },
      })
    })
  },
})
