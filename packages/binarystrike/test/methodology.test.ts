import { describe, expect, test } from "bun:test"
import { Blackboard } from "../src/blackboard.js"
import { Coverage } from "../src/coverage.js"
import { Finding } from "../src/finding.js"
import { FGS } from "../src/fgs.js"
import { Methodology } from "../src/methodology.js"
import { tmpdir } from "./fixture.js"

describe("Methodology", () => {
  test("requires an explicit sourced completion checkpoint, not prose or metadata", async () => {
    await using dir = await tmpdir()
    await Blackboard.write({ root: dir.path, kind: "fact", title: "Report not ready",
      body: "Scope and binary metadata remain unreviewed.", tags: ["asset:sample.bin", "scope:local"] })
    const initial = await Methodology.status({ root: dir.path })
    expect(initial.phases.every((phase) => phase.status === "not_started")).toBe(true)
    const checkpoint = await Blackboard.write({ root: dir.path, kind: "fact", title: "Review checkpoint",
      body: "Reviewer recorded the triage review outcome.", tags: ["phase:binary_triage"],
      status: "completed", confidence: "high" })
    expect((await Methodology.status({ root: dir.path })).completed_count).toBe(0)
    await Blackboard.update({ root: dir.path, id: checkpoint.id, patch: { source: "review-notes.md" } })
    expect((await Methodology.status({ root: dir.path })).completed_count).toBe(1)
    await Blackboard.update({ root: dir.path, id: checkpoint.id, patch: { status: "superseded" } })
    expect((await Methodology.status({ root: dir.path })).completed_count).toBe(0)
  })

  test("uses the latest explicit verdict per coverage cell and never guesses from prose", async () => {
    await using dir = await tmpdir()
    const tags = ["coverage", "asset:sample.bin", "class:review", "scope:local"]
    await Blackboard.write({ root: dir.path, kind: "fact", title: "First review", body: "Review notes",
      tags: [...tags, "verdict:tested_vulnerable"] })
    await Blackboard.write({ root: dir.path, kind: "fact", title: "Follow-up review", body: "Review notes",
      tags: [...tags, "verdict:tested_not_vulnerable"] })
    await Coverage.record({ root: dir.path, asset: "other.bin", class: "review", scope: "local",
      note: "Confirmed findings found: this sentence is not a structured verdict." })
    const result = await Methodology.status({ root: dir.path })
    expect(result.coverage).toMatchObject({ total_checks: null, coverage_percent: null,
      completed_checks: 2, vulnerable_checks: 0, unknown_verdict_checks: 1, total_entries: 3 })
    expect(Methodology.format(result)).toContain("unknown (no planned check inventory)")
    expect(Methodology.format(result)).not.toContain("null%")
  })

  test("derives observational progress from the blackboard and ledger", async () => {
    await using dir = await tmpdir()
    const empty = await Methodology.status({ root: dir.path })
    expect(empty.completion_percent).toBe(0)
    expect(empty.current_phase).toBe("scope_analysis")

    await Blackboard.write({
      root: dir.path,
      kind: "fact",
      title: "Sample ELF metadata",
      body: "The authorized sample is an x86_64 ELF binary.",
      source: "analysis-report.md",
      tags: ["binary", "metadata", "architecture", "phase:binary_triage"],
      confidence: "high",
    })
    await Blackboard.write({
      root: dir.path,
      kind: "intent",
      title: "Trace parser input dynamically",
      body: "Use a bounded debugger to verify the length flow.",
      tags: ["dynamic", "debug"],
    })
    await Coverage.record({
      root: dir.path,
      asset: "sample.bin",
      class: "memory-corruption",
      scope: "local",
      note: "No unsafe write reached an attacker-controlled sink.",
    })

    const result = await Methodology.status({ root: dir.path, include_validation: true })
    expect(result.phases.find((phase) => phase.id === "binary_triage")?.status).toBe("completed")
    expect(result.phases.find((phase) => phase.id === "dynamic_analysis")?.status).toBe("in_progress")
    expect(result.coverage.total_checks).toBeNull()
    expect(result.coverage.coverage_percent).toBeNull()
    expect(result.coverage.completed_checks).toBe(1)
    expect(result.coverage.vulnerable_checks).toBe(0)
    expect(result.graph).toMatchObject({ facts: 2, intents: 1, hints: 0 })
    expect(result.violations).toHaveLength(0)
    expect(Methodology.format(result)).toContain("BinaryStrike Methodology")
  })

  test("exposes pending candidate validation without forcing a route", async () => {
    await using dir = await tmpdir()
    const finding = await Finding.record({
      root: dir.path,
      severity: "high",
      title: "Parser memory corruption",
      description: "A length field reaches a copy operation without a bound check.",
      evidence: ["static trace"],
    })
    const pending = await Methodology.status({ root: dir.path, include_validation: true })
    expect(pending.findings.pending).toBe(1)
    expect(pending.graph.hints).toBe(1)

    const approved = await Finding.update({ root: dir.path, id: finding.id, status: "approved" })
    expect(approved.fact_id).toBeString()
    const done = await Methodology.status({ root: dir.path, include_validation: true })
    expect(done.findings.approved).toBe(1)
    expect(done.findings.pending).toBe(0)
    expect(done.phases.find((phase) => phase.id === "vulnerability_validation")?.status).toBe("completed")
  })

  test("blocks approved findings that have no evidence or linked fact", async () => {
    await using dir = await tmpdir()
    const finding = await Finding.record({
      root: dir.path,
      severity: "high",
      title: "Unsupported parser claim",
      description: "The parser may be unsafe.",
    })
    await Finding.update({ root: dir.path, id: finding.id, status: "approved" })
    const result = await Methodology.status({ root: dir.path, include_validation: true })
    expect(result.violations).toContainEqual({
      gate: "evidence_quality",
      severity: "blocking",
      message: "1 approved finding(s) have no reproducible evidence or linked blackboard fact.",
    })
  })

  test("surfaces pending FGS steps as observational next steps", async () => {
    await using dir = await tmpdir()
    const goal = await FGS.goal({ root: dir.path, title: "Review parser", body: "Complete the parser review." })
    const step = await FGS.step({
      root: dir.path,
      goal_id: goal.id,
      title: "Trace input boundary",
      body: "Inspect the length check with bounded tooling.",
      priority: 95,
    })
    const result = await Methodology.status({ root: dir.path })
    expect(result.next_steps.some((item) => item.includes(step.id) && item.includes("Trace input boundary"))).toBe(true)
    await FGS.updateStep({ root: dir.path, id: step.id, status: "completed" })
    const done = await Methodology.status({ root: dir.path })
    expect(done.next_steps.some((item) => item.includes(step.id))).toBe(false)
  })
})
