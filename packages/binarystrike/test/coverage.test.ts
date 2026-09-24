import { describe, expect, test } from "bun:test"
import { Coverage } from "../src/coverage.js"
import { Blackboard } from "../src/blackboard.js"
import { tmpdir } from "./fixture.js"
import { Intel } from "../src/intel.js"

describe("Coverage", () => {
  test("records searchable coverage facts and suppresses duplicates", async () => {
    await using dir = await tmpdir()
    const first = await Coverage.record({
      root: dir.path,
      asset: "sample.bin",
      class: "unsafe-api",
      scope: "local",
      note: "Checked imported string functions; no attacker-controlled call reached a sink.",
      request_id: "trace-1",
    })
    const duplicate = await Coverage.record({
      root: dir.path,
      asset: "sample.bin",
      class: "unsafe-api",
      scope: "local",
      note: "A second note must not create a duplicate coverage cell.",
    })

    expect(first.duplicate).toBe(false)
    expect(duplicate.duplicate).toBe(true)
    expect(await Coverage.query({ root: dir.path, asset: "sample.bin", class: "unsafe-api" })).toHaveLength(1)
    expect((await Blackboard.read({ root: dir.path })).at(0)?.tags).toContain("coverage")
  })

  test("keeps wide and local coverage independently filterable", async () => {
    await using dir = await tmpdir()
    await Coverage.record({
      root: dir.path,
      asset: "deployment",
      class: "weak-tls",
      scope: "wide",
      note: "Reviewed the deployment TLS policy and certificate chain.",
    })
    await Coverage.record({
      root: dir.path,
      asset: "api.example.test/orders",
      class: "idor",
      scope: "local",
      note: "Compared authorized and unauthorized object identifiers.",
    })

    expect(await Coverage.query({ root: dir.path, scope: "wide" })).toHaveLength(1)
    expect(await Coverage.query({ root: dir.path, scope: "local" })).toHaveLength(1)
    expect((await Coverage.query({ root: dir.path, scope: "wide" }))[0]?.asset).toBe("deployment")
  })

  test("allows a superseded coverage cell to be recorded again", async () => {
    await using dir = await tmpdir()
    const first = await Coverage.record({
      root: dir.path,
      asset: "sample.bin",
      class: "unsafe-api",
      scope: "local",
      note: "Initial review.",
    })
    await Blackboard.update({ root: dir.path, id: first.note.id, patch: { status: "superseded" } })
    const second = await Coverage.record({
      root: dir.path,
      asset: "sample.bin",
      class: "unsafe-api",
      scope: "local",
      note: "Re-tested after the binary changed.",
    })
    expect(second.duplicate).toBe(false)
    expect(await Coverage.query({ root: dir.path, asset: "sample.bin" })).toHaveLength(1)
  })

  test("records VRT verdicts as causal coverage facts", async () => {
    await using dir = await tmpdir()
    const intel = await Intel.record({
      root: dir.path,
      type: "endpoint",
      title: "Parser endpoint",
      asset: "sample.bin",
      confidence: "high",
    })
    const clean = await Coverage.recordCheck({
      root: dir.path,
      intel_id: intel.entry.id,
      asset: "sample.bin",
      class: "memory-corruption",
      scope: "local",
      status: "tested_not_vulnerable",
      technique: "bounded input",
    })
    expect(clean.note.verdict).toBe("tested_not_vulnerable")
    expect(clean.note.intel_id).toBe(intel.entry.id)
    expect((await Blackboard.graph({ root: dir.path })).edges).toEqual([{ from: intel.entry.id, to: clean.note.id }])
    await expect(
      Coverage.recordCheck({
        root: dir.path,
        intel_id: intel.entry.id,
        asset: "sample.bin",
        class: "memory-corruption",
        scope: "local",
        status: "tested_vulnerable",
      }),
    ).rejects.toThrow("require evidence")
  })
})
