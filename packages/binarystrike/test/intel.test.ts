import { describe, expect, test } from "bun:test"
import { Blackboard } from "../src/blackboard.js"
import { Intel } from "../src/intel.js"
import { tmpdir } from "./fixture.js"

describe("Intel", () => {
  test("projects structured observations into fact/hint nodes and suppresses duplicates", async () => {
    await using dir = await tmpdir()
    const fact = await Intel.record({
      root: dir.path,
      type: "endpoint",
      title: "Orders API",
      asset: "sample.bin",
      detail: "The binary exposes an authenticated orders parser.",
      confidence: "high",
      tags: ["api-security"],
    })
    const duplicate = await Intel.record({
      root: dir.path,
      type: "endpoint",
      title: "Orders API",
      asset: "sample.bin",
    })
    const hint = await Intel.record({
      root: dir.path,
      type: "vulnerability_hint",
      title: "Length may reach copy sink",
      asset: "sample.bin",
      detail: "Trace the length before treating this as a vulnerability.",
      related_ids: [fact.entry.id],
      target_class: "memory-corruption",
    })

    expect(fact.duplicate).toBe(false)
    expect(fact.entry.kind).toBe("fact")
    expect(duplicate.duplicate).toBe(true)
    expect(hint.entry.kind).toBe("hint")
    expect(hint.entry.related_ids).toEqual([fact.entry.id])
    expect(await Intel.read({ root: dir.path, asset: "SAMPLE.BIN" })).toHaveLength(2)
    expect((await Blackboard.graph({ root: dir.path })).edges).toEqual([{ from: fact.entry.id, to: hint.entry.id }])
  })

  test("updates status and confidence as append-only blackboard events", async () => {
    await using dir = await tmpdir()
    const created = await Intel.record({
      root: dir.path,
      type: "technology",
      title: "Custom parser",
      asset: "sample.bin",
    })
    const updated = await Intel.update({
      root: dir.path,
      id: created.entry.id,
      status: "tested",
      confidence: "confirmed",
      detail: "The parser behavior was reproduced with a bounded sample.",
    })

    expect(updated.status).toBe("tested")
    expect(updated.confidence).toBe("confirmed")
    expect((await Blackboard.history(dir.path))).toHaveLength(2)
  })
})
