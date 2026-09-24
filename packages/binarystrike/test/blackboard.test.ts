import { describe, expect, test } from "bun:test"
import path from "path"
import { Blackboard } from "../src/blackboard.js"
import { tmpdir } from "./fixture.js"

describe("Blackboard", () => {
  test("renders a bounded prompt context only when entries exist", async () => {
    await using dir = await tmpdir()
    expect(await Blackboard.context(dir.path)).toBeUndefined()

    await Blackboard.write({
      root: dir.path,
      kind: "fact",
      title: "Observed import",
      body: "The sample imports memcpy.",
    })

    const context = await Blackboard.context(dir.path)
    expect(context).toContain(Blackboard.Marker)
    expect(context).toContain("Observed import")
    expect(context).toContain("untrusted project-local analysis context")
  })

  test("keeps fact, intent, and hint relationships in the project graph", async () => {
    await using dir = await tmpdir()
    const fact = await Blackboard.write({
      root: dir.path,
      kind: "fact",
      title: "Parser accepts a user-controlled length",
      body: "The ELF parser reads the length field before checking the input size.",
      confidence: "high",
      source: "sample.bin:0x401000",
    })
    const intent = await Blackboard.write({
      root: dir.path,
      kind: "intent",
      title: "Trace the length into allocation",
      body: "Use a debugger and a bounded sample to verify the sink.",
      parent_ids: [fact.id],
    })
    const hint = await Blackboard.write({
      root: dir.path,
      kind: "hint",
      title: "Check the decompression path",
      body: "The same parser may be reachable from firmware extraction.",
      parent_ids: [fact.id, intent.id],
    })

    const graph = await Blackboard.graph({ root: dir.path })
    expect(graph.nodes.map((entry) => entry.id)).toEqual([fact.id, intent.id, hint.id])
    expect(graph.edges).toEqual([
      { from: fact.id, to: intent.id },
      { from: fact.id, to: hint.id },
      { from: intent.id, to: hint.id },
    ])

    const context = await Blackboard.render({ root: dir.path })
    expect(context).toContain("## Facts")
    expect(context).toContain("## Intents")
    expect(context).toContain("## Hints")
    expect(context).toContain(fact.id)
  })

  test("records updates in the append-only timeline", async () => {
    await using dir = await tmpdir()
    const intent = await Blackboard.write({
      root: dir.path,
      kind: "intent",
      title: "Review imports",
      body: "Inspect imported functions before selecting a debugger.",
    })
    const updated = await Blackboard.update({
      root: dir.path,
      id: intent.id,
      patch: { status: "completed", confidence: "confirmed" },
    })

    expect(updated.status).toBe("completed")
    expect(updated.confidence).toBe("confirmed")
    expect((await Blackboard.history(dir.path))).toHaveLength(2)
    expect(await Bun.file(path.join(dir.path, ".binarystrike", "blackboard", "events.jsonl")).exists()).toBe(true)
  })

  test("can add causal links later but keeps the graph acyclic", async () => {
    await using dir = await tmpdir()
    const fact = await Blackboard.write({
      root: dir.path,
      kind: "fact",
      title: "Observed parser input",
      body: "The input reaches the parser.",
    })
    const intent = await Blackboard.write({
      root: dir.path,
      kind: "intent",
      title: "Trace parser input",
      body: "Follow the input to its sink.",
    })
    const updated = await Blackboard.update({
      root: dir.path,
      id: intent.id,
      patch: { parent_ids: [fact.id] },
    })
    expect(updated.parent_ids).toEqual([fact.id])
    await expect(
      Blackboard.update({ root: dir.path, id: fact.id, patch: { parent_ids: [intent.id] } }),
    ).rejects.toThrow("cycle")
  })

  test("rejects links to unknown entries without writing an event", async () => {
    await using dir = await tmpdir()
    expect(
      Blackboard.write({
        root: dir.path,
        kind: "hint",
        title: "Orphan hint",
        body: "This must be attached to an existing fact or intent.",
        parent_ids: ["bb_missing"],
      }),
    ).rejects.toThrow("parent not found")
    expect(await Blackboard.history(dir.path)).toHaveLength(0)
  })
})
