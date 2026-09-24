import { describe, expect, test } from "bun:test"
import { FGS } from "../src/fgs.js"
import { Blackboard } from "../src/blackboard.js"
import { tmpdir } from "./fixture.js"

describe("FGS", () => {
  test("keeps Goal, Step, and submitted Fact in one causal graph", async () => {
    await using dir = await tmpdir()
    const goal = await FGS.goal({
      root: dir.path,
      title: "Determine parser exploitability",
      body: "Finish when the input reaches a memory safety sink or is disproven.",
    })
    const step = await FGS.step({
      root: dir.path,
      goal_id: goal.id,
      title: "Trace the length field",
      body: "Use a bounded debugger run and preserve the trace.",
      priority: 90,
    })
    const fact = await FGS.fact({
      root: dir.path,
      step_id: step.id,
      title: "Length reaches allocation",
      body: "The trace shows the user-controlled length reaches the allocation size.",
      source: "trace.log:12",
    })
    const graph = await FGS.read({ root: dir.path })

    expect(graph.goals).toHaveLength(1)
    expect(graph.steps[0]?.priority).toBe(90)
    expect(graph.facts[0]?.parent_ids).toContain(step.id)
    expect(graph.edges).toEqual([
      { from: goal.id, to: step.id },
      { from: step.id, to: fact.id },
    ])
    const context = await FGS.context(dir.path)
    expect(context).toContain(`Fact [${fact.id}]`)
    expect(context).toContain(`<- ${step.id}`)
    expect((await Blackboard.render({ root: dir.path })).toString()).toContain("## Goals")
  })

  test("requires a real Goal for Steps and a real Step for Facts", async () => {
    await using dir = await tmpdir()
    await expect(
      FGS.step({ root: dir.path, goal_id: "bb_missing", title: "orphan", body: "not allowed" }),
    ).rejects.toThrow("FGS entry not found")
    await expect(
      FGS.fact({ root: dir.path, step_id: "bb_missing", title: "orphan", body: "not allowed" }),
    ).rejects.toThrow("FGS entry not found")
  })

  test("updates lifecycle without scheduling or deleting nodes", async () => {
    await using dir = await tmpdir()
    const goal = await FGS.goal({ root: dir.path, title: "Review sample", body: "Review all parser paths." })
    const step = await FGS.step({ root: dir.path, goal_id: goal.id, title: "Inspect imports", body: "Read imports." })
    await FGS.updateStep({ root: dir.path, id: step.id, status: "active", priority: 100 })
    await FGS.updateGoal({ root: dir.path, id: goal.id, status: "completed" })
    expect((await FGS.read({ root: dir.path })).nodes).toHaveLength(2)
    expect(await Blackboard.history(dir.path)).toHaveLength(4)
  })
})
