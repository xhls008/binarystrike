import { describe, expect, test } from "bun:test"
import { Blackboard } from "../src/blackboard.js"
import { Finding } from "../src/finding.js"
import { FGS } from "../src/fgs.js"
import { Report } from "../src/report.js"
import { tmpdir } from "./fixture.js"
import path from "path"

const data = {
  severity: "high" as const,
  title: "IDOR in order lookup",
  description: "The order identifier is accepted without an authorization check.",
  cwe: "CWE-639",
  endpoint: "GET /api/orders/{id}",
  attack_vector: "path_parameter",
  reproduction: "Replace the identifier with another user's order.",
}

describe("Finding", () => {
  test("records candidates, returns similar findings, and triages duplicates", async () => {
    await using dir = await tmpdir()
    const first = await Finding.record({ root: dir.path, ...data })
    const second = await Finding.record({ root: dir.path, ...data, title: "IDOR in order detail" })

    expect(first.status).toBe("new")
    expect(second.status).toBe("new")
    expect(second.similar[0]?.id).toBe(first.id)
    expect((await Blackboard.read({ root: dir.path, kind: ["hint"] })).map((entry) => entry.id)).toContain(
      second.blackboard_id!,
    )
    const context = await Finding.context(dir.path)
    expect(context).toContain("Pending BinaryStrike Findings")
    expect(context).toContain(second.id)
    expect(context?.length).toBeLessThan(12_200)

    const triaged = await Finding.update({
      root: dir.path,
      id: second.id,
      status: "duplicate",
      duplicate_of: first.id,
    })
    expect(triaged.status).toBe("duplicate")
    expect(triaged.duplicate_of).toBe(first.id)
    expect((await Blackboard.read({ root: dir.path, status: "superseded" })).map((entry) => entry.id)).toContain(
      second.blackboard_id!,
    )
    const restored = await Finding.update({ root: dir.path, id: second.id, status: "approved" })
    expect(restored.status).toBe("approved")
    expect(restored.duplicate_of).toBeNull()
    expect(await Finding.history(dir.path)).toHaveLength(5)
  })

  test("promotes an approved candidate from hint to fact without deleting history", async () => {
    await using dir = await tmpdir()
    const finding = await Finding.record({ root: dir.path, ...data })
    const approved = await Finding.update({ root: dir.path, id: finding.id, status: "approved" })
    const facts = await Blackboard.read({ root: dir.path, kind: ["fact"] })

    expect(approved.fact_id).toBeString()
    expect(facts).toHaveLength(1)
    expect(facts[0]?.parent_ids).toContain(finding.blackboard_id!)
    expect((await Blackboard.history(dir.path)).map((event) => event.type)).toEqual([
      "created",
      "created",
      "updated",
      "updated",
      "created",
    ])
  })

  test("exposes verification as an intent and closes it without asserting ignored findings", async () => {
    await using dir = await tmpdir()
    const finding = await Finding.record({ root: dir.path, ...data })
    const open = await Finding.update({ root: dir.path, id: finding.id, status: "open" })
    expect(open.intent_id).toBeString()
    expect((await Blackboard.read({ root: dir.path, kind: ["intent"] }))[0]?.status).toBe("active")

    const ignored = await Finding.update({ root: dir.path, id: finding.id, status: "ignored" })
    expect(ignored.status).toBe("ignored")
    expect((await Blackboard.read({ root: dir.path, kind: ["intent"] }))[0]?.status).toBe("rejected")
    expect(await Blackboard.read({ root: dir.path, kind: ["fact"] })).toHaveLength(0)
  })

  test("supersedes the confirmed fact when a finding is fixed", async () => {
    await using dir = await tmpdir()
    const finding = await Finding.record({ root: dir.path, ...data })
    const approved = await Finding.update({ root: dir.path, id: finding.id, status: "approved" })
    await Finding.update({ root: dir.path, id: finding.id, status: "fixed" })
    expect((await Blackboard.read({ root: dir.path })).find((entry) => entry.id === approved.fact_id)?.status).toBe("superseded")
  })

  test("requires valid blackboard references and supports report export by finding id", async () => {
    await using dir = await tmpdir()
    const fact = await Blackboard.write({
      root: dir.path,
      kind: "fact",
      title: "Observed unauthorized order access",
      body: "A second account can retrieve the order.",
    })
    const finding = await Finding.record({ root: dir.path, ...data, blackboard_ids: [fact.id] })
    const report = await Report.generate({ root: dir.path, finding_ids: [finding.id], format: ["json"] })
    expect(report.findings).toBe(1)
    expect(await Bun.file(path.join(report.directory, "report.json")).json()).toMatchObject({
      findings: [{ title: data.title, blackboard_ids: [fact.id] }],
    })
    await expect(Finding.record({ root: dir.path, ...data, blackboard_ids: ["bb_missing"] })).rejects.toThrow(
      "blackboard entry not found",
    )
  })

  test("does not allow a duplicate to point to itself or an unknown finding", async () => {
    await using dir = await tmpdir()
    const finding = await Finding.record({ root: dir.path, ...data })
    await expect(
      Finding.update({ root: dir.path, id: finding.id, status: "duplicate", duplicate_of: finding.id }),
    ).rejects.toThrow("duplicate target")
    await expect(
      Finding.update({ root: dir.path, id: finding.id, status: "duplicate", duplicate_of: "finding_missing" }),
    ).rejects.toThrow("duplicate target")
  })

  test("links a finding hint to an FGS verification step and confirmed fact", async () => {
    await using dir = await tmpdir()
    const goal = await FGS.goal({
      root: dir.path,
      title: "Validate authorization controls",
      body: "Finish when the candidate is confirmed or rejected.",
    })
    const finding = await Finding.record({ root: dir.path, ...data, goal_id: goal.id })
    const opened = await Finding.update({ root: dir.path, id: finding.id, status: "open" })
    expect(opened.step_id).toBeString()
    const step = (await Blackboard.read({ root: dir.path })).find((entry) => entry.id === opened.step_id)
    expect(step?.kind).toBe("step")
    expect(step?.parent_ids).toContain(opened.blackboard_id!)

    const approved = await Finding.update({ root: dir.path, id: finding.id, status: "approved" })
    const fact = (await Blackboard.read({ root: dir.path })).find((entry) => entry.id === approved.fact_id)
    expect(fact?.kind).toBe("fact")
    expect(fact?.parent_ids).toContain(opened.step_id!)
    expect((await Blackboard.read({ root: dir.path })).find((entry) => entry.id === opened.step_id)?.status).toBe("completed")
    await Finding.update({ root: dir.path, id: finding.id, status: "fixed" })
    expect((await Blackboard.read({ root: dir.path })).find((entry) => entry.id === opened.step_id)?.status).toBe("completed")
  })
})
