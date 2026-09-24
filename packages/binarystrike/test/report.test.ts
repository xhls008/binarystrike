import { describe, expect, test } from "bun:test"
import path from "path"
import { tmpdir } from "./fixture.js"
import { Blackboard } from "../src/blackboard.js"
import { Report } from "../src/report.js"

describe("Report.generate", () => {
  test("writes report formats inside the project", async () => {
    await using dir = await tmpdir()
    const fact = await Blackboard.write({
      root: dir.path,
      kind: "fact",
      title: "Parser accepts a user-controlled length",
      body: "Observed in the authorized sample.",
    })
    const intent = await Blackboard.write({
      root: dir.path,
      kind: "intent",
      title: "Verify the allocation sink",
      body: "Trace the length into the allocation.",
      parent_ids: [fact.id],
    })
    const result = await Report.generate({
      root: dir.path,
      session: "ses_test",
      findings: [
        {
          severity: "high",
          status: "confirmed",
          title: "Heap overflow in parser",
          description: "Attacker-controlled length is used without a bounds check.",
          cwe: "CWE-122",
          location: "parse_header+0x84",
          endpoint: "firmware parser",
          attack_vector: "malformed length field",
          blackboard_ids: [fact.id, intent.id],
          confidence: "confirmed",
          evidence: ["sha256:abc123", "gdb backtrace"],
          poc: "python3 reproduce.py sample.bin",
          business_impact: "Code execution in the update service.",
        },
      ],
      evidence: [
        {
          id: "request-1",
          kind: "request",
          label: "Reproduction request",
          content: "GET /health HTTP/1.1\\nHost: example.test\\n",
        },
      ],
    })

    expect(result.directory).toBe(path.join(dir.path, ".binarystrike", "reports", "ses_test"))
    expect(result.files).toHaveLength(4)
    expect(result.evidence).toBe(1)
    expect(result.methodology).toBeNumber()
    expect(result.chains).toBe(0)
    expect(await Bun.file(path.join(result.directory, "report.json")).json()).toMatchObject({
      session: "ses_test",
      evidence: [{ id: "request-1", kind: "request" }],
      methodology: { graph: { facts: 1, intents: 1 } },
    })
    const markdown = await Bun.file(path.join(result.directory, "report.md")).text()
    expect(markdown).toContain("Reproduction request")
    expect(markdown).toContain("malformed length field")
    expect(markdown).toContain(`${fact.id}, ${intent.id}`)
    expect(markdown).toContain("Proof Of Concept")
    expect(markdown).toContain("Business Impact")
    expect(await Bun.file(path.join(result.directory, "evidence", "request-1.txt")).text()).toContain("GET /health")
    expect(await Bun.file(path.join(result.directory, "report.html")).text()).toContain("BinaryStrike Report")
  })

  test("rejects findings that cite an unknown blackboard entry", async () => {
    await using dir = await tmpdir()
    expect(
      Report.generate({
        root: dir.path,
        findings: [
          {
            severity: "low",
            status: "unverified",
            title: "Unverified lead",
            description: "Needs corroboration.",
            evidence: [],
            blackboard_ids: ["bb_missing"],
          },
        ],
      }),
    ).rejects.toThrow("blackboard entry not found")
  })

  test("rejects output outside the project", async () => {
    await using dir = await tmpdir()
    expect(
      Report.generate({
        root: dir.path,
        findings: [],
        dir: "../outside",
      }),
    ).rejects.toThrow("stay inside")
  })

  test("keeps evidence when a report has no findings", async () => {
    await using dir = await tmpdir()
    const result = await Report.generate({
      root: dir.path,
      findings: [],
      evidence: [{ id: "trace", kind: "artifact", content: "clean sample" }],
      format: ["markdown"],
    })

    const markdown = await Bun.file(path.join(result.directory, "report.md")).text()
    expect(markdown).toContain("No findings were supplied.")
    expect(markdown).toContain("trace (artifact)")
  })
})
