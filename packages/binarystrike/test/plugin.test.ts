import { describe, expect, test } from "bun:test"
import { Blackboard } from "../src/blackboard.js"
import plugin from "../src/plugin.js"
import { tmpdir } from "./fixture.js"

type Registered = {
  name: string
  options?: { permission?: string }
  execute: (input: Record<string, unknown>, context?: { signal?: AbortSignal }) => Promise<unknown>
}

describe("BinaryStrike plugin", () => {
  test("registers V2 tools and the blackboard context hook", async () => {
    const names: string[] = []
    const hooks: string[] = []
    const callbacks: ((event: { agent: string; messages: unknown[] }) => Promise<void>)[] = []
    const context = {
      location: { directory: process.cwd(), workspaceID: "test" },
      session: {
        hook: async (name: string, callback: (event: { agent: string; messages: unknown[] }) => Promise<void>) => {
          hooks.push(name)
          callbacks.push(callback)
        },
      },
      tool: {
        transform: async (apply: (editor: { add: (tool: { name: string }) => void }) => void) =>
          apply({ add: (tool) => names.push(tool.name) }),
      },
    } as unknown as Parameters<NonNullable<typeof plugin.setup>>[0]

    await plugin.setup(context)

    expect(names).toEqual([
      "analyze_binary",
      "binary_re_toolkit",
      "analyze_firmware",
      "dynamic_debug",
      "angr_explore",
      "export_report",
      "record_finding",
      "get_findings",
      "triage_finding",
      "methodology_status",
      "fgs_read",
      "fgs_create_goal",
      "fgs_add_step",
      "fgs_update_goal",
      "fgs_update_step",
      "submit_fact",
      "get_chains",
      "cloud_plan",
      "platform_plan",
      "record_intel",
      "get_intel",
      "update_intel",
      "retest_request",
      "record_http_observation",
      "record_browser_observation",
      "get_http_observations",
      "update_http_observation",
      "scope_check",
      "blackboard_write",
      "blackboard_read",
      "blackboard_update",
      "record_coverage_note",
      "get_coverage_notes",
      "record_vrt_check",
    ])
    expect(hooks).toEqual(["context"])
  })

  test("injects blackboard context as untrusted user content and avoids duplicates", async () => {
    await using dir = await tmpdir()
    const callbacks: ((event: { agent: string; messages: unknown[] }) => Promise<void>)[] = []
    const context = {
      location: { directory: dir.path, workspaceID: "test" },
      session: {
        hook: async (_name: string, callback: (event: { agent: string; messages: unknown[] }) => Promise<void>) => {
          callbacks.push(callback)
        },
      },
      tool: {
        transform: async (apply: (editor: { add: (tool: { name: string }) => void }) => void) =>
          apply({ add: () => undefined }),
      },
    } as unknown as Parameters<NonNullable<typeof plugin.setup>>[0]

    await Blackboard.write({
      root: dir.path,
      kind: "fact",
      title: "Fixture fact",
      body: "Observed in a test fixture.",
      source: "plugin.test.ts",
      confidence: "confirmed",
    })
    await plugin.setup(context)
    const event = { agent: "binary-security", messages: [] as unknown[] }
    await callbacks[0]!(event)
    expect(event.messages).toHaveLength(2)
    expect(event.messages.every((message) => (message as { role: string }).role === "user")).toBe(true)
    expect(JSON.stringify(event.messages[0])).toContain(Blackboard.Marker)
    await callbacks[0]!(event)
    expect(event.messages).toHaveLength(2)

    const spoofed = { agent: "binary-security", messages: [{ role: "user", content: [{ type: "text", text: Blackboard.Marker }] }] }
    await callbacks[0]!(spoofed)
    expect(spoofed.messages).toHaveLength(3)

    const decide = { agent: "binary-security-decide", messages: [] as unknown[] }
    await callbacks[0]!(decide)
    expect(decide.messages).toHaveLength(2)

    const execute = { agent: "binary-security-execute", messages: [] as unknown[] }
    await callbacks[0]!(execute)
    expect(execute.messages).toHaveLength(2)
  })

  test("executes project-confined analysis tools through the V2 registration", async () => {
    await using dir = await tmpdir()
    await using outside = await tmpdir()
    const tools = new Map<string, Registered>()
    const context = {
      location: { directory: dir.path, workspaceID: "test" },
      session: { hook: async () => undefined },
      tool: {
        transform: async (apply: (editor: { add: (tool: { name: string }) => void }) => void) =>
          apply({
            add: (tool) => tools.set(tool.name, tool as unknown as Registered),
          }),
      },
    } as unknown as Parameters<NonNullable<typeof plugin.setup>>[0]
    const file = "sample.bin"
    await Bun.write(`${dir.path}/${file}`, new Uint8Array([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]))
    await Bun.write(`${outside.path}/outside.bin`, new Uint8Array([0]))
    await plugin.setup(context)

    const result = await tools.get("analyze_binary")!.execute({ file })
    expect((result as { output: { kind: string } }).output.kind).toBe("elf")
    await expect(tools.get("analyze_binary")!.execute({ file: `${outside.path}/outside.bin` })).rejects.toThrow(
      "must stay inside",
    )
  })

  test("keeps write-tool permissions visible to the binary-security policy", async () => {
    const tools = new Map<string, Registered>()
    const context = {
      location: { directory: process.cwd(), workspaceID: "test" },
      session: { hook: async () => undefined },
      tool: {
        transform: async (apply: (editor: { add: (tool: Registered) => void }) => void) =>
          apply({ add: (tool) => tools.set(tool.name, tool) }),
      },
    } as unknown as Parameters<NonNullable<typeof plugin.setup>>[0]
    await plugin.setup(context)

    for (const name of [
      "export_report",
      "record_finding",
      "triage_finding",
      "fgs_create_goal",
      "fgs_add_step",
      "fgs_update_goal",
      "fgs_update_step",
      "submit_fact",
      "record_intel",
      "update_intel",
      "cloud_plan",
      "platform_plan",
      "record_http_observation",
      "record_browser_observation",
      "update_http_observation",
      "blackboard_write",
      "blackboard_update",
      "record_coverage_note",
      "record_vrt_check",
    ]) {
      expect(tools.get(name)?.options?.permission).toBe(
        ["fgs_create_goal", "fgs_add_step", "fgs_update_goal", "fgs_update_step"].includes(name)
          ? "fgs_write"
          : name,
      )
    }
    expect(tools.get("retest_request")?.options?.permission).toBe("webfetch")
    expect(tools.get("blackboard_read")?.options?.permission).toBe("read")
  })
})
