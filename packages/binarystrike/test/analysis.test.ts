import { describe, expect, test } from "bun:test"
import path from "path"
import { tmpdir } from "./fixture.js"
import { BinaryAnalysis } from "../src/analysis.js"

describe("BinaryAnalysis", () => {
  test("identifies a minimal ELF header and extracts strings", async () => {
    await using dir = await tmpdir()
    const file = path.join(dir.path, "sample")
    const bytes = new Uint8Array(96)
    bytes.set([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01], 0)
    bytes[18] = 62
    bytes[24] = 0x40
    bytes[60] = 3
    bytes.set(new TextEncoder().encode("system /bin/sh password=secret"), 64)
    await Bun.write(file, bytes)

    const result = await BinaryAnalysis.analyze({ file, limit: 20 })

    expect(result.kind).toBe("elf")
    expect(result.arch).toBe("x86_64")
    expect(result.bits).toBe(64)
    expect(result.sha256).toHaveLength(64)
    expect(result.findings.some((item) => item.kind === "process")).toBe(true)
    expect(result.findings.some((item) => item.kind === "secret")).toBe(true)
    expect(result.dynamic_debugging.some((cmd) => cmd.startsWith("gdb"))).toBe(true)
    expect(result.re_tools.some((tool) => tool.id === "ghidra")).toBe(true)
  })

  test("plans firmware and angr workflows", async () => {
    await using dir = await tmpdir()
    const file = path.join(dir.path, "firmware.bin")
    const bytes = new Uint8Array(128)
    bytes.set(new TextEncoder().encode("header hsqs /etc/passwd token=abc"), 16)
    await Bun.write(file, bytes)

    const firmware = await BinaryAnalysis.analyzeFirmware({ file })
    const angr = await BinaryAnalysis.angrExplore({
      file,
      find: ["0x401000"],
      avoid: ["0x400800"],
      argv: ["--check"],
      stdin: "AAAA",
    })

    expect(firmware.indicators.some((item) => item.kind === "squashfs" && item.found)).toBe(true)
    expect(firmware.tools.some((tool) => tool.id === "binwalk")).toBe(true)
    expect(firmware.workflows.some((flow) => flow.commands.some((cmd) => cmd.includes("syft")))).toBe(true)
    expect(angr.script).toContain("find = [4198400]")
    expect(angr.script).toContain("avoid = [4196352]")
  })
})
