import path from "path"
import { createHash } from "crypto"

type Kind = "elf" | "pe" | "mach-o" | "apk" | "zip" | "unknown"

type Finding = {
  kind: string
  value: string
  reason: string
}

export namespace BinaryAnalysis {
  export type Capability = {
    id: string
    name: string
    category: "re" | "firmware" | "dynamic" | "symbolic"
    command: string
    available: boolean
    path?: string
    purpose: string
  }

  export type Workflow = {
    name: string
    purpose: string
    commands: string[]
    available: boolean
  }

  export type FirmwareIndicator = {
    kind: string
    found: boolean
    reason: string
  }

  export type ToolchainResult = {
    file: string
    kind: Kind
    tools: Capability[]
    workflows: Workflow[]
    opencode_upgrade: Upgrade
  }

  export type FirmwareResult = {
    file: string
    kind: Kind
    indicators: FirmwareIndicator[]
    tools: Capability[]
    workflows: Workflow[]
    opencode_upgrade: Upgrade
  }

  export type DynamicResult = {
    file: string
    kind: Kind
    tools: Capability[]
    workflows: Workflow[]
    qiling_harness: string
    opencode_upgrade: Upgrade
  }

  export type AngrResult = {
    file: string
    kind: Kind
    tools: Capability[]
    command: string
    script: string
    opencode_upgrade: Upgrade
  }

  type Upgrade = {
    classification: "binarystrike-only"
    rationale: string
  }

  export type Result = {
    file: string
    size: number
    sha256: string
    kind: Kind
    arch?: string
    bits?: 32 | 64
    endian?: "little" | "big"
    entrypoint?: string
    sections?: number
    strings: string[]
    findings: Finding[]
    re_tools: Capability[]
    firmware_analysis: FirmwareResult
    dynamic_debugging: string[]
    dynamic_debugging_plan: DynamicResult
    angr_exploration: AngrResult
    opencode_upgrade: Upgrade
  }

  function upgrade(rationale: string): Upgrade {
    return {
      classification: "binarystrike-only",
      rationale,
    }
  }

  function hex(value: number | bigint) {
    return "0x" + value.toString(16)
  }

  function q(value: string) {
    return JSON.stringify(value)
  }

  function stem(file: string) {
    return path.basename(file).replace(/[^a-zA-Z0-9_.-]+/g, "_")
  }

  function capability(
    id: string,
    name: string,
    category: Capability["category"],
    command: string,
    purpose: string,
  ): Capability {
    const found = Bun.which(command) ?? undefined
    return {
      id,
      name,
      category,
      command,
      available: found !== undefined,
      path: found,
      purpose,
    }
  }

  function available(tools: Capability[], command: string) {
    return tools.some((tool) => tool.command === command && tool.available)
  }

  function has(bytes: Uint8Array, pattern: number[]) {
    return bytes.some((_, index) => pattern.every((byte, offset) => bytes[index + offset] === byte))
  }

  function cstr(bytes: Uint8Array, min: number, limit: number) {
    const out: string[] = []
    let buf = ""
    for (const byte of bytes) {
      if (byte >= 32 && byte <= 126) {
        buf += String.fromCharCode(byte)
        continue
      }
      if (buf.length >= min) out.push(buf)
      if (out.length >= limit) return out
      buf = ""
    }
    if (buf.length >= min && out.length < limit) out.push(buf)
    return out
  }

  function le16(bytes: Uint8Array, offset: number) {
    return bytes[offset] | (bytes[offset + 1] << 8)
  }

  function le32(bytes: Uint8Array, offset: number) {
    return (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) >>> 0
  }

  function le64(bytes: Uint8Array, offset: number) {
    return BigInt(le32(bytes, offset)) | (BigInt(le32(bytes, offset + 4)) << 32n)
  }

  function arch(kind: Kind, value?: number) {
    if (kind === "elf") {
      return (
        {
          3: "x86",
          40: "arm",
          62: "x86_64",
          183: "aarch64",
          243: "riscv",
        }[value ?? 0] ?? (value ? `machine-${value}` : undefined)
      )
    }
    if (kind === "pe") {
      return (
        {
          0x014c: "x86",
          0x8664: "x86_64",
          0x01c0: "arm",
          0xaa64: "aarch64",
        }[value ?? 0] ?? (value ? `machine-${hex(value)}` : undefined)
      )
    }
  }

  function identify(
    bytes: Uint8Array,
    file: string,
  ): Pick<Result, "kind" | "arch" | "bits" | "endian" | "entrypoint" | "sections"> {
    if (bytes[0] === 0x7f && bytes[1] === 0x45 && bytes[2] === 0x4c && bytes[3] === 0x46) {
      const bits = bytes[4] === 2 ? 64 : 32
      const endian = bytes[5] === 2 ? "big" : "little"
      return {
        kind: "elf",
        bits,
        endian,
        arch: arch("elf", le16(bytes, 18)),
        entrypoint: bits === 64 ? hex(le64(bytes, 24)) : hex(le32(bytes, 24)),
        sections: le16(bytes, bits === 64 ? 60 : 48),
      }
    }
    if (bytes[0] === 0x4d && bytes[1] === 0x5a) {
      const off = le32(bytes, 0x3c)
      if (bytes[off] === 0x50 && bytes[off + 1] === 0x45 && bytes[off + 2] === 0 && bytes[off + 3] === 0) {
        const magic = le16(bytes, off + 24)
        return {
          kind: "pe",
          bits: magic === 0x20b ? 64 : 32,
          endian: "little",
          arch: arch("pe", le16(bytes, off + 4)),
          sections: le16(bytes, off + 6),
          entrypoint: hex(le32(bytes, off + 40)),
        }
      }
    }
    const magic = le32(bytes, 0)
    if ([0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe].includes(magic)) {
      return {
        kind: "mach-o",
        bits: [0xfeedfacf, 0xcffaedfe].includes(magic) ? 64 : 32,
        endian: [0xcefaedfe, 0xcffaedfe].includes(magic) ? "big" : "little",
      }
    }
    if (bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x03 && bytes[3] === 0x04) {
      return { kind: path.extname(file).toLowerCase() === ".apk" ? "apk" : "zip" }
    }
    return { kind: "unknown" }
  }

  function findings(strings: string[]) {
    const patterns = [
      {
        kind: "unsafe-c",
        re: /\b(strcpy|strcat|gets|sprintf|vsprintf|scanf|memcpy)\b/i,
        reason: "unsafe C API may require bounds review",
      },
      {
        kind: "process",
        re: /\b(system|popen|execve|CreateProcess|WinExec|ShellExecute)\b/i,
        reason: "process execution surface",
      },
      {
        kind: "memory",
        re: /\b(mprotect|VirtualProtect|dlopen|LoadLibrary|ptrace)\b/i,
        reason: "runtime loading, tracing, or memory permission change",
      },
      {
        kind: "network",
        re: /\b(socket|connect|send|recv|WinHttp|InternetOpen|http:\/\/|https:\/\/)\b/i,
        reason: "network behavior",
      },
      {
        kind: "secret",
        re: /(AKIA[0-9A-Z]{16}|BEGIN [A-Z ]*PRIVATE KEY|password=|api[_-]?key=|token=)/i,
        reason: "possible embedded secret",
      },
    ]
    return strings.flatMap((value) =>
      patterns
        .filter((pattern) => pattern.re.test(value))
        .map((pattern) => ({
          kind: pattern.kind,
          value,
          reason: pattern.reason,
        })),
    )
  }

  function debug(file: string, result: Pick<Result, "kind">) {
    const quoted = JSON.stringify(file)
    const base = [`file ${quoted}`, `strings -a ${quoted} | head -200`, `sha256sum ${quoted}`]
    if (result.kind === "elf") {
      return [
        ...base,
        `readelf -h -S -s ${quoted}`,
        `objdump -d -M intel ${quoted} | less`,
        `gdb -q ${quoted}`,
        `strace -f -o trace.strace ${quoted}`,
        `ltrace -f -o trace.ltrace ${quoted}`,
      ]
    }
    if (result.kind === "pe") return [...base, `objdump -x ${quoted}`, `rabin2 -I -i -S -z ${quoted}`]
    if (result.kind === "mach-o") return [...base, `otool -hvl ${quoted}`, `lldb ${quoted}`]
    if (result.kind === "apk") return [...base, `unzip -l ${quoted}`, `jadx -d jadx-out ${quoted}`, `frida-ps -Uai`]
    return base
  }

  function re(file: string, info: Pick<Result, "kind">): ToolchainResult {
    const quoted = q(file)
    const dir = `.binarystrike/re/${stem(file)}`
    const tools = [
      capability(
        "ghidra",
        "Ghidra headless analyzer",
        "re",
        "analyzeHeadless",
        "Import and analyze binaries into a Ghidra project.",
      ),
      capability(
        "ida",
        "IDA batch analyzer",
        "re",
        "idat64",
        "Generate IDA auto-analysis database and assembly listings.",
      ),
      capability("ida_gui", "IDA GUI", "re", "ida64", "Open an interactive IDA Pro session."),
      capability("binary_ninja", "Binary Ninja", "re", "binaryninja", "Open an interactive Binary Ninja database."),
      capability("radare2", "radare2", "re", "r2", "Run scriptable auto-analysis and function triage."),
      capability("rizin", "Rizin", "re", "rizin", "Run scriptable auto-analysis and function triage."),
      capability("capa", "capa", "re", "capa", "Detect behavioral capabilities and suspicious code patterns."),
      capability("yara", "YARA", "re", "yara", "Run local rules over a binary or extracted firmware tree."),
      capability("rabin2", "rabin2", "re", "rabin2", "Extract imports, sections, symbols, and strings."),
      capability("jadx", "jadx", "re", "jadx", "Decompile Android APK bytecode."),
    ]
    const workflows = [
      {
        name: "Ghidra headless import",
        purpose: "Create a reusable project for decompiler, xref, function, and call graph review.",
        commands: [`mkdir -p ${q(dir)}`, `analyzeHeadless ${q(dir)} ${q(stem(file))} -import ${quoted} -overwrite`],
        available: available(tools, "analyzeHeadless"),
      },
      {
        name: "IDA auto-analysis",
        purpose: "Create an IDB/I64 database and batch analysis artifacts for follow-up review.",
        commands: [`mkdir -p ${q(dir)}`, `idat64 -A -B ${quoted}`],
        available: available(tools, "idat64"),
      },
      {
        name: "Binary Ninja review",
        purpose: "Open the sample in Binary Ninja for MLIL/HLIL guided review.",
        commands: [`binaryninja ${quoted}`],
        available: available(tools, "binaryninja"),
      },
      {
        name: "radare2 first pass",
        purpose: "Produce functions, imports, strings, and xrefs from a scriptable open-source RE backend.",
        commands: [`mkdir -p ${q(dir)}`, `r2 -A -q -c "iIj;aflj;izzj" ${quoted} > ${q(`${dir}/r2.json`)}`],
        available: available(tools, "r2"),
      },
      {
        name: "Capability scan",
        purpose: "Detect behavioral capabilities before deep manual reversing.",
        commands: [`mkdir -p ${q(dir)}`, `capa ${quoted} | tee ${q(`${dir}/capa.txt`)}`],
        available: available(tools, "capa"),
      },
      {
        name: "Android decompile",
        purpose: "Decompile APK code and resources for mobile binary review.",
        commands: [`mkdir -p ${q(dir)}`, `jadx -d ${q(`${dir}/jadx`)} ${quoted}`],
        available: info.kind === "apk" && available(tools, "jadx"),
      },
    ]
    return {
      file,
      kind: info.kind,
      tools,
      workflows,
      opencode_upgrade: upgrade(
        "Reverse-engineering IDE integration is a BinaryStrike security workflow, not generic opencode core behavior.",
      ),
    }
  }

  function firmware(file: string, bytes: Uint8Array, info: Pick<Result, "kind">): FirmwareResult {
    const quoted = q(file)
    const dir = `.binarystrike/firmware/${stem(file)}`
    const indicators = [
      {
        kind: "squashfs",
        found: has(bytes, [0x68, 0x73, 0x71, 0x73]) || has(bytes, [0x73, 0x71, 0x73, 0x68]),
        reason: "SquashFS root filesystems are common in firmware images.",
      },
      {
        kind: "ubi",
        found: has(bytes, [0x55, 0x42, 0x49, 0x23]),
        reason: "UBI images are common on NAND-backed embedded Linux devices.",
      },
      {
        kind: "uimage",
        found: has(bytes, [0x27, 0x05, 0x19, 0x56]),
        reason: "U-Boot legacy image header.",
      },
      {
        kind: "zip-container",
        found: info.kind === "zip" || info.kind === "apk",
        reason: "ZIP-like container may hold update bundles, APK content, or packaged firmware assets.",
      },
    ]
    const tools = [
      capability("binwalk", "Binwalk", "firmware", "binwalk", "Identify and recursively extract firmware regions."),
      capability("emba", "EMBA", "firmware", "emba", "Run firmware SBOM, secrets, config, and CVE checks."),
      capability("unsquashfs", "unsquashfs", "firmware", "unsquashfs", "Extract SquashFS root filesystems."),
      capability(
        "ubireader",
        "ubireader_extract_images",
        "firmware",
        "ubireader_extract_images",
        "Extract UBI/UBIFS images.",
      ),
      capability("jefferson", "Jefferson", "firmware", "jefferson", "Extract JFFS2 filesystems."),
      capability("yara", "YARA", "firmware", "yara", "Run local rules across extracted firmware trees."),
      capability("syft", "Syft", "firmware", "syft", "Create SBOMs from extracted filesystems."),
      capability("grype", "Grype", "firmware", "grype", "Scan SBOMs or filesystems for known vulnerable components."),
    ]
    return {
      file,
      kind: info.kind,
      indicators,
      tools,
      workflows: [
        {
          name: "Recursive extraction",
          purpose: "Extract nested filesystems and embedded payloads into an evidence directory.",
          commands: [`mkdir -p ${q(dir)}`, `binwalk -eM --directory ${q(dir)} ${quoted}`],
          available: available(tools, "binwalk"),
        },
        {
          name: "Firmware security audit",
          purpose: "Run EMBA modules for SBOM, credentials, configs, binaries, and known-vulnerable components.",
          commands: [`mkdir -p ${q(dir)}`, `emba -f ${quoted} -l ${q(`${dir}/emba`)}`],
          available: available(tools, "emba"),
        },
        {
          name: "Extracted filesystem triage",
          purpose:
            "Locate services, startup scripts, SUID files, keys, credentials, and native binaries after extraction.",
          commands: [
            `find ${q(dir)} -maxdepth 5 -type f | sed -n '1,300p'`,
            `find ${q(dir)} -type f -perm -4000 -o -perm -2000 2>/dev/null`,
            `grep -RInE "(password|passwd|secret|token|private key|BEGIN .* KEY)" ${q(dir)} 2>/dev/null | head -100`,
            `find ${q(dir)} -type f -name "*.so*" -o -perm -111 2>/dev/null | head -200`,
          ],
          available: true,
        },
        {
          name: "SBOM and CVE scan",
          purpose: "Generate an SBOM and scan components from extracted firmware evidence.",
          commands: [
            `mkdir -p ${q(dir)}`,
            `syft dir:${q(dir)} -o cyclonedx-json > ${q(`${dir}/sbom.cdx.json`)}`,
            `grype sbom:${q(`${dir}/sbom.cdx.json`)}`,
          ],
          available: available(tools, "syft") && available(tools, "grype"),
        },
      ],
      opencode_upgrade: upgrade(
        "Firmware unpacking, SBOM, and embedded filesystem review are BinaryStrike-only binary security workflows.",
      ),
    }
  }

  function qiling(file: string, args: readonly string[] = []) {
    return [
      "from qiling import Qiling",
      "from qiling.const import QL_VERBOSE",
      "",
      `target = ${JSON.stringify(file)}`,
      `argv = [target, ${args.map((arg) => JSON.stringify(arg)).join(", ")}]`,
      "",
      "# Pick the matching rootfs for the target OS and architecture.",
      "# Examples: examples/rootfs/x8664_linux, examples/rootfs/arm_linux, examples/rootfs/x8664_windows",
      'ql = Qiling(argv, "rootfs", verbose=QL_VERBOSE.DEFAULT)',
      "ql.run()",
      "",
    ].join("\n")
  }

  function dynamic(
    file: string,
    info: Pick<Result, "kind">,
    input: { args?: readonly string[]; stdin?: string } = {},
  ): DynamicResult {
    const quoted = q(file)
    const args = (input.args ?? []).map(q).join(" ")
    const run = [quoted, args].filter((item) => item.length > 0).join(" ")
    const stdin = input.stdin ? ` < ${q(input.stdin)}` : ""
    const dir = `.binarystrike/debug/${stem(file)}`
    const tools = [
      capability("gdb", "GDB", "dynamic", "gdb", "Debug ELF/native Linux samples and collect crash state."),
      capability("lldb", "LLDB", "dynamic", "lldb", "Debug Mach-O/native samples and collect crash state."),
      capability(
        "strace",
        "strace",
        "dynamic",
        "strace",
        "Trace Linux syscalls for file, process, and network behavior.",
      ),
      capability("ltrace", "ltrace", "dynamic", "ltrace", "Trace dynamic library calls."),
      capability("frida", "Frida", "dynamic", "frida", "Attach runtime hooks to native/mobile processes."),
      capability("frida_ps", "Frida process list", "dynamic", "frida-ps", "Discover mobile or local attach targets."),
      capability(
        "python",
        "Python",
        "dynamic",
        "python3",
        "Run Qiling or helper harnesses when modules are installed.",
      ),
    ]
    const workflows = [
      {
        name: "Linux syscall and library trace",
        purpose: "Capture non-invasive runtime behavior before interactive debugging.",
        commands: [
          `mkdir -p ${q(dir)}`,
          `strace -f -s 256 -o ${q(`${dir}/trace.strace`)} ${run}${stdin}`,
          `ltrace -f -s 256 -o ${q(`${dir}/trace.ltrace`)} ${run}${stdin}`,
        ],
        available: info.kind === "elf" && available(tools, "strace"),
      },
      {
        name: "GDB crash triage",
        purpose: "Collect backtrace, registers, mappings, and instruction context for a controlled local sample.",
        commands: [
          `mkdir -p ${q(dir)}`,
          `gdb -q --batch -ex "set pagination off" -ex "run" -ex "bt full" -ex "info registers" -ex "info proc mappings" --args ${run}`,
          `gdb -q --args ${run}`,
        ],
        available: info.kind === "elf" && available(tools, "gdb"),
      },
      {
        name: "LLDB crash triage",
        purpose: "Collect macOS backtrace, registers, and loaded image state.",
        commands: [
          `mkdir -p ${q(dir)}`,
          `lldb --batch -o "run" -o "bt all" -o "register read" -o "image list" -- ${run}`,
          `lldb ${quoted}`,
        ],
        available: info.kind === "mach-o" && available(tools, "lldb"),
      },
      {
        name: "Frida attach scaffold",
        purpose: "Hook dangerous APIs or APK/native-library functions during authorized runtime analysis.",
        commands: [
          `frida-ps -Uai`,
          `frida -U -f <package.name> -l ${q(`${dir}/hooks.js`)}`,
          `frida -f ${quoted} -l ${q(`${dir}/hooks.js`)}`,
        ],
        available: available(tools, "frida") || available(tools, "frida-ps"),
      },
      {
        name: "Qiling emulation scaffold",
        purpose: "Run a constrained user-mode emulator harness for native binaries when a rootfs is available.",
        commands: [`mkdir -p ${q(dir)}`, `python3 -m pip install qiling`, `python3 ${q(`${dir}/qiling_run.py`)}`],
        available: available(tools, "python3"),
      },
    ]
    return {
      file,
      kind: info.kind,
      tools,
      workflows,
      qiling_harness: qiling(file, input.args),
      opencode_upgrade: upgrade(
        "Dynamic binary debugging and emulation runners are BinaryStrike-only security workflows.",
      ),
    }
  }

  function parseAddress(value: string) {
    const trimmed = value.trim()
    const parsed = trimmed.toLowerCase().startsWith("0x")
      ? Number.parseInt(trimmed.slice(2), 16)
      : Number.parseInt(trimmed, 10)
    return Number.isFinite(parsed) ? parsed : undefined
  }

  function angrScript(
    file: string,
    input: { find?: readonly string[]; avoid?: readonly string[]; stdin?: string; argv?: readonly string[] },
  ) {
    const find = (input.find ?? []).map(parseAddress).filter((item): item is number => item !== undefined)
    const avoid = (input.avoid ?? []).map(parseAddress).filter((item): item is number => item !== undefined)
    const stdin = input.stdin ? JSON.stringify(input.stdin) : "None"
    const argv = JSON.stringify([file, ...(input.argv ?? [])])
    return [
      "#!/usr/bin/env python3",
      "import angr",
      "",
      `target = ${JSON.stringify(file)}`,
      `argv = ${argv}`,
      `find = ${JSON.stringify(find)}`,
      `avoid = ${JSON.stringify(avoid)}`,
      `stdin = ${stdin}`,
      "",
      "project = angr.Project(target, auto_load_libs=False)",
      "state = project.factory.entry_state(args=argv)",
      "if stdin is not None:",
      "    state = project.factory.entry_state(args=argv, stdin=stdin.encode())",
      "",
      "if not find:",
      "    cfg = project.analyses.CFGFast(normalize=True)",
      "    print('functions', len(cfg.kb.functions))",
      "    for addr, func in list(cfg.kb.functions.items())[:100]:",
      "        print(hex(addr), func.name)",
      "else:",
      "    simgr = project.factory.simgr(state)",
      "    simgr.explore(find=find, avoid=avoid)",
      "    print('found', len(simgr.found))",
      "    for found in simgr.found[:5]:",
      "        print(found.posix.dumps(0))",
      "",
    ].join("\n")
  }

  function angr(
    file: string,
    info: Pick<Result, "kind">,
    input: { find?: readonly string[]; avoid?: readonly string[]; stdin?: string; argv?: readonly string[] } = {},
  ): AngrResult {
    const dir = `.binarystrike/angr/${stem(file)}`
    const tools = [capability("python", "Python", "symbolic", "python3", "Run the generated angr exploration harness.")]
    return {
      file,
      kind: info.kind,
      tools,
      command: `mkdir -p ${q(dir)} && python3 ${q(`${dir}/angr_explore.py`)}`,
      script: angrScript(file, input),
      opencode_upgrade: upgrade(
        "angr symbolic exploration is specific to BinaryStrike binary vulnerability research workflows.",
      ),
    }
  }

  export async function analyze(input: { file: string; minString?: number; limit?: number }): Promise<Result> {
    const file = path.resolve(input.file)
    const data = new Uint8Array(await Bun.file(file).arrayBuffer())
    const strings = cstr(data, input.minString ?? 5, input.limit ?? 500)
    const info = identify(data, file)
    const dynamicPlan = dynamic(file, info)
    return {
      file,
      size: data.byteLength,
      sha256: createHash("sha256").update(data).digest("hex"),
      ...info,
      strings,
      findings: findings(strings).slice(0, 100),
      re_tools: re(file, info).tools,
      firmware_analysis: firmware(file, data, info),
      dynamic_debugging: debug(file, info),
      dynamic_debugging_plan: dynamicPlan,
      angr_exploration: angr(file, info),
      opencode_upgrade: upgrade(
        "Binary reverse engineering, firmware triage, dynamic debugging, and symbolic exploration are product-specific security capabilities, not generic opencode core behavior.",
      ),
    }
  }

  export async function toolchain(input: { file: string }) {
    const file = path.resolve(input.file)
    const info = identify(new Uint8Array(await Bun.file(file).arrayBuffer()), file)
    return re(file, info)
  }

  export async function analyzeFirmware(input: { file: string }) {
    const file = path.resolve(input.file)
    const data = new Uint8Array(await Bun.file(file).arrayBuffer())
    const info = identify(data, file)
    return firmware(file, data, info)
  }

  export async function dynamicDebug(input: { file: string; args?: readonly string[]; stdin?: string }) {
    const file = path.resolve(input.file)
    const info = identify(new Uint8Array(await Bun.file(file).arrayBuffer()), file)
    return dynamic(file, info, input)
  }

  export async function angrExplore(input: {
    file: string
    find?: readonly string[]
    avoid?: readonly string[]
    stdin?: string
    argv?: readonly string[]
  }) {
    const file = path.resolve(input.file)
    const info = identify(new Uint8Array(await Bun.file(file).arrayBuffer()), file)
    return angr(file, info, input)
  }
}
