export type Platform = "linux-ebpf" | "cicd" | "macos" | "windows"

export type Step = {
  id: string
  title: string
  purpose: string
  command: string
  read_only: true
  evidence: string
}

export type Plan = {
  platform: Platform
  scope: string
  prerequisites: string[]
  steps: Step[]
  safety: string[]
}

type Catalog = Omit<Plan, "platform" | "scope"> & { steps: Step[] }

const catalogs: Record<Platform, Catalog> = {
  "linux-ebpf": {
    prerequisites: ["Use an authorized Linux host or lab image.", "Collect kernel state without attaching programs or changing BPF policy."],
    safety: [
      "This tool only returns a plan; it never loads, attaches, detaches, or modifies an eBPF program.",
      "Do not capture credentials, keystrokes, TLS plaintext, or process memory through this read-only slice.",
      "Record capability and policy failures as Facts and require an explicit Intent for any later instrumentation.",
    ],
    steps: [
      {
        id: "kernel",
        title: "Identify kernel and BPF support",
        purpose: "Establish kernel version and whether the host advertises BPF support.",
        command: "uname -a && bpftool feature probe kernel",
        read_only: true,
        evidence: "kernel release, architecture, BPF helper, and verifier capabilities",
      },
      {
        id: "programs",
        title: "Inventory loaded BPF programs",
        purpose: "Review existing instrumentation without changing attachments or maps.",
        command: "bpftool prog show && bpftool link show",
        read_only: true,
        evidence: "program IDs, types, attach points, owners, and link state",
      },
      {
        id: "policy",
        title: "Review BPF policy controls",
        purpose: "Understand lockdown, LSM, and filesystem controls that constrain instrumentation.",
        command: "cat /sys/kernel/security/lsm; mountpoint /sys/fs/bpf; sysctl kernel.unprivileged_bpf_disabled",
        read_only: true,
        evidence: "LSM list, BPF filesystem state, and unprivileged BPF policy",
      },
    ],
  },
  cicd: {
    prerequisites: ["Declare the authorized organization, repository, or CI host.", "Use metadata/list API permissions only for the inventory phase."],
    safety: [
      "This tool only returns a plan; it never calls GitHub, GitLab, Jenkins, or a CI runner.",
      "Do not retrieve secret values, dispatch workflows, modify pipeline files, or create webhooks.",
      "Record repository and runner metadata as Facts and treat exposed-secret indicators as Hints until verified.",
    ],
    steps: [
      {
        id: "repository",
        title: "Inventory repository controls",
        purpose: "Map branch protection, visibility, owners, and workflow locations.",
        command: "git remote -v && git branch --all --format='%(refname:short)'",
        read_only: true,
        evidence: "remote hosts, branches, protected-branch metadata, and workflow paths",
      },
      {
        id: "pipeline",
        title: "Inspect pipeline definitions",
        purpose: "Identify triggers, third-party actions, artifacts, and privileged runner contexts.",
        command: "git ls-files '.github/workflows/*' '.gitlab-ci.yml' 'Jenkinsfile'",
        read_only: true,
        evidence: "pipeline files, trigger events, action references, and deployment stages",
      },
      {
        id: "runner",
        title: "Inventory runner metadata",
        purpose: "Map runner labels and trust boundaries without starting a job.",
        command: "git grep -n -E 'runs-on:|tags:|executor:|privileged:' -- .github .gitlab-ci.yml Jenkinsfile",
        read_only: true,
        evidence: "runner labels, privileged flags, container executors, and environment boundaries",
      },
    ],
  },
  macos: {
    prerequisites: ["Use an authorized macOS host or lab image.", "Do not disable SIP, TCC, Gatekeeper, or logging for inventory."],
    safety: [
      "This tool only returns a plan; it never reads password stores, captures keys, bypasses TCC, or changes logs.",
      "Treat keychain and browser stores as sensitive assets; collect metadata only.",
      "Require an explicit, reviewed Intent before any runtime tracing or host change.",
    ],
    steps: [
      {
        id: "identity",
        title: "Identify macOS security posture",
        purpose: "Collect version, architecture, SIP, and Gatekeeper posture.",
        command: "sw_vers; uname -a; csrutil status; spctl --status",
        read_only: true,
        evidence: "OS build, architecture, SIP state, and assessment policy",
      },
      {
        id: "logging",
        title: "Inventory security logging",
        purpose: "Establish available unified logging and audit controls without clearing them.",
        command: "log show --last 1h --style syslog --info --debug | head -200",
        read_only: true,
        evidence: "recent security-relevant events and logging availability",
      },
      {
        id: "runtime",
        title: "Inventory runtime controls",
        purpose: "Map launch services and endpoint-security posture without persistence changes.",
        command: "launchctl print system; systemextensionsctl list",
        read_only: true,
        evidence: "launch domains, loaded services, and system extensions",
      },
    ],
  },
  windows: {
    prerequisites: ["Use an authorized Windows host or lab image.", "Do not bypass Defender, AMSI, ETW, or event logging for inventory."],
    safety: [
      "This tool only returns a plan; it never dumps credentials, patches AMSI/ETW, clears logs, or changes Defender.",
      "Collect privilege and control metadata only; do not access LSASS, SAM, DPAPI, or browser secrets.",
      "Require explicit scope and a reviewed Intent before any monitored action.",
    ],
    steps: [
      {
        id: "identity",
        title: "Identify Windows security posture",
        purpose: "Collect OS, principal, privilege, and elevation metadata.",
        command: "whoami /all; systeminfo",
        read_only: true,
        evidence: "principal, groups, privileges, OS build, and architecture",
      },
      {
        id: "defender",
        title: "Inventory endpoint protection",
        purpose: "Record Defender and security-provider posture without changing exclusions.",
        command: "Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled",
        read_only: true,
        evidence: "protection status, signatures, and real-time monitoring state",
      },
      {
        id: "logging",
        title: "Inventory event logging",
        purpose: "Identify available event channels and audit policy without clearing records.",
        command: "Get-WinEvent -ListLog * | Where-Object {$_.IsEnabled} | Select-Object LogName,RecordCount",
        read_only: true,
        evidence: "enabled channels and event counts",
      },
    ],
  },
}

function clean(value: string | undefined, fallback: string) {
  const result = value?.trim()
  return result || fallback
}

export namespace PlatformPlan {
  export function plan(input: { platform: Platform; scope?: string; focus?: string }) {
    const catalog = catalogs[input.platform]
    const focus = input.focus?.trim().toLowerCase()
    const steps = focus
      ? catalog.steps.filter((step) => step.id === focus || step.title.toLowerCase().includes(focus))
      : catalog.steps
    if (!steps.length) throw new Error(`Unknown ${input.platform} platform planning focus: ${input.focus}`)
    return {
      platform: input.platform,
      scope: clean(input.scope, "authorized host or repository scope (declare before execution)"),
      prerequisites: [...catalog.prerequisites],
      steps: steps.map((step) => ({ ...step })),
      safety: [...catalog.safety],
    } satisfies Plan
  }
}
