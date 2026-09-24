---
name: dynamic-debugging
description: Authorized dynamic debugging workflow for native binaries, mobile apps, and firmware-like targets
tags: [binary, reverse-engineering, debugging, gdb, lldb, frida, strace, ltrace]
version: "1.0"
---

# Dynamic Debugging Workflow

Use this skill only for authorized binaries, lab targets, owned systems, or explicit assessment scope.

## Goals

- Reproduce the behavior under a debugger or tracer.
- Capture crash inputs, stack traces, registers, loaded libraries, syscalls, and network/file activity.
- Identify attacker-controlled data flow into dangerous sinks.
- Preserve enough evidence for a reproducible vulnerability report and retest.

## Preparation

1. Record file metadata:

```bash
file ./target
sha256sum ./target
strings -a ./target | head -200
```

2. Collect static context:

```bash
readelf -h -S -s ./target
objdump -d -M intel ./target | less
checksec --file=./target
```

3. Create an evidence directory:

```bash
mkdir -p .binarystrike/reports/debug-evidence
```

## Linux Native

### Reproduce With Tracing

```bash
strace -f -s 256 -o .binarystrike/reports/debug-evidence/trace.strace ./target
ltrace -f -s 256 -o .binarystrike/reports/debug-evidence/trace.ltrace ./target
```

Look for:

- File reads from unexpected paths
- Network connections
- `execve`, `system`, `popen`
- `mprotect` or executable memory changes
- Crashes immediately after attacker-controlled input

### Debug With gdb

```bash
gdb -q ./target
set pagination off
set disassembly-flavor intel
run
bt full
info registers
info proc mappings
x/32gx $rsp
```

Useful breakpoints:

```gdb
break main
break system
break execve
break strcpy
break memcpy
break sprintf
catch syscall execve
catch syscall openat
catch syscall connect
```

Crash triage:

```gdb
run < crash.input
bt full
info registers
x/64bx $rsp
x/32i $rip-32
generate-core-file .binarystrike/reports/debug-evidence/core.dump
```

## macOS Native

```bash
lldb ./target
run
bt all
register read
image list
```

Set breakpoints:

```lldb
breakpoint set --name main
breakpoint set --name system
breakpoint set --name strcpy
breakpoint set --name memcpy
```

## Android / iOS

Use Frida for runtime hooks:

```bash
frida-ps -Uai
frida -U -f com.example.app -l hooks.js
```

Minimal hook template:

```js
Interceptor.attach(Module.findExportByName(null, "strcmp"), {
  onEnter(args) {
    console.log("strcmp", args[0].readCString(), args[1].readCString())
  },
})
```

For APKs:

```bash
jadx -d jadx-out ./target.apk
apktool d ./target.apk -o apktool-out
```

## Evidence Rules

Always save:

- Exact command line
- Input file or payload
- stdout/stderr
- debugger backtrace
- register state for crashes
- trace output
- binary hash

Prefer writing artifacts under:

```text
.binarystrike/reports/<session-id>/debug/
```

## Reporting Criteria

Report a vulnerability only when the evidence proves a real security impact:

- Crash is reachable by attacker-controlled input
- Memory corruption affects control flow or exploitable state
- Secret extraction is confirmed
- Privilege boundary is crossed
- Dangerous syscall or command execution is attacker-influenced

Do not report generic crashes, unreachable code paths, or tool warnings without a reproducible exploit path.
