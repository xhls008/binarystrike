export type Match = { scope: string; matches: boolean; reason: string }

function targetHost(value: string) {
  const input = value.toLowerCase().trim()
  try {
    return new URL(input.includes("://") ? input : `https://${input}`).hostname
  } catch {
    return input.replace(/^https?:\/\//, "").split("/")[0] ?? ""
  }
}

function ip(value: string) {
  const match = /^(\d+\.\d+\.\d+\.\d+)$/.exec(value)
  if (!match) return undefined
  const parts = match[1].split(".").map(Number)
  if (parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return undefined
  return parts.reduce((result, part) => result * 256 + part, 0)
}

function cidr(target: string, scope: string) {
  const [range, bits] = scope.split("/")
  const targetValue = ip(target)
  const rangeValue = ip(range)
  const width = Number(bits)
  if (targetValue === undefined || rangeValue === undefined || !Number.isInteger(width) || width < 0 || width > 32) {
    return undefined
  }
  const mask = width === 0 ? 0 : (0xffffffff << (32 - width)) >>> 0
  return (targetValue & mask) === (rangeValue & mask)
}

export function match(target: string, scope: string): Match {
  const value = targetHost(target)
  const rule = scope.toLowerCase().trim()
  if (!rule) return { scope: rule, matches: false, reason: "empty scope rule" }
  if (value === rule) return { scope: rule, matches: true, reason: "exact host match" }
  if (rule.startsWith("*.")) {
    const domain = rule.slice(2)
    if (value === domain || value.endsWith(`.${domain}`)) {
      return { scope: rule, matches: true, reason: `matches wildcard ${rule}` }
    }
    return { scope: rule, matches: false, reason: `does not match wildcard ${rule}` }
  }
  if (/^\d+\.\d+\.\d+\.\d+\/\d+$/.test(rule)) {
    const matches = cidr(value, rule)
    return matches === undefined
      ? { scope: rule, matches: false, reason: "target is not a valid IPv4 address" }
      : { scope: rule, matches, reason: matches ? `IPv4 address is inside ${rule}` : `IPv4 address is outside ${rule}` }
  }
  const host = targetHost(rule)
  if (value.endsWith(`.${host}`)) return { scope: rule, matches: true, reason: `subdomain of ${host}` }
  return { scope: rule, matches: false, reason: "no host or wildcard match" }
}

export function check(target: string, scopes: readonly string[]) {
  const results = scopes.map((scope) => match(target, scope))
  return { target: targetHost(target), in_scope: results.some((result) => result.matches), results }
}
