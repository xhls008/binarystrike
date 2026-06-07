import { Locale } from "@/util/locale"

export function agentLabel(agent: string | { name: string } | undefined, fallback = "Unknown") {
  const name = typeof agent === "string" ? agent : agent?.name
  if (!name) return fallback
  if (name === "cyberstrike") return "BinaryStrike"
  return Locale.titlecase(name)
}

export function providerLabel(provider: { id: string; name?: string } | undefined, fallback?: string) {
  if (!provider) return fallback ?? ""
  if (provider.id === "cyberstrike") return "BinaryStrike"
  return provider.name ?? fallback ?? provider.id
}
