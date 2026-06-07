export function providerLabel(provider: { id: string; name?: string } | undefined, fallback?: string) {
  if (!provider) return fallback ?? ""
  if (provider.id === "cyberstrike") return "BinaryStrike"
  return provider.name ?? fallback ?? provider.id
}
