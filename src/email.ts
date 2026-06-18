export interface ParsedEmailAddress {
  localPart: string
  domain: string
}

export function normalizeDomain(value: string): string {
  const firstHost = value.split(',')[0]?.trim() ?? ''
  const withoutPort = stripPort(firstHost)
  return withoutPort.toLowerCase().replace(/\.$/, '')
}

export function normalizeLocalPart(value: string): string {
  return value.trim().toLowerCase()
}

export function parseEmailAddress(value: string): ParsedEmailAddress | null {
  const address = extractAddress(value)
  const at = address.lastIndexOf('@')

  if (at <= 0 || at === address.length - 1) return null

  const localPart = normalizeLocalPart(address.slice(0, at))
  const domain = normalizeDomain(address.slice(at + 1))

  if (!localPart || !domain) return null

  return { localPart, domain }
}

function extractAddress(value: string): string {
  const trimmed = value.trim().replace(/^mailto:/i, '')
  const angleMatch = /<([^<>]+)>/.exec(trimmed)
  return (angleMatch?.[1] ?? trimmed).trim()
}

function stripPort(host: string): string {
  if (host.startsWith('[')) {
    const end = host.indexOf(']')
    return end === -1 ? host : host.slice(1, end)
  }

  const colon = host.lastIndexOf(':')
  if (colon === -1) return host

  const hasSingleColon = host.indexOf(':') === colon
  return hasSingleColon ? host.slice(0, colon) : host
}
