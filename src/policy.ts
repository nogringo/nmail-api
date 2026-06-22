import type { OutboundSendCounts, Plan, PlanLimits } from './types.js'

const MB = 1024 * 1024

// Built-in plans seeded by migration 003 and used as the in-code fallback when
// the database has no plans yet. Limits are editable from the admin UI.
export const FREE_PLAN: Plan = {
  name: 'free',
  perMinute: 5,
  perHour: 30,
  perDay: 50,
  maxMessageBytes: 10 * MB,
  maxRecipients: 5,
  isDefault: true,
}

export const PREMIUM_PLAN: Plan = {
  name: 'premium',
  perMinute: 10,
  perHour: 100,
  perDay: 500,
  maxMessageBytes: 25 * MB,
  maxRecipients: 10,
  isDefault: false,
}

export const DEFAULT_PLANS: Plan[] = [FREE_PLAN, PREMIUM_PLAN]

export function isRateLimited(counts: OutboundSendCounts, limits: PlanLimits): boolean {
  return (
    counts.minute >= limits.perMinute ||
    counts.hour >= limits.perHour ||
    counts.day >= limits.perDay
  )
}

export function messageByteSize(rawMime: string | undefined): number {
  if (typeof rawMime !== 'string' || !rawMime) return 0
  return Buffer.byteLength(rawMime, 'utf8')
}

export function countRecipients(headers: Array<[string, string]> | undefined): number {
  if (!Array.isArray(headers)) return 0

  let total = 0
  for (const entry of headers) {
    if (!Array.isArray(entry) || typeof entry[0] !== 'string' || typeof entry[1] !== 'string') continue

    const name = entry[0].toLowerCase()
    if (name === 'to' || name === 'cc' || name === 'bcc') {
      total += splitAddressList(entry[1]).length
    }
  }

  return total
}

// Split an address-list header value on commas, ignoring commas inside quoted
// display names or inside <angle brackets>.
function splitAddressList(value: string): string[] {
  const parts: string[] = []
  let current = ''
  let inQuotes = false
  let depth = 0

  for (const char of value) {
    if (char === '"') inQuotes = !inQuotes
    else if (char === '<') depth += 1
    else if (char === '>' && depth > 0) depth -= 1

    if (char === ',' && !inQuotes && depth === 0) {
      if (current.trim()) parts.push(current.trim())
      current = ''
      continue
    }

    current += char
  }

  if (current.trim()) parts.push(current.trim())
  return parts
}

export function sanitizePlanLimits(value: unknown): PlanLimits | null {
  if (!value || typeof value !== 'object') return null

  const input = value as Record<string, unknown>
  const perMinute = toCount(input.perMinute)
  const perHour = toCount(input.perHour)
  const perDay = toCount(input.perDay)
  const maxMessageBytes = toBytes(input.maxMessageBytes)
  const maxRecipients = toCount(input.maxRecipients)

  if (
    perMinute === null ||
    perHour === null ||
    perDay === null ||
    maxMessageBytes === null ||
    maxRecipients === null
  ) {
    return null
  }

  return { perMinute, perHour, perDay, maxMessageBytes, maxRecipients }
}

export function normalizePlanName(value: unknown): string {
  return String(value ?? '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_-]/g, '')
}

function toCount(value: unknown): number | null {
  const count = typeof value === 'string' ? Number(value) : value
  if (typeof count !== 'number' || !Number.isInteger(count) || count < 0 || count > 10_000_000) {
    return null
  }

  return count
}

function toBytes(value: unknown): number | null {
  const bytes = typeof value === 'string' ? Number(value) : value
  if (typeof bytes !== 'number' || !Number.isInteger(bytes) || bytes < 0 || bytes > 1024 * MB) {
    return null
  }

  return bytes
}