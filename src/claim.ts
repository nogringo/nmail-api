import { verifyEvent } from 'nostr-tools/pure'
import { parseEmailAddress } from './email.js'
import type { IdentityVisibility } from './types.js'

// App-specific kind a client signs to prove ownership of a pubkey when claiming
// an alias. It must match what the client signs.
export const ALIAS_CLAIM_KIND = 27240

// created_at must be within this window of the server clock to bound replay.
export const CLAIM_MAX_AGE_SECONDS = 300

// Provisioned alias local part bounds. The 47 cap also keeps aliases clear of
// the base36-encoded pubkey range (48-52 chars), which is never an alias.
export const ALIAS_LOCAL_PART_MIN = 6
export const ALIAS_LOCAL_PART_MAX = 47

export type ClaimReason =
  | 'invalid_event'
  | 'invalid_signature'
  | 'stale_event'
  | 'invalid_address'
  | 'invalid_local_part'
  | 'invalid_visibility'

export type VerifiedClaim = {
  pubkey: string
  domain: string
  localPart: string
  visibility: IdentityVisibility
}

export type ClaimResult = { ok: true; claim: VerifiedClaim } | { ok: false; reason: ClaimReason }

interface NostrEvent {
  id: string
  pubkey: string
  created_at: number
  kind: number
  tags: string[][]
  content: string
  sig: string
}

export function verifyClaimEvent(value: unknown, nowSeconds: number): ClaimResult {
  const event = asNostrEvent(value)
  if (!event || event.kind !== ALIAS_CLAIM_KIND) return fail('invalid_event')

  if (!verifyEvent(event)) return fail('invalid_signature')

  if (Math.abs(nowSeconds - event.created_at) > CLAIM_MAX_AGE_SECONDS) return fail('stale_event')

  const address = findTagValue(event.tags, 'address')
  if (!address) return fail('invalid_address')

  const parsed = parseEmailAddress(address)
  if (!parsed) return fail('invalid_address')

  if (parsed.localPart.length < ALIAS_LOCAL_PART_MIN || parsed.localPart.length > ALIAS_LOCAL_PART_MAX) {
    return fail('invalid_local_part')
  }

  const visibilityTag = findTagValue(event.tags, 'visibility')
  if (visibilityTag !== undefined && visibilityTag !== 'public' && visibilityTag !== 'private') {
    return fail('invalid_visibility')
  }
  const visibility: IdentityVisibility = visibilityTag === 'private' ? 'private' : 'public'

  return {
    ok: true,
    claim: { pubkey: event.pubkey, domain: parsed.domain, localPart: parsed.localPart, visibility },
  }
}

function asNostrEvent(value: unknown): NostrEvent | null {
  if (!value || typeof value !== 'object') return null

  const event = value as Record<string, unknown>
  if (typeof event.id !== 'string') return null
  if (typeof event.pubkey !== 'string') return null
  if (typeof event.created_at !== 'number') return null
  if (typeof event.kind !== 'number') return null
  if (typeof event.content !== 'string') return null
  if (typeof event.sig !== 'string') return null
  if (!Array.isArray(event.tags) || !event.tags.every(isStringArray)) return null

  return event as unknown as NostrEvent
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((entry) => typeof entry === 'string')
}

function findTagValue(tags: string[][], name: string): string | undefined {
  for (const tag of tags) {
    if (tag[0] === name) return tag[1]
  }

  return undefined
}

function fail(reason: ClaimReason): ClaimResult {
  return { ok: false, reason }
}
