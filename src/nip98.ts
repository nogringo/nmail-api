import { verifyEvent } from 'nostr-tools/pure'
import { normalizeDomain } from './email.js'
import { asNostrEvent, findTagValue } from './nostr.js'

// NIP-98 HTTP Auth: the client base64-encodes a signed kind-27235 event and
// sends it as `Authorization: Nostr <base64>`. The event binds the request via
// its `u` (absolute URL) and `method` tags and a fresh `created_at`.
export const NIP98_KIND = 27235
export const NIP98_MAX_AGE_SECONDS = 60

export type Nip98Reason =
  | 'missing_auth'
  | 'invalid_token'
  | 'invalid_event'
  | 'invalid_signature'
  | 'stale_event'
  | 'method_mismatch'
  | 'url_mismatch'
  | 'missing_payload'
  | 'payload_mismatch'

export type Nip98Result = { ok: true; pubkey: string } | { ok: false; reason: Nip98Reason }

export interface Nip98Request {
  authorization: string | undefined
  method: string
  host: string
  // request.url: the path, possibly with a query string.
  path: string
  nowSeconds: number
  payloadHash?: string
}

export function verifyNip98(request: Nip98Request): Nip98Result {
  const token = readToken(request.authorization)
  if (!token) return fail('missing_auth')

  const event = decodeEvent(token)
  if (!event) return fail('invalid_token')
  if (event.kind !== NIP98_KIND) return fail('invalid_event')
  if (!verifyEvent(event)) return fail('invalid_signature')
  if (Math.abs(request.nowSeconds - event.created_at) > NIP98_MAX_AGE_SECONDS) return fail('stale_event')

  const method = findTagValue(event.tags, 'method')
  if (!method || method.toUpperCase() !== request.method.toUpperCase()) return fail('method_mismatch')

  // Bind to host + path. Scheme and query string are ignored: TLS is usually
  // terminated by a proxy, and the query only carries idempotent preferences.
  const signed = parseUrl(findTagValue(event.tags, 'u'))
  if (!signed) return fail('url_mismatch')
  if (normalizeDomain(signed.host) !== normalizeDomain(request.host)) return fail('url_mismatch')
  if (signed.pathname !== pathname(request.path)) return fail('url_mismatch')

  if (request.payloadHash) {
    const payload = findTagValue(event.tags, 'payload')
    if (!payload) return fail('missing_payload')
    if (payload.toLowerCase() !== request.payloadHash.toLowerCase()) return fail('payload_mismatch')
  }

  return { ok: true, pubkey: event.pubkey }
}

function readToken(authorization: string | undefined): string | null {
  if (!authorization) return null

  const match = /^nostr\s+(.+)$/i.exec(authorization.trim())
  return match ? match[1].trim() : null
}

function decodeEvent(token: string): ReturnType<typeof asNostrEvent> {
  try {
    return asNostrEvent(JSON.parse(Buffer.from(token, 'base64').toString('utf8')))
  } catch {
    return null
  }
}

function parseUrl(value: string | undefined): URL | null {
  if (!value) return null

  try {
    return new URL(value)
  } catch {
    return null
  }
}

function pathname(path: string): string {
  const query = path.indexOf('?')
  return query === -1 ? path : path.slice(0, query)
}

function fail(reason: Nip98Reason): Nip98Result {
  return { ok: false, reason }
}
