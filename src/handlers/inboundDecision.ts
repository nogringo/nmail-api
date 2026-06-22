import type { FastifyReply, FastifyRequest } from 'fastify'
import { timingSafeEqual } from 'node:crypto'
import { parseEmailAddress } from '../email.js'
import { decodeBase36Pubkey, decodeNpub } from '../nostr.js'
import type { AppConfig, IdentityRepository, InboundDecisionPayload, InboundDecisionResponse } from '../types.js'

export function createInboundDecisionHandler(
  repo: IdentityRepository,
  config: Pick<AppConfig, 'protectedEmailDomains' | 'inboundDecisionToken'>,
) {
  return async function inboundDecisionHandler(request: FastifyRequest, reply: FastifyReply) {
    if (!isAuthorizedDecisionRequest(request, config.inboundDecisionToken, 'x-inbound-decision-token')) {
      return reply.code(401).send({ error: 'unauthorized' })
    }

    const payload = parseDecisionPayload(request.body)
    if (!payload) {
      return reply.code(400).send({ error: 'invalid decision payload' })
    }

    try {
      const decision = await decideDelivery(payload, repo, config.protectedEmailDomains)
      return reply.send(decision)
    } catch (error) {
      request.log.error({ error }, 'Inbound decision lookup failed')
      return reply.code(503).send({ error: 'policy_unavailable' })
    }
  }
}

export function isAuthorizedDecisionRequest(
  request: FastifyRequest,
  expectedToken: string,
  headerName: string,
): boolean {
  const token = extractDecisionToken(request, headerName)
  if (!token) return false

  const actual = Buffer.from(token)
  const expected = Buffer.from(expectedToken)
  return actual.length === expected.length && timingSafeEqual(actual, expected)
}

export async function decideDelivery(
  payload: InboundDecisionPayload,
  repo: IdentityRepository,
  protectedEmailDomains: Set<string>,
): Promise<InboundDecisionResponse> {
  const requiredByDomain = new Map<string, Set<string>>()

  for (const recipient of payload.message.recipients) {
    const parsed = parseEmailAddress(recipient)
    if (!parsed || !protectedEmailDomains.has(parsed.domain)) continue

    const pubkey = await resolveRecipientPubkey(parsed.domain, parsed.localPart, repo)
    if (!pubkey) return denyUnknownRecipient()

    const requiredPubkeys = requiredByDomain.get(parsed.domain) ?? new Set<string>()
    requiredPubkeys.add(pubkey)
    requiredByDomain.set(parsed.domain, requiredPubkeys)
  }

  for (const [domain, pubkeys] of requiredByDomain) {
    const identities = await repo.findMailEnabledIdentitiesByPubkeys(domain, [...pubkeys])
    for (const pubkey of pubkeys) {
      if (!identities.has(pubkey)) {
        return denyUnknownRecipient()
      }
    }
  }

  return { decision: 'allow' }
}

export async function resolveRecipientPubkey(
  domain: string,
  localPart: string,
  repo: IdentityRepository,
): Promise<string | null> {
  if (/^[0-9a-f]{64}$/.test(localPart)) return localPart

  const npub = decodeNpub(localPart)
  if (npub) return npub

  const identity = await repo.findIdentity(domain, localPart)
  if (identity) return identity.pubkey

  return decodeBase36Pubkey(localPart)
}

function parseDecisionPayload(value: unknown): InboundDecisionPayload | null {
  if (!value || typeof value !== 'object') return null

  const payload = value as Partial<InboundDecisionPayload>
  if (!payload.message || typeof payload.message !== 'object') return null
  if (!Array.isArray(payload.message.recipients)) return null

  return payload as InboundDecisionPayload
}

function extractDecisionToken(request: FastifyRequest, headerName: string): string {
  const headerToken = firstHeaderValue(request.headers[headerName])
  if (headerToken) return headerToken

  const authorization = firstHeaderValue(request.headers.authorization)
  const bearerMatch = /^Bearer\s+(.+)$/i.exec(authorization)
  if (bearerMatch?.[1]) return bearerMatch[1].trim()

  const query = request.query
  if (query && typeof query === 'object' && 'token' in query) {
    const token = (query as { token?: unknown }).token
    if (typeof token === 'string') return token.trim()
  }

  return ''
}

function firstHeaderValue(value: string | string[] | undefined): string {
  const header = Array.isArray(value) ? value[0] : value
  return header?.trim() ?? ''
}

function denyUnknownRecipient(): InboundDecisionResponse {
  return {
    decision: 'deny',
    reason: 'unknown_recipient',
    message: 'Recipient is not configured for inbound mail delivery',
  }
}
