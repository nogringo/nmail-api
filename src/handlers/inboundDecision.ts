import type { FastifyReply, FastifyRequest } from 'fastify'
import { timingSafeEqual } from 'node:crypto'
import { parseEmailAddress } from '../email.js'
import type { AppConfig, IdentityRepository, InboundDecisionPayload, InboundDecisionResponse } from '../types.js'

export function createInboundDecisionHandler(
  repo: IdentityRepository,
  config: Pick<AppConfig, 'protectedEmailDomains' | 'inboundDecisionToken'>,
) {
  return async function inboundDecisionHandler(request: FastifyRequest, reply: FastifyReply) {
    if (!isAuthorizedDecisionRequest(request, config.inboundDecisionToken)) {
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

export function isAuthorizedDecisionRequest(request: FastifyRequest, expectedToken: string): boolean {
  const token = extractDecisionToken(request)
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

    const required = requiredByDomain.get(parsed.domain) ?? new Set<string>()
    required.add(parsed.localPart)
    requiredByDomain.set(parsed.domain, required)
  }

  for (const [domain, localParts] of requiredByDomain) {
    const identities = await repo.findMailEnabledIdentities(domain, [...localParts])
    for (const localPart of localParts) {
      if (!identities.has(localPart)) {
        return denyUnknownRecipient()
      }
    }
  }

  return { decision: 'allow' }
}

function parseDecisionPayload(value: unknown): InboundDecisionPayload | null {
  if (!value || typeof value !== 'object') return null

  const payload = value as Partial<InboundDecisionPayload>
  if (!payload.message || typeof payload.message !== 'object') return null
  if (!Array.isArray(payload.message.recipients)) return null

  return payload as InboundDecisionPayload
}

function extractDecisionToken(request: FastifyRequest): string {
  const headerToken = firstHeaderValue(request.headers['x-inbound-decision-token'])
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
