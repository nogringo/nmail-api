import type { FastifyReply, FastifyRequest } from 'fastify'
import { parseEmailAddress } from '../email.js'
import { decodeNpub } from '../nostr.js'
import { countRecipients, isRateLimited, messageByteSize } from '../policy.js'
import type {
  AppConfig,
  IdentityRepository,
  OutboundDecisionPayload,
  OutboundDecisionResponse,
  PolicyRepository,
} from '../types.js'
import { isAuthorizedDecisionRequest, resolveRecipientPubkey } from './inboundDecision.js'

export function createOutboundDecisionHandler(
  repo: IdentityRepository & PolicyRepository,
  config: Pick<AppConfig, 'protectedEmailDomains'> & { outboundDecisionToken: string },
) {
  return async function outboundDecisionHandler(request: FastifyRequest, reply: FastifyReply) {
    if (!isAuthorizedDecisionRequest(request, config.outboundDecisionToken, 'x-outbound-decision-token')) {
      return reply.code(401).send({ error: 'unauthorized' })
    }

    const payload = parseDecisionPayload(request.body)
    if (!payload) {
      return reply.code(400).send({ error: 'invalid decision payload' })
    }

    try {
      const decision = await decideSending(payload, repo, config.protectedEmailDomains)
      return reply.send(decision)
    } catch (error) {
      request.log.error({ error }, 'Outbound decision lookup failed')
      return reply.code(503).send({ error: 'policy_unavailable' })
    }
  }
}

export async function decideSending(
  payload: OutboundDecisionPayload,
  repo: IdentityRepository & PolicyRepository,
  protectedEmailDomains: Set<string>,
): Promise<OutboundDecisionResponse> {
  const sender = normalizePubkey(payload.nostrSender)
  if (!sender) return denyUnauthorizedSender()

  const fromHeader = findHeaderValue(payload.headers, 'from')
  if (!fromHeader) return denyUnauthorizedSender()

  const parsed = parseEmailAddress(fromHeader)
  if (!parsed || !protectedEmailDomains.has(parsed.domain)) return denyUnauthorizedSender()

  const pubkey = await resolveRecipientPubkey(parsed.domain, parsed.localPart, repo)
  if (pubkey !== sender) return denyUnauthorizedSender()

  const identities = await repo.findMailEnabledIdentitiesByPubkeys(parsed.domain, [sender])
  if (!identities.has(sender)) return denyUnauthorizedSender()

  const giftWrapId = typeof payload.giftWrapId === 'string' ? payload.giftWrapId.trim() : ''

  // Re-asking about an already-recorded message is idempotent: it was allowed and
  // counted once, so the bridge can safely retry without burning another slot.
  if (giftWrapId && (await repo.hasOutboundSend(giftWrapId))) {
    return { decision: 'allow' }
  }

  const plan = await repo.getPlanForPubkey(sender)

  const recipients = countRecipients(payload.headers)
  if (recipients > plan.maxRecipients) return denyTooManyRecipients(plan.maxRecipients)

  // Message size is only enforceable when the bridge forwards the full .eml
  // (DECISION_PAYLOAD_MODE=full). Without it the size is unknown, so we skip it.
  const size = messageByteSize(payload.rawMime)
  if (size > 0 && size > plan.maxMessageBytes) return denyMessageTooLarge(plan.maxMessageBytes)

  const counts = await repo.countOutboundSends(sender)
  if (isRateLimited(counts, plan)) return denyRateLimited()

  await repo.recordOutboundSend(sender, giftWrapId || undefined)

  return { decision: 'allow' }
}

function parseDecisionPayload(value: unknown): OutboundDecisionPayload | null {
  if (!value || typeof value !== 'object') return null

  const payload = value as Partial<OutboundDecisionPayload>
  if (typeof payload.nostrSender !== 'string') return null

  return payload as OutboundDecisionPayload
}

function normalizePubkey(value: string | undefined): string | null {
  if (typeof value !== 'string') return null

  const trimmed = value.trim().toLowerCase()
  if (/^[0-9a-f]{64}$/.test(trimmed)) return trimmed

  return decodeNpub(trimmed)
}

function findHeaderValue(headers: Array<[string, string]> | undefined, name: string): string | null {
  if (!Array.isArray(headers)) return null

  const target = name.toLowerCase()
  for (const entry of headers) {
    if (Array.isArray(entry) && typeof entry[0] === 'string' && entry[0].toLowerCase() === target) {
      return typeof entry[1] === 'string' ? entry[1] : null
    }
  }

  return null
}

function denyUnauthorizedSender(): OutboundDecisionResponse {
  return {
    decision: 'deny',
    reason: 'unauthorized_sender',
    message: 'Sender is not authorized to send mail from this address',
  }
}

function denyRateLimited(): OutboundDecisionResponse {
  return {
    decision: 'deny',
    reason: 'rate_limited',
    message: 'Sending rate limit exceeded, try again later',
  }
}

function denyTooManyRecipients(max: number): OutboundDecisionResponse {
  return {
    decision: 'deny',
    reason: 'too_many_recipients',
    message: `Too many recipients, the limit is ${max}`,
  }
}

function denyMessageTooLarge(maxBytes: number): OutboundDecisionResponse {
  return {
    decision: 'deny',
    reason: 'message_too_large',
    message: `Message exceeds the size limit of ${maxBytes} bytes`,
  }
}
