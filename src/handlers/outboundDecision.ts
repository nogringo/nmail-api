import type { FastifyReply, FastifyRequest } from 'fastify'
import { parseEmailAddress } from '../email.js'
import { decodeEncodedLocalPart, decodeNpub } from '../nostr.js'
import { countRecipients, isDomainAllowed, isRateLimited, messageByteSize } from '../policy.js'
import type {
  AccountRepository,
  DomainRepository,
  IdentityRepository,
  OutboundDecisionPayload,
  OutboundDecisionResponse,
  PolicyRepository,
} from '../types.js'
import { isAuthorizedDecisionRequest } from './inboundDecision.js'

type OutboundRepository = IdentityRepository & AccountRepository & PolicyRepository & DomainRepository

type Ownership = 'alias' | 'encoded' | 'denied'

export function createOutboundDecisionHandler(
  repo: OutboundRepository,
  config: { outboundDecisionToken: string },
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
      const domains = new Set(await repo.listDomains())
      const decision = await decideSending(payload, repo, domains)
      return reply.send(decision)
    } catch (error) {
      request.log.error({ error }, 'Outbound decision lookup failed')
      return reply.code(503).send({ error: 'policy_unavailable' })
    }
  }
}

export async function decideSending(
  payload: OutboundDecisionPayload,
  repo: OutboundRepository,
  domains: Set<string>,
): Promise<OutboundDecisionResponse> {
  const sender = normalizePubkey(payload.nostrSender)
  if (!sender) return denyUnauthorizedSender()

  const fromHeader = findHeaderValue(payload.headers, 'from')
  if (!fromHeader) return denyUnauthorizedSender()

  const parsed = parseEmailAddress(fromHeader)
  if (!parsed || !domains.has(parsed.domain)) return denyUnauthorizedSender()

  const ownership = await resolveOwnership(parsed.domain, parsed.localPart, sender, repo)
  if (ownership === 'denied') return denyUnauthorizedSender()

  const giftWrapId = typeof payload.giftWrapId === 'string' ? payload.giftWrapId.trim() : ''

  if (giftWrapId && (await repo.hasOutboundSend(giftWrapId))) {
    return { decision: 'allow' }
  }

  const account = await repo.getOrCreateAccount(sender)
  if (!account.active || !account.mailEnabled) return denyAccountDisabled()

  const plan = await repo.getPlan(account.plan)

  if (ownership === 'encoded' && !isDomainAllowed(plan, parsed.domain)) {
    return denyDomainNotAllowed(parsed.domain)
  }

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

async function resolveOwnership(
  domain: string,
  localPart: string,
  sender: string,
  repo: IdentityRepository,
): Promise<Ownership> {
  const alias = await repo.findIdentity(domain, localPart)
  if (alias) return alias.pubkey === sender ? 'alias' : 'denied'

  const decoded = decodeEncodedLocalPart(localPart)
  if (decoded && decoded === sender) return 'encoded'

  return 'denied'
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

function denyAccountDisabled(): OutboundDecisionResponse {
  return {
    decision: 'deny',
    reason: 'account_disabled',
    message: 'This account is not allowed to send mail',
  }
}

function denyDomainNotAllowed(domain: string): OutboundDecisionResponse {
  return {
    decision: 'deny',
    reason: 'domain_not_allowed',
    message: `Your plan cannot send from ${domain}`,
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
