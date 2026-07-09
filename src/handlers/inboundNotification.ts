import { timingSafeEqual } from 'node:crypto'
import type { FastifyReply, FastifyRequest } from 'fastify'
import type {
  AppConfig,
  InboundNotificationRepository,
  InboundNotificationEmailMetadata,
  InboundNotificationEvent,
  PushNotificationDispatcher,
} from '../types.js'

const FORBIDDEN_EMAIL_FIELDS = new Set(['rawMime', 'body', 'bodyMime', 'content', 'html', 'text'])
const MAX_NOTIFICATION_EVENT_AGE_SECONDS = 7 * 24 * 60 * 60
const MAX_NOTIFICATION_EVENT_FUTURE_SKEW_SECONDS = 10 * 60

const noopPushNotificationDispatcher: PushNotificationDispatcher = {
  async dispatch() {
    return undefined
  },
}

export function createInboundNotificationHandler(
  repo: InboundNotificationRepository,
  config: Pick<AppConfig, 'inboundNotificationToken'>,
  dispatcher: PushNotificationDispatcher = noopPushNotificationDispatcher,
) {
  return async function inboundNotificationHandler(request: FastifyRequest, reply: FastifyReply) {
    if (!config.inboundNotificationToken || !isAuthorizedNotificationRequest(request, config.inboundNotificationToken)) {
      return reply.code(401).send({ error: 'unauthorized' })
    }

    const payload = parseNotificationPayload(request.body)
    if (!payload) return reply.code(400).send({ error: 'invalid_notification_payload' })

    if (shouldSkipNotificationEvent(payload.event, Math.floor(Date.now() / 1000))) {
      return reply.code(202).send({ status: 'accepted' })
    }

    let claimedDelivery: { recipientPubkey: string; eventId: string } | null = null

    try {
      if (payload.event.id) {
        const claimed = await repo.claimInboundNotificationDelivery(payload.recipientPubkey, payload.event.id)
        if (!claimed) return reply.code(202).send({ status: 'accepted' })
        claimedDelivery = { recipientPubkey: payload.recipientPubkey, eventId: payload.event.id }
      }

      const subscriptions = await repo.listPushSubscriptions([payload.recipientPubkey])
      await dispatcher.dispatch({
        recipientPubkey: payload.recipientPubkey,
        relays: payload.relays,
        event: payload.event,
        authenticatedPubkeys: payload.authenticatedPubkeys,
        email: payload.email,
        subscriptions,
      })

      return reply.code(202).send({ status: 'accepted' })
    } catch (error) {
      if (claimedDelivery) {
        try {
          await repo.releaseInboundNotificationDelivery(claimedDelivery.recipientPubkey, claimedDelivery.eventId)
        } catch (releaseError) {
          request.log.error({ error: releaseError }, 'Inbound notification delivery claim release failed')
        }
      }
      request.log.error({ error }, 'Inbound notification dispatch failed')
      return reply.code(503).send({ error: 'notification_unavailable' })
    }
  }
}

function isAuthorizedNotificationRequest(request: FastifyRequest, expectedToken: string): boolean {
  const authorization = firstHeaderValue(request.headers.authorization)
  const bearerMatch = /^Bearer\s+(.+)$/i.exec(authorization)
  const token = bearerMatch?.[1]?.trim()
  if (!token) return false

  const actual = Buffer.from(token)
  const expected = Buffer.from(expectedToken)
  return actual.length === expected.length && timingSafeEqual(actual, expected)
}

function parseNotificationPayload(value: unknown): {
  recipientPubkey: string
  relays: string[]
  event: InboundNotificationEvent
  email?: InboundNotificationEmailMetadata
  authenticatedPubkeys: string[]
} | null {
  if (!value || typeof value !== 'object') return null

  const payload = value as Record<string, unknown>
  if (hasForbiddenEmailBody(payload)) return null

  const recipientPubkey = optionalHex64(payload.recipientPubkey)
  if (!recipientPubkey) return null

  const relays = parseRelays(payload.relays)
  if (!relays) return null

  const authenticatedPubkeys = parsePubkeyArray(payload.authenticatedPubkeys)
  if (!authenticatedPubkeys) return null

  const email = parseEmailMetadata(payload.email)
  if (email === null) return null

  const event = parseEvent(payload.event, email !== undefined)
  if (!event) return null

  const parsed = { recipientPubkey, relays, event, authenticatedPubkeys }
  return email === undefined ? parsed : { ...parsed, email }
}

function parseEvent(value: unknown, isPublicEmail: boolean): InboundNotificationEvent | null {
  if (!value || typeof value !== 'object') return null

  const event = value as Record<string, unknown>
  const content = typeof event.content === 'string' ? event.content : undefined
  const sig = optionalHex(event.sig, 128)

  if (isPublicEmail) {
    if (content === undefined || !sig) return null
  } else if (Object.hasOwn(event, 'content') || Object.hasOwn(event, 'sig')) {
    return null
  }

  const tags = parseTags(event.tags)
  if (!tags) return null

  const id = optionalHex64(event.id)
  if (event.id !== undefined && !id) return null

  const pubkey = optionalHex64(event.pubkey)
  if (event.pubkey !== undefined && !pubkey) return null

  const createdAt = optionalSafeInteger(event.created_at)
  if (createdAt === undefined) return null

  const kind = optionalSafeInteger(event.kind)
  if (event.kind !== undefined && kind === undefined) return null

  return {
    tags,
    created_at: createdAt,
    ...(id ? { id } : {}),
    ...(pubkey ? { pubkey } : {}),
    ...(kind !== undefined ? { kind } : {}),
    ...(content !== undefined ? { content } : {}),
    ...(sig ? { sig } : {}),
  }
}

function parseRelays(value: unknown): string[] | null {
  if (!Array.isArray(value)) return null

  const relays = new Set<string>()
  for (const entry of value) {
    if (typeof entry !== 'string') return null

    const relay = entry.trim()
    if (!relay) return null

    try {
      const url = new URL(relay)
      if (url.protocol !== 'ws:' && url.protocol !== 'wss:') return null
    } catch {
      return null
    }

    relays.add(relay)
  }

  return [...relays]
}

function shouldSkipNotificationEvent(event: InboundNotificationEvent, nowSeconds: number): boolean {
  return (
    event.created_at < nowSeconds - MAX_NOTIFICATION_EVENT_AGE_SECONDS ||
    event.created_at > nowSeconds + MAX_NOTIFICATION_EVENT_FUTURE_SKEW_SECONDS
  )
}

function parseTags(value: unknown): string[][] | null {
  if (value === undefined) return []
  if (!Array.isArray(value)) return null

  const tags: string[][] = []
  for (const tag of value) {
    if (!Array.isArray(tag) || !tag.every((entry) => typeof entry === 'string')) return null
    tags.push([...tag])
  }

  return tags
}

function parseEmailMetadata(value: unknown): InboundNotificationEmailMetadata | undefined | null {
  if (value === undefined) return undefined
  if (!value || typeof value !== 'object') return null

  const email = value as Record<string, unknown>
  if (hasForbiddenEmailBody(email)) return null

  const from = parseFrom(email.from)
  if (email.from !== undefined && !from) return null

  const subject = optionalNonEmptyString(email.subject)
  if (email.subject !== undefined && subject === undefined) return null

  const preview = optionalNonEmptyString(email.preview)
  if (email.preview !== undefined && preview === undefined) return null

  return {
    ...(from ? { from } : {}),
    ...(subject !== undefined ? { subject } : {}),
    ...(preview !== undefined ? { preview } : {}),
  }
}

function parseFrom(value: unknown): InboundNotificationEmailMetadata['from'] | null {
  if (!value || typeof value !== 'object') return null

  const from = value as Record<string, unknown>
  const address = optionalNonEmptyString(from.address)
  if (!address) return null

  const name = optionalNonEmptyString(from.name)
  if (from.name !== undefined && name === undefined) return null

  return name === undefined ? { address } : { address, name }
}

function parsePubkeyArray(value: unknown): string[] | null {
  if (value === undefined) return []
  if (!Array.isArray(value)) return null

  const pubkeys = new Set<string>()
  for (const entry of value) {
    const pubkey = optionalHex64(entry)
    if (!pubkey) return null
    pubkeys.add(pubkey)
  }

  return [...pubkeys]
}

function hasForbiddenEmailBody(value: Record<string, unknown>): boolean {
  return Object.keys(value).some((key) => FORBIDDEN_EMAIL_FIELDS.has(key))
}

function optionalHex64(value: unknown): string | undefined {
  return optionalHex(value, 64)
}

function optionalHex(value: unknown, length: number): string | undefined {
  if (typeof value !== 'string') return undefined

  const normalized = value.trim().toLowerCase()
  return new RegExp(`^[0-9a-f]{${length}}$`).test(normalized) ? normalized : undefined
}

function optionalSafeInteger(value: unknown): number | undefined {
  return Number.isSafeInteger(value) && Number(value) >= 0 ? Number(value) : undefined
}

function optionalNonEmptyString(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined

  const trimmed = value.trim()
  return trimmed ? trimmed : undefined
}

function firstHeaderValue(value: string | string[] | undefined): string {
  const header = Array.isArray(value) ? value[0] : value
  return header?.trim() ?? ''
}
