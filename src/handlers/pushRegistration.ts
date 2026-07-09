import { createHash } from 'node:crypto'
import type { FastifyReply, FastifyRequest } from 'fastify'
import { verifyNip98 } from '../nip98.js'
import type { PushSubscriptionInput, PushSubscriptionRepository } from '../types.js'

type PushRegistrationAction = 'register' | 'disable'

interface PushRegistrationPayload {
  action: PushRegistrationAction
  transport: PushTransport
}

type PushTransport =
  | { type: 'fcm'; token: string }
  | { type: 'unifiedpush'; endpoint: string; p256dh?: string; auth?: string; instance?: string }

interface RawBodyRequest extends FastifyRequest {
  rawBody?: Buffer
}

export function createPushRegistrationHandler(repo: PushSubscriptionRepository) {
  return async function pushRegistrationHandler(request: RawBodyRequest, reply: FastifyReply) {
    if (!isJsonRequest(request)) return reply.code(400).send({ error: 'invalid_push_registration' })

    const payloadHash = request.rawBody ? sha256Hex(request.rawBody) : null
    if (!payloadHash) return reply.code(400).send({ error: 'invalid_push_registration' })

    const auth = verifyNip98({
      authorization: request.headers.authorization,
      method: request.method,
      host: request.headers.host ?? '',
      path: request.url,
      nowSeconds: Math.floor(Date.now() / 1000),
      payloadHash,
    })

    if (!auth.ok) {
      return reply.header('www-authenticate', 'Nostr').code(401).send({ error: auth.reason })
    }

    const payload = parsePushRegistrationPayload(request.body)
    if (!payload) return reply.code(400).send({ error: 'invalid_push_registration' })

    const subscription = toSubscriptionInput(auth.pubkey, payload.transport)

    try {
      if (payload.action === 'register') {
        await repo.upsertPushSubscription(subscription)
      } else {
        await repo.deletePushSubscription(subscription.pubkey, subscription.transport, subscription.destination)
      }

      return reply.code(204).send()
    } catch (error) {
      request.log.error({ error }, 'Push registration failed')
      return reply.code(503).send({ error: 'push_registration_unavailable' })
    }
  }
}

function parsePushRegistrationPayload(value: unknown): PushRegistrationPayload | null {
  if (!value || typeof value !== 'object') return null

  const payload = value as { action?: unknown; transport?: unknown }
  if (payload.action !== 'register' && payload.action !== 'disable') return null

  const transport = parseTransport(payload.transport, payload.action === 'register')
  if (!transport) return null

  return { action: payload.action, transport }
}

function parseTransport(value: unknown, requireEncryptionKeys: boolean): PushTransport | null {
  if (!value || typeof value !== 'object') return null

  const transport = value as Record<string, unknown>
  if (transport.type === 'fcm') {
    const token = nonEmptyString(transport.token)
    return token ? { type: 'fcm', token } : null
  }

  if (transport.type === 'unifiedpush') {
    const endpoint = validWebPushEndpoint(transport.endpoint)
    const p256dh = nonEmptyString(transport.p256dh)
    const auth = nonEmptyString(transport.auth)
    if (!endpoint || (requireEncryptionKeys && (!p256dh || !auth))) return null

    return {
      type: 'unifiedpush',
      endpoint,
      ...(p256dh ? { p256dh } : {}),
      ...(auth ? { auth } : {}),
      instance: optionalString(transport.instance),
    }
  }

  return null
}

function validWebPushEndpoint(value: unknown): string | null {
  const endpoint = nonEmptyString(value)
  if (!endpoint) return null

  try {
    return new URL(endpoint).protocol === 'https:' ? endpoint : null
  } catch {
    return null
  }
}

function toSubscriptionInput(pubkey: string, transport: PushTransport): PushSubscriptionInput {
  if (transport.type === 'fcm') {
    return { pubkey, transport: transport.type, destination: transport.token }
  }

  return {
    pubkey,
    transport: transport.type,
    destination: transport.endpoint,
    p256dh: transport.p256dh ?? null,
    auth: transport.auth ?? null,
    instance: transport.instance ?? null,
  }
}

function isJsonRequest(request: FastifyRequest): boolean {
  const contentType = request.headers['content-type']
  return typeof contentType === 'string' && /^application\/json\b/i.test(contentType)
}

function sha256Hex(body: Buffer): string {
  return createHash('sha256').update(body).digest('hex')
}

function nonEmptyString(value: unknown): string | null {
  if (typeof value !== 'string') return null

  const trimmed = value.trim()
  return trimmed ? trimmed : null
}

function optionalString(value: unknown): string | undefined {
  if (value === undefined || value === null) return undefined
  return nonEmptyString(value) ?? undefined
}
