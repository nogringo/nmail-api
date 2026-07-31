import { createHash } from 'node:crypto'
import type { FastifyReply, FastifyRequest } from 'fastify'
import { verifyNip98 } from '../nip98.js'
import type { PushSubscriptionInput, PushSubscriptionRepository } from '../types.js'

type PushRegistrationAction = 'register' | 'disable'

interface PushRegistrationPayload {
  action: PushRegistrationAction
  language?: string
  pubkey?: string
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
    if (!isJsonRequest(request) || !request.rawBody) {
      return reply.code(400).send({ error: 'invalid_push_registration' })
    }

    const payload = parsePushRegistrationPayload(request.body)
    if (!payload) return reply.code(400).send({ error: 'invalid_push_registration' })

    // `disable` needs no credential: the push destination is the only secret it
    // carries, so a subscription can be dropped once its key is gone.
    let pubkey: string | null = null
    if (payload.action === 'register') {
      const auth = verifyNip98({
        authorization: request.headers.authorization,
        method: request.method,
        host: request.headers.host ?? '',
        path: request.url,
        nowSeconds: Math.floor(Date.now() / 1000),
        payloadHash: sha256Hex(request.rawBody),
      })

      if (!auth.ok) {
        return reply.header('www-authenticate', 'Nostr').code(401).send({ error: auth.reason })
      }

      pubkey = auth.pubkey
    }

    try {
      if (pubkey) {
        await repo.upsertPushSubscription(toSubscriptionInput(pubkey, payload))
      } else {
        await repo.deletePushSubscriptions(payload.transport.type, destinationOf(payload.transport), payload.pubkey)
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

  const payload = value as { action?: unknown; language?: unknown; pubkey?: unknown; transport?: unknown }
  if (payload.action !== 'register' && payload.action !== 'disable') return null

  const language = payload.action === 'register' ? parseOptionalLanguage(payload.language) : undefined
  if (payload.action === 'register' && payload.language !== undefined && !language) return null

  // Only narrows a disable, so it is never a credential: the destination bounds
  // the deletion on its own. The register account is the NIP-98 signer.
  const pubkey = payload.action === 'disable' ? parseOptionalPubkey(payload.pubkey) : undefined
  if (payload.action === 'disable' && payload.pubkey !== undefined && !pubkey) return null

  const transport = parseTransport(payload.transport, payload.action === 'register')
  if (!transport) return null

  return {
    action: payload.action,
    ...(language ? { language } : {}),
    ...(pubkey ? { pubkey } : {}),
    transport,
  }
}

function parseOptionalPubkey(value: unknown): string | undefined {
  if (value === undefined || value === null) return undefined

  const pubkey = nonEmptyString(value)?.toLowerCase()
  return pubkey && /^[0-9a-f]{64}$/.test(pubkey) ? pubkey : undefined
}

function parseTransport(value: unknown, isRegister: boolean): PushTransport | null {
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
    if (!endpoint) return null
    if ((p256dh && !auth) || (!p256dh && auth)) return null

    return {
      type: 'unifiedpush',
      endpoint,
      ...(p256dh ? { p256dh } : {}),
      ...(auth ? { auth } : {}),
      ...(isRegister ? { instance: optionalString(transport.instance) } : {}),
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

function destinationOf(transport: PushTransport): string {
  return transport.type === 'fcm' ? transport.token : transport.endpoint
}

function toSubscriptionInput(pubkey: string, payload: PushRegistrationPayload): PushSubscriptionInput {
  const { transport } = payload
  const base = {
    pubkey,
    transport: transport.type,
    destination: destinationOf(transport),
    ...(payload.language ? { language: payload.language } : {}),
  }

  if (transport.type === 'fcm') return base

  return {
    ...base,
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

function parseOptionalLanguage(value: unknown): string | undefined {
  if (value === undefined || value === null) return undefined

  const language = nonEmptyString(value)
  if (!language) return undefined

  try {
    return Intl.getCanonicalLocales(language)[0] ?? undefined
  } catch {
    return undefined
  }
}

function optionalString(value: unknown): string | undefined {
  if (value === undefined || value === null) return undefined
  return nonEmptyString(value) ?? undefined
}
