import type { FastifyReply, FastifyRequest } from 'fastify'
import { createHash, createHmac, timingSafeEqual } from 'node:crypto'
import type { RoleMessageRepository } from '../types.js'

// Mirrors haraka-webhook lib/payload.js: the signature only bounds replay within
// this window, so reuse the same span as the alias-claim replay bound.
const SIGNATURE_MAX_AGE_SECONDS = 300

export function createRoleWebhookHandler(
  repo: RoleMessageRepository,
  config: { roleWebhookSigningKey: string },
) {
  return async function roleWebhookHandler(request: FastifyRequest, reply: FastifyReply) {
    const fields = request.body
    if (!fields || typeof fields !== 'object') {
      return reply.code(400).send({ error: 'invalid_payload' })
    }

    const body = fields as Record<string, unknown>
    const timestamp = stringField(body.timestamp)
    const token = stringField(body.token)
    const signature = stringField(body.signature)

    if (!isAuthorizedRoleRequest(config.roleWebhookSigningKey, timestamp, token, signature)) {
      return reply.code(401).send({ error: 'unauthorized' })
    }

    const recipient = stringField(body.recipient)
    const bodyMime = stringField(body['body-mime'])
    if (!recipient || !bodyMime) {
      return reply.code(400).send({ error: 'invalid_payload' })
    }

    try {
      await repo.recordRoleMessage({
        recipient,
        sender: stringField(body.sender),
        from: stringField(body.from),
        subject: stringField(body.subject),
        headers: parseHeaders(stringField(body['message-headers'])),
        bodyMime,
        contentHash: createHash('sha256').update(bodyMime).digest('hex'),
      })
      return reply.send({ ok: true })
    } catch (error) {
      request.log.error({ error }, 'Role webhook storage failed')
      return reply.code(503).send({ error: 'storage_unavailable' })
    }
  }
}

export function isAuthorizedRoleRequest(
  signingKey: string,
  timestamp: string,
  token: string,
  signature: string,
): boolean {
  if (!timestamp || !token || !signature) return false

  const seconds = Number(timestamp)
  if (!Number.isFinite(seconds)) return false
  if (Math.abs(Math.floor(Date.now() / 1000) - seconds) > SIGNATURE_MAX_AGE_SECONDS) return false

  const expected = createHmac('sha256', signingKey).update(`${timestamp}${token}`).digest('hex')
  const actualBuffer = Buffer.from(signature)
  const expectedBuffer = Buffer.from(expected)
  return actualBuffer.length === expectedBuffer.length && timingSafeEqual(actualBuffer, expectedBuffer)
}

function parseHeaders(value: string): unknown {
  if (!value) return []
  try {
    return JSON.parse(value)
  } catch {
    return []
  }
}

function stringField(value: unknown): string {
  return typeof value === 'string' ? value : ''
}
