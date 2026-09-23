import type { FastifyReply, FastifyRequest } from 'fastify'
import { normalizeDomain, normalizeLocalPart } from '../email.js'
import { verifyNip98 } from '../nip98.js'
import type { AccountRepository, AppConfig, IdentityRepository, Nip05Response } from '../types.js'

interface Nip05Query {
  name?: string
}

export function createNip05Handler(
  repo: IdentityRepository & AccountRepository,
  config: Pick<AppConfig, 'nip05PrivateReaders'>,
) {
  return async function nip05Handler(request: FastifyRequest<{ Querystring: Nip05Query }>, reply: FastifyReply) {
    const name = normalizeLocalPart(request.query.name ?? '')
    const domain = normalizeDomain(request.headers.host ?? '')

    reply.header('access-control-allow-origin', '*')

    if (!name || !domain) {
      return reply.code(400).send({ error: 'name and host are required' })
    }

    const privateReader = isPrivateReader(request, config.nip05PrivateReaders)
    if (privateReader) reply.header('cache-control', 'no-store')

    const identity = await repo.findNip05Identity(domain, name, privateReader)
    if (!identity) {
      return reply.send(emptyNip05Response())
    }

    const account = await repo.getAccount(identity.pubkey)

    return reply.send({
      names: { [name]: identity.pubkey },
      relays: { [identity.pubkey]: account?.relays ?? [] },
    } satisfies Nip05Response)
  }
}

export function emptyNip05Response(): Nip05Response {
  return { names: {}, relays: {} }
}

function isPrivateReader(request: FastifyRequest, readers: string[]): boolean {
  if (!readers.length || !request.headers.authorization) return false

  const result = verifyNip98({
    authorization: request.headers.authorization,
    method: request.method,
    host: request.headers.host ?? '',
    path: request.url,
    nowSeconds: Math.floor(Date.now() / 1000),
    bindQuery: true,
  })
  if (result.ok && readers.includes(result.pubkey)) return true

  request.log.warn({ reason: result.ok ? 'not_a_reader' : result.reason }, 'NIP-05 private read refused')
  return false
}
