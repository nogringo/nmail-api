import type { FastifyReply, FastifyRequest } from 'fastify'
import { normalizeDomain, normalizeLocalPart } from '../email.js'
import type { IdentityRepository, Nip05Response } from '../types.js'

interface Nip05Query {
  name?: string
}

export function createNip05Handler(repo: IdentityRepository) {
  return async function nip05Handler(request: FastifyRequest<{ Querystring: Nip05Query }>, reply: FastifyReply) {
    const name = normalizeLocalPart(request.query.name ?? '')
    const domain = normalizeDomain(request.headers.host ?? '')

    reply.header('access-control-allow-origin', '*')

    if (!name || !domain) {
      return reply.code(400).send({ error: 'name and host are required' })
    }

    const identity = await repo.findPublicIdentity(domain, name)
    if (!identity) {
      return reply.send(emptyNip05Response())
    }

    return reply.send({
      names: { [name]: identity.pubkey },
      relays: { [identity.pubkey]: identity.relays },
    } satisfies Nip05Response)
  }
}

export function emptyNip05Response(): Nip05Response {
  return { names: {}, relays: {} }
}
