import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import { provisionAlias, sendAliasResult, type AliasRepository } from '../aliases.js'
import { normalizeDomain, normalizeLocalPart } from '../email.js'
import { isEncodedLocalPart } from '../nostr.js'
import { verifyNip98 } from '../nip98.js'
import type { IdentityVisibility } from '../types.js'

interface NameParams {
  name: string
}

interface VisibilityQuery {
  visibility?: string
}

// REST alias lifecycle from docs/AliasProtocol.md, served on the NIP-05 domain
// (the request Host). Authentication is NIP-98: the signing pubkey owns the
// aliases it claims.
export function registerAliasRoutes(app: FastifyInstance, repo: AliasRepository): void {
  app.get('/aliases', async (request, reply) => {
    const pubkey = authenticate(request, reply)
    if (pubkey === null) return reply

    const identities = await repo.listIdentitiesByPubkey(pubkey)
    const aliases = identities.filter((identity) => !isEncodedLocalPart(identity.localPart))
    return reply.send({ aliases })
  })

  app.put('/aliases/:name', async (request: FastifyRequest<{ Params: NameParams; Querystring: VisibilityQuery }>, reply) => {
    const pubkey = authenticate(request, reply)
    if (pubkey === null) return reply

    const visibility = parseVisibility(request.query.visibility)
    if (!visibility) return reply.code(400).send({ error: 'invalid_visibility' })

    const domain = normalizeDomain(request.headers.host ?? '')
    const localPart = normalizeLocalPart(request.params.name)
    if (!domain) return reply.code(400).send({ error: 'invalid_domain' })

    try {
      const result = await provisionAlias(repo, { pubkey, domain, localPart, visibility }, { updateVisibility: true })
      return sendAliasResult(reply, result)
    } catch (error) {
      request.log.error({ error }, 'Alias claim failed')
      return reply.code(503).send({ error: 'claim_unavailable' })
    }
  })

  app.delete('/aliases/:name', async (request: FastifyRequest<{ Params: NameParams }>, reply) => {
    const pubkey = authenticate(request, reply)
    if (pubkey === null) return reply

    const domain = normalizeDomain(request.headers.host ?? '')
    const localPart = normalizeLocalPart(request.params.name)

    const existing = await repo.findIdentity(domain, localPart)
    if (!existing) return reply.code(404).send({ error: 'alias_not_found' })
    if (existing.pubkey !== pubkey) return reply.code(403).send({ error: 'not_owner' })

    if (!repo.deleteIdentityByName) return reply.code(501).send({ error: 'release_unavailable' })
    await repo.deleteIdentityByName(domain, localPart)
    return reply.code(204).send()
  })
}

// Returns the authenticated pubkey, or null after sending a 401 with the reason.
function authenticate(request: FastifyRequest, reply: FastifyReply): string | null {
  const result = verifyNip98({
    authorization: request.headers.authorization,
    method: request.method,
    host: request.headers.host ?? '',
    path: request.url,
    nowSeconds: Math.floor(Date.now() / 1000),
  })

  if (!result.ok) {
    reply.header('www-authenticate', 'Nostr').code(401).send({ error: result.reason })
    return null
  }

  return result.pubkey
}

function parseVisibility(value: string | undefined): IdentityVisibility | null {
  if (value === undefined || value === '') return 'public'
  if (value === 'public' || value === 'private') return value
  return null
}
