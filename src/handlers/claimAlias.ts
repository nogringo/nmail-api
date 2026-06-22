import type { FastifyReply, FastifyRequest } from 'fastify'
import { verifyClaimEvent } from '../claim.js'
import { isEncodedLocalPart } from '../nostr.js'
import { isDomainAllowed } from '../policy.js'
import type {
  AccountRepository,
  DomainRepository,
  IdentityRepository,
  PolicyRepository,
  UserIdentity,
} from '../types.js'

type ClaimRepository = IdentityRepository & AccountRepository & PolicyRepository & DomainRepository

const duplicateConstraint = 'identities_unique_name'

export function createClaimAliasHandler(repo: ClaimRepository) {
  return async function claimAliasHandler(request: FastifyRequest, reply: FastifyReply) {
    if (!repo.createIdentity) {
      return reply.code(501).send({ error: 'claim_unavailable' })
    }

    const verified = verifyClaimEvent(request.body, Math.floor(Date.now() / 1000))
    if (!verified.ok) {
      return reply.code(400).send({ error: verified.reason })
    }

    const { pubkey, domain, localPart, visibility } = verified.claim

    if (isEncodedLocalPart(localPart)) {
      return reply.code(400).send({ error: 'encoded_not_claimable' })
    }

    try {
      const domains = new Set(await repo.listDomains())
      if (!domains.has(domain)) {
        return reply.code(400).send({ error: 'domain_not_managed' })
      }

      const existing = await repo.findIdentity(domain, localPart)
      if (existing) {
        if (existing.pubkey !== pubkey) {
          return reply.code(409).send({ error: 'alias_taken' })
        }
        return reply.send({ alias: toAlias(existing) })
      }

      const account = await repo.getOrCreateAccount(pubkey)
      if (!account.active) {
        return reply.code(403).send({ error: 'account_disabled' })
      }

      const plan = await repo.getPlan(account.plan)
      if (!isDomainAllowed(plan, domain)) {
        return reply.code(403).send({ error: 'domain_not_allowed', message: `Your plan cannot claim aliases on ${domain}` })
      }

      const aliasCount = await countAliases(repo, pubkey)
      if (aliasCount >= plan.maxAliases) {
        return reply.code(403).send({
          error: 'alias_limit_reached',
          message: `Your plan allows at most ${plan.maxAliases} aliases`,
        })
      }

      const alias = await repo.createIdentity({ domain, localPart, pubkey, visibility })
      return reply.code(201).send({ alias: toAlias(alias) })
    } catch (error) {
      if (isDuplicateIdentityError(error)) {
        return reply.code(409).send({ error: 'alias_taken' })
      }
      request.log.error({ error }, 'Alias claim failed')
      return reply.code(503).send({ error: 'claim_unavailable' })
    }
  }
}

function toAlias(identity: UserIdentity): UserIdentity {
  return {
    domain: identity.domain,
    localPart: identity.localPart,
    pubkey: identity.pubkey,
    visibility: identity.visibility,
  }
}

async function countAliases(repo: IdentityRepository, pubkey: string): Promise<number> {
  const identities = await repo.listIdentitiesByPubkey(pubkey)
  return identities.filter((identity: UserIdentity) => !isEncodedLocalPart(identity.localPart)).length
}

function isDuplicateIdentityError(error: unknown): boolean {
  if (!error || typeof error !== 'object') return false

  const pgError = error as { code?: unknown; constraint?: unknown }
  return pgError.code === '23505' && pgError.constraint === duplicateConstraint
}
