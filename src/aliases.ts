import type { FastifyReply } from 'fastify'
import { isEncodedLocalPart } from './nostr.js'
import { isDomainAllowed } from './policy.js'
import type {
  AccountRepository,
  DomainRepository,
  IdentityRepository,
  IdentityVisibility,
  PolicyRepository,
  UserIdentity,
} from './types.js'

// Provisioned alias local part bounds. The 47 cap also keeps aliases clear of
// the base36-encoded pubkey range (48-52 chars), which is never an alias.
export const ALIAS_LOCAL_PART_MIN = 6
export const ALIAS_LOCAL_PART_MAX = 47

// NIP-05 allows a-z0-9-_. ; we go stricter: separators only between alphanumerics
// (no leading/trailing or repeated . _ -). Local part is already lowercased.
export const ALIAS_LOCAL_PART = /^[a-z0-9]+([._-][a-z0-9]+)*$/

// Role and system mailboxes that must not be user-claimable (RFC 2142 plus
// common service addresses). Matched with separators stripped, so post-master,
// no.reply, etc. cannot slip through. The admin path can still provision these.
export const RESERVED_LOCAL_PARTS = new Set([
  'abuse', 'admin', 'administrator', 'billing', 'contact', 'daemon', 'help',
  'hostmaster', 'info', 'legal', 'mail', 'mailerdaemon', 'marketing', 'noc',
  'noreply', 'nostr', 'postmaster', 'privacy', 'root', 'sales', 'security',
  'spam', 'support', 'sysadmin', 'usenet', 'uucp', 'webmaster', 'www',
])

export type LocalPartReason = 'reserved_local_part' | 'invalid_local_part'

// Reserved/length/charset rules for a provisioned alias local part. The REST
// alias endpoints take the name from the request URL, so it is validated here
// rather than from a trusted source.
export function validateLocalPart(localPart: string): LocalPartReason | null {
  if (RESERVED_LOCAL_PARTS.has(localPart.replace(/[._-]/g, ''))) return 'reserved_local_part'
  if (localPart.length < ALIAS_LOCAL_PART_MIN || localPart.length > ALIAS_LOCAL_PART_MAX) return 'invalid_local_part'
  if (!ALIAS_LOCAL_PART.test(localPart)) return 'invalid_local_part'

  return null
}

export type AliasRepository = IdentityRepository & AccountRepository & PolicyRepository & DomainRepository

export interface AliasProvisionInput {
  pubkey: string
  domain: string
  localPart: string
  visibility: IdentityVisibility
}

export type AliasProvisionResult =
  | { status: 'created'; alias: UserIdentity }
  | { status: 'updated'; alias: UserIdentity }
  | { status: 'taken' }
  | { status: 'rejected'; code: 400 | 403; error: string; message?: string }
  | { status: 'unavailable' }

const duplicateConstraint = 'identities_unique_name'

// The single place that turns an authenticated (pubkey, domain, localPart,
// visibility) into an identity row, enforcing the alias policy.
// `updateVisibility` controls the idempotent owner branch: REST PUT updates the
// visibility, a re-claim of the same name returns the existing row untouched.
export async function provisionAlias(
  repo: AliasRepository,
  input: AliasProvisionInput,
  options: { updateVisibility: boolean },
): Promise<AliasProvisionResult> {
  const { pubkey, domain, localPart, visibility } = input

  const reason = validateLocalPart(localPart)
  if (reason) return { status: 'rejected', code: 400, error: reason }
  if (isEncodedLocalPart(localPart)) return { status: 'rejected', code: 400, error: 'encoded_not_claimable' }

  try {
    const domains = new Set(await repo.listDomains())
    if (!domains.has(domain)) return { status: 'rejected', code: 400, error: 'domain_not_managed' }

    const existing = await repo.findIdentity(domain, localPart)
    if (existing) {
      if (existing.pubkey !== pubkey) return { status: 'taken' }
      if (options.updateVisibility && existing.visibility !== visibility && repo.setIdentityVisibility) {
        const updated = await repo.setIdentityVisibility(domain, localPart, pubkey, visibility)
        if (updated) return { status: 'updated', alias: toAlias(updated) }
      }
      return { status: 'updated', alias: toAlias(existing) }
    }

    const account = await repo.getOrCreateAccount(pubkey)
    if (!account.active) return { status: 'rejected', code: 403, error: 'account_disabled' }

    const plan = await repo.getPlan(account.plan)
    if (!isDomainAllowed(plan, domain)) {
      return { status: 'rejected', code: 403, error: 'domain_not_allowed', message: `Your plan cannot claim aliases on ${domain}` }
    }

    const aliasCount = await countAliases(repo, pubkey)
    if (aliasCount >= plan.maxAliases) {
      return { status: 'rejected', code: 403, error: 'alias_limit_reached', message: `Your plan allows at most ${plan.maxAliases} aliases` }
    }

    if (!repo.createIdentity) return { status: 'unavailable' }
    const alias = await repo.createIdentity({ domain, localPart, pubkey, visibility })
    return { status: 'created', alias: toAlias(alias) }
  } catch (error) {
    if (isDuplicateIdentityError(error)) return { status: 'taken' }
    throw error
  }
}

export function sendAliasResult(reply: FastifyReply, result: AliasProvisionResult) {
  switch (result.status) {
    case 'created':
      return reply.code(201).send({ alias: result.alias })
    case 'updated':
      return reply.send({ alias: result.alias })
    case 'taken':
      return reply.code(409).send({ error: 'alias_taken' })
    case 'rejected':
      return reply.code(result.code).send(result.message ? { error: result.error, message: result.message } : { error: result.error })
    case 'unavailable':
      return reply.code(501).send({ error: 'claim_unavailable' })
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
  return identities.filter((identity) => !isEncodedLocalPart(identity.localPart)).length
}

function isDuplicateIdentityError(error: unknown): boolean {
  if (!error || typeof error !== 'object') return false

  const pgError = error as { code?: unknown; constraint?: unknown }
  return pgError.code === '23505' && pgError.constraint === duplicateConstraint
}
