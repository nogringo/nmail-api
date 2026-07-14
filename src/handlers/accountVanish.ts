import type { FastifyReply, FastifyRequest } from 'fastify'
import { verifyEvent } from 'nostr-tools/pure'
import { asNostrEvent, normalizeRelayUrl, type NostrEvent } from '../nostr.js'
import type { AccountRepository, AppConfig } from '../types.js'

const NIP62_KIND = 62
const MAX_PAST_SECONDS = 7 * 24 * 60 * 60
const MAX_FUTURE_SECONDS = 24 * 60 * 60
const ALL_RELAYS = 'ALL_RELAYS'

export function createAccountVanishHandler(
  repo: AccountRepository,
  config: Pick<AppConfig, 'accountDeletionRelayUrls'>,
) {
  const relayUrls = new Set(config.accountDeletionRelayUrls.map(normalizeRelayUrl).filter((relay): relay is string => relay !== null))

  return async function accountVanishHandler(request: FastifyRequest, reply: FastifyReply) {
    const event = parsePayload(request.body)
    if (!event || !isValidVanishEvent(event, relayUrls, Math.floor(Date.now() / 1000))) {
      return reply.code(400).send({ error: 'invalid_request' })
    }

    await repo.deleteAccountData(event.pubkey)
    return reply.code(202).send({ status: 'accepted' })
  }
}

function parsePayload(value: unknown): NostrEvent | null {
  if (!value || typeof value !== 'object') return null

  const payload = value as Record<string, unknown>
  return asNostrEvent(payload.event)
}

function isValidVanishEvent(event: NostrEvent, relayUrls: Set<string>, nowSeconds: number): boolean {
  if (event.kind !== NIP62_KIND) return false
  if (!/^[0-9a-f]{64}$/.test(event.pubkey)) return false
  if (event.created_at < nowSeconds - MAX_PAST_SECONDS) return false
  if (event.created_at > nowSeconds + MAX_FUTURE_SECONDS) return false
  if (!targetsNmail(event.tags, relayUrls)) return false

  try {
    return verifyEvent(event)
  } catch {
    return false
  }
}

function targetsNmail(tags: string[][], relayUrls: Set<string>): boolean {
  return tags.some((tag) => {
    if (tag[0] !== 'relay') return false
    if (tag[1] === ALL_RELAYS) return true

    const relayUrl = normalizeRelayUrl(tag[1])
    return relayUrl !== null && relayUrls.has(relayUrl)
  })
}
