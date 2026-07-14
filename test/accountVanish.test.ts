import test from 'node:test'
import assert from 'node:assert/strict'
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import { buildApp } from '../src/app.js'
import { MemoryIdentityRepository, identity } from './helpers.js'

const appConfig = {
  inboundDecisionToken: 'secret-token',
  accountDeletionRelayUrls: ['wss://relay.nmail.li'],
}

function createdAt(): number {
  return Math.floor(Date.now() / 1000)
}

function vanishEvent(options: { sk?: Uint8Array; createdAt?: number; kind?: number; relay?: string } = {}) {
  const sk = options.sk ?? generateSecretKey()
  const event = finalizeEvent(
    {
      kind: options.kind ?? 62,
      created_at: options.createdAt ?? createdAt(),
      tags: [['relay', options.relay ?? 'wss://relay.nmail.li']],
      content: '',
    },
    sk,
  )

  return { event, sk, pubkey: getPublicKey(sk) }
}

async function buildVanishApp() {
  const repo = new MemoryIdentityRepository()
  const app = await buildApp(repo, appConfig)
  return { repo, app }
}

async function post(app: Awaited<ReturnType<typeof buildApp>>, payload: unknown) {
  return app.inject({
    method: 'POST',
    url: '/accounts/vanish',
    headers: { 'content-type': 'application/json' },
    payload: JSON.stringify(payload),
  })
}

test('POST deletes account data for a valid NIP-62 event', async () => {
  const { repo, app } = await buildVanishApp()
  const { event, pubkey } = vanishEvent()

  repo.add(identity({ pubkey, localPart: 'delete-me' }))
  await repo.upsertPushSubscription({ pubkey, transport: 'fcm', destination: 'token-1' })
  await repo.recordOutboundSend(pubkey, 'gift-wrap-1')
  assert.equal(await repo.claimInboundNotificationDelivery(pubkey, 'a'.repeat(64)), true)

  const result = await post(app, { event })

  assert.equal(result.statusCode, 202)
  assert.deepEqual(result.json(), { status: 'accepted' })
  assert.equal(await repo.getAccount(pubkey), null)
  assert.equal(await repo.findIdentity('nmail.li', 'delete-me'), null)
  assert.equal(repo.pushSubscriptions.size, 0)
  assert.equal(repo.sends.length, 0)
  assert.equal(repo.inboundNotificationDeliveries.size, 0)

  await app.close()
})

test('POST accepts ALL_RELAYS', async () => {
  const { repo, app } = await buildVanishApp()
  const { event, pubkey } = vanishEvent({ relay: 'ALL_RELAYS' })
  repo.setAccount(pubkey)

  const result = await post(app, { event })

  assert.equal(result.statusCode, 202)
  assert.equal(await repo.getAccount(pubkey), null)

  await app.close()
})

test('POST is idempotent for already-deleted account data', async () => {
  const { app } = await buildVanishApp()
  const { event } = vanishEvent()

  assert.equal((await post(app, { event })).statusCode, 202)
  assert.equal((await post(app, { event })).statusCode, 202)

  await app.close()
})

test('POST rejects invalid NIP-62 requests without deleting data', async () => {
  const cases: Array<{ name: string; payload: unknown }> = []

  cases.push({ name: 'invalid payload', payload: { nope: true } })
  cases.push({ name: 'wrong kind', payload: { event: vanishEvent({ kind: 1 }).event } })
  cases.push({ name: 'stale event', payload: { event: vanishEvent({ createdAt: createdAt() - 8 * 24 * 60 * 60 }).event } })
  cases.push({ name: 'future event', payload: { event: vanishEvent({ createdAt: createdAt() + 2 * 24 * 60 * 60 }).event } })
  cases.push({ name: 'wrong relay', payload: { event: vanishEvent({ relay: 'wss://other.example' }).event } })

  const signed = vanishEvent()
  cases.push({ name: 'invalid signature', payload: { event: { ...signed.event, content: 'tampered' } } })

  for (const { name, payload } of cases) {
    const { repo, app } = await buildVanishApp()
    const pubkey = signed.pubkey
    repo.setAccount(pubkey)

    const result = await post(app, payload)

    assert.equal(result.statusCode, 400, name)
    assert.deepEqual(result.json(), { error: 'invalid_request' }, name)
    assert.ok(await repo.getAccount(pubkey), name)

    await app.close()
  }
})
