import test from 'node:test'
import assert from 'node:assert/strict'
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import { buildApp } from '../src/app.js'
import { ALIAS_CLAIM_KIND } from '../src/claim.js'
import { MemoryIdentityRepository } from './helpers.js'

const appConfig = { inboundDecisionToken: 'secret-token' }
const domain = 'nmail.li'

interface ClaimOptions {
  sk?: Uint8Array
  address: string
  visibility?: string
  createdAt?: number
  kind?: number
}

function claimEvent(options: ClaimOptions) {
  const sk = options.sk ?? generateSecretKey()
  const tags: string[][] = [['address', options.address]]
  if (options.visibility) tags.push(['visibility', options.visibility])

  const event = finalizeEvent(
    {
      kind: options.kind ?? ALIAS_CLAIM_KIND,
      created_at: options.createdAt ?? Math.floor(Date.now() / 1000),
      tags,
      content: '',
    },
    sk,
  )

  return { event, sk, pubkey: getPublicKey(sk) }
}

async function buildClaimApp() {
  const repo = new MemoryIdentityRepository()
  await repo.addDomain(domain)
  const app = await buildApp(repo, appConfig)
  return { repo, app }
}

async function claim(app: Awaited<ReturnType<typeof buildApp>>, event: unknown) {
  return app.inject({ method: 'POST', url: '/aliases/claim', payload: event as object })
}

test('Claim creates a public alias and auto-creates the account', async () => {
  const { repo, app } = await buildClaimApp()
  const { event, pubkey } = claimEvent({ address: `alicia@${domain}` })

  const response = await claim(app, event)

  assert.equal(response.statusCode, 201)
  assert.deepEqual(response.json().alias, {
    domain,
    localPart: 'alicia',
    pubkey,
    visibility: 'public',
  })
  assert.ok(await repo.getAccount(pubkey), 'account is created')

  await app.close()
})

test('Claim honours the requested visibility', async () => {
  const { app } = await buildClaimApp()
  const { event } = claimEvent({ address: `hidden@${domain}`, visibility: 'private' })

  const response = await claim(app, event)

  assert.equal(response.statusCode, 201)
  assert.equal(response.json().alias.visibility, 'private')

  await app.close()
})

test('Claiming the same alias twice is idempotent for the owner', async () => {
  const { app } = await buildClaimApp()
  const sk = generateSecretKey()

  const first = await claim(app, claimEvent({ sk, address: `alicia@${domain}` }).event)
  assert.equal(first.statusCode, 201)

  const second = await claim(app, claimEvent({ sk, address: `alicia@${domain}` }).event)
  assert.equal(second.statusCode, 200)
  assert.equal(second.json().alias.localPart, 'alicia')

  await app.close()
})

test('Claiming an alias owned by another pubkey is rejected', async () => {
  const { app } = await buildClaimApp()

  const first = await claim(app, claimEvent({ address: `alicia@${domain}` }).event)
  assert.equal(first.statusCode, 201)

  const second = await claim(app, claimEvent({ address: `alicia@${domain}` }).event)
  assert.equal(second.statusCode, 409)
  assert.equal(second.json().error, 'alias_taken')

  await app.close()
})

test('Claim enforces the free plan alias limit', async () => {
  const { app } = await buildClaimApp()
  const sk = generateSecretKey()

  assert.equal((await claim(app, claimEvent({ sk, address: `first1@${domain}` }).event)).statusCode, 201)
  assert.equal((await claim(app, claimEvent({ sk, address: `second@${domain}` }).event)).statusCode, 201)

  const third = await claim(app, claimEvent({ sk, address: `third1@${domain}` }).event)
  assert.equal(third.statusCode, 403)
  assert.equal(third.json().error, 'alias_limit_reached')

  await app.close()
})

test('Claim allows more aliases on a higher plan', async () => {
  const { repo, app } = await buildClaimApp()
  const sk = generateSecretKey()
  repo.setAccount(getPublicKey(sk), { plan: 'premium' })

  for (const name of ['alias1', 'alias2', 'alias3']) {
    assert.equal((await claim(app, claimEvent({ sk, address: `${name}@${domain}` }).event)).statusCode, 201)
  }

  await app.close()
})

test('Claim rejects a domain outside the plan allowed_domains', async () => {
  const { repo, app } = await buildClaimApp()
  await repo.upsertPlan(
    'restricted',
    { perMinute: 5, perHour: 30, perDay: 50, maxMessageBytes: 1, maxRecipients: 5, maxAliases: 5, allowedDomains: ['other.example'] },
    false,
  )
  const sk = generateSecretKey()
  repo.setAccount(getPublicKey(sk), { plan: 'restricted' })

  const response = await claim(app, claimEvent({ sk, address: `alicia@${domain}` }).event)

  assert.equal(response.statusCode, 403)
  assert.equal(response.json().error, 'domain_not_allowed')

  await app.close()
})

test('Claim rejects a too-short local part', async () => {
  const { app } = await buildClaimApp()
  const response = await claim(app, claimEvent({ address: `bob@${domain}` }).event)

  assert.equal(response.statusCode, 400)
  assert.equal(response.json().error, 'invalid_local_part')

  await app.close()
})

test('Claim rejects pubkey-encoded local parts (too long to be aliases)', async () => {
  const { app } = await buildClaimApp()
  const hex64 = 'a'.repeat(64)
  const response = await claim(app, claimEvent({ address: `${hex64}@${domain}` }).event)

  assert.equal(response.statusCode, 400)
  assert.equal(response.json().error, 'invalid_local_part')

  await app.close()
})

test('Claim rejects an unmanaged domain', async () => {
  const { app } = await buildClaimApp()
  const response = await claim(app, claimEvent({ address: 'alicia@unknown.example' }).event)

  assert.equal(response.statusCode, 400)
  assert.equal(response.json().error, 'domain_not_managed')

  await app.close()
})

test('Claim rejects a stale event', async () => {
  const { app } = await buildClaimApp()
  const createdAt = Math.floor(Date.now() / 1000) - 3600
  const response = await claim(app, claimEvent({ address: `alice@${domain}`, createdAt }).event)

  assert.equal(response.statusCode, 400)
  assert.equal(response.json().error, 'stale_event')

  await app.close()
})

test('Claim rejects a tampered signature', async () => {
  const { app } = await buildClaimApp()
  const { event } = claimEvent({ address: `alice@${domain}` })
  const tampered = { ...event, tags: [['address', `mallory@${domain}`]] }

  const response = await claim(app, tampered)

  assert.equal(response.statusCode, 400)
  assert.equal(response.json().error, 'invalid_signature')

  await app.close()
})

test('Claim rejects the wrong event kind', async () => {
  const { app } = await buildClaimApp()
  const response = await claim(app, claimEvent({ address: `alice@${domain}`, kind: 1 }).event)

  assert.equal(response.statusCode, 400)
  assert.equal(response.json().error, 'invalid_event')

  await app.close()
})

test('Claimed public alias resolves over NIP-05', async () => {
  const { app } = await buildClaimApp()
  assert.equal((await claim(app, claimEvent({ address: `alicia@${domain}` }).event)).statusCode, 201)

  const nip05 = await app.inject({ method: 'GET', url: `/.well-known/nostr.json?name=alicia`, headers: { host: domain } })
  assert.equal(nip05.statusCode, 200)
  assert.ok(nip05.json().names.alicia, 'alias is published in NIP-05')

  await app.close()
})
