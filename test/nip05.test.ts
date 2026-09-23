import test from 'node:test'
import assert from 'node:assert/strict'
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import { buildApp } from '../src/app.js'
import { NIP98_KIND } from '../src/nip98.js'
import { identity, MemoryIdentityRepository } from './helpers.js'

function nip98Token(sk: Uint8Array, url: string): string {
  const event = finalizeEvent(
    {
      kind: NIP98_KIND,
      created_at: Math.floor(Date.now() / 1000),
      tags: [
        ['u', url],
        ['method', 'GET'],
      ],
      content: '',
    },
    sk,
  )

  return `Nostr ${Buffer.from(JSON.stringify(event)).toString('base64')}`
}

async function signedPrivateLookup(options: { readers: string[]; sk: Uint8Array; signedName?: string }) {
  const repo = new MemoryIdentityRepository()
  repo.add(identity({ visibility: 'private' }))
  const app = await buildApp(repo, { inboundDecisionToken: 'secret-token', nip05PrivateReaders: options.readers })
  const signedUrl = `https://nmail.li/.well-known/nostr.json?name=${options.signedName ?? 'alice'}`

  const response = await app.inject({
    method: 'GET',
    url: '/.well-known/nostr.json?name=alice',
    headers: { host: 'nmail.li', authorization: nip98Token(options.sk, signedUrl) },
  })

  await app.close()
  return response
}

test('NIP-05 returns active identity with relays', async () => {
  const repo = new MemoryIdentityRepository()
  repo.add(identity())
  repo.setAccount('0'.repeat(64), { relays: ['wss://relay.damus.io'] })
  const app = await buildApp(repo, { inboundDecisionToken: 'secret-token' })

  const response = await app.inject({
    method: 'GET',
    url: '/.well-known/nostr.json?name=Alice',
    headers: { host: 'nmail.li:3000' },
  })

  assert.equal(response.statusCode, 200)
  assert.deepEqual(response.json(), {
    names: { alice: '0'.repeat(64) },
    relays: { ['0'.repeat(64)]: ['wss://relay.damus.io'] },
  })

  await app.close()
})

test('NIP-05 returns an empty response when identity is absent', async () => {
  const repo = new MemoryIdentityRepository()
  const app = await buildApp(repo, { inboundDecisionToken: 'secret-token' })

  const response = await app.inject({
    method: 'GET',
    url: '/.well-known/nostr.json?name=alice',
    headers: { host: 'nmail.li' },
  })

  assert.equal(response.statusCode, 200)
  assert.deepEqual(response.json(), { names: {}, relays: {} })

  await app.close()
})

test('NIP-05 does not return private identities publicly', async () => {
  const repo = new MemoryIdentityRepository()
  repo.add(identity({ visibility: 'private' }))
  const app = await buildApp(repo, { inboundDecisionToken: 'secret-token' })

  const response = await app.inject({
    method: 'GET',
    url: '/.well-known/nostr.json?name=alice',
    headers: { host: 'nmail.li' },
  })

  assert.equal(response.statusCode, 200)
  assert.deepEqual(response.json(), { names: {}, relays: {} })

  await app.close()
})

test('NIP-05 returns private identities to a listed reader', async () => {
  const sk = generateSecretKey()
  const response = await signedPrivateLookup({ readers: [getPublicKey(sk)], sk })

  assert.equal(response.statusCode, 200)
  assert.equal(response.headers['cache-control'], 'no-store')
  assert.deepEqual(response.json().names, { alice: '0'.repeat(64) })
})

test('NIP-05 hides private identities from signers that are not readers', async () => {
  const response = await signedPrivateLookup({ readers: [getPublicKey(generateSecretKey())], sk: generateSecretKey() })

  assert.equal(response.statusCode, 200)
  assert.deepEqual(response.json(), { names: {}, relays: {} })
})

test('NIP-05 private reads are bound to the signed name', async () => {
  const sk = generateSecretKey()
  const response = await signedPrivateLookup({ readers: [getPublicKey(sk)], sk, signedName: 'bob' })

  assert.equal(response.statusCode, 200)
  assert.deepEqual(response.json(), { names: {}, relays: {} })
})
