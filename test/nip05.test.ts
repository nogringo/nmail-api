import test from 'node:test'
import assert from 'node:assert/strict'
import { buildApp } from '../src/app.js'
import { identity, MemoryIdentityRepository } from './helpers.js'

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
