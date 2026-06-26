import test from 'node:test'
import assert from 'node:assert/strict'
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import { buildApp } from '../src/app.js'
import { NIP98_KIND } from '../src/nip98.js'
import { MemoryIdentityRepository } from './helpers.js'

const appConfig = { inboundDecisionToken: 'secret-token' }
const domain = 'nmail.li'

interface TokenOptions {
  sk?: Uint8Array
  method: string
  path: string
  host?: string
  createdAt?: number
  kind?: number
}

// Build the `Authorization: Nostr <base64>` value for a NIP-98 request. `u` is
// the absolute URL the server reconstructs from Host + path.
function authToken(options: TokenOptions) {
  const sk = options.sk ?? generateSecretKey()
  const url = `https://${options.host ?? domain}${options.path}`
  const event = finalizeEvent(
    {
      kind: options.kind ?? NIP98_KIND,
      created_at: options.createdAt ?? Math.floor(Date.now() / 1000),
      tags: [
        ['u', url],
        ['method', options.method],
      ],
      content: '',
    },
    sk,
  )

  return { token: `Nostr ${Buffer.from(JSON.stringify(event)).toString('base64')}`, sk, pubkey: getPublicKey(sk) }
}

async function buildAliasApp() {
  const repo = new MemoryIdentityRepository()
  await repo.addDomain(domain)
  const app = await buildApp(repo, appConfig)
  return { repo, app }
}

function put(app: Awaited<ReturnType<typeof buildApp>>, name: string, options: { sk?: Uint8Array; visibility?: string } = {}) {
  const path = `/aliases/${name}` + (options.visibility ? `?visibility=${options.visibility}` : '')
  const { token, sk, pubkey } = authToken({ sk: options.sk, method: 'PUT', path })
  return { sk, pubkey, response: app.inject({ method: 'PUT', url: path, headers: { host: domain, authorization: token } }) }
}

test('PUT claims a public alias and auto-creates the account', async () => {
  const { repo, app } = await buildAliasApp()
  const { pubkey, response } = put(app, 'alicia')

  const result = await response
  assert.equal(result.statusCode, 201)
  assert.deepEqual(result.json().alias, { domain, localPart: 'alicia', pubkey, visibility: 'public' })
  assert.ok(await repo.getAccount(pubkey), 'account is created')

  await app.close()
})

test('PUT honours the requested visibility', async () => {
  const { app } = await buildAliasApp()
  const result = await put(app, 'hidden1', { visibility: 'private' }).response

  assert.equal(result.statusCode, 201)
  assert.equal(result.json().alias.visibility, 'private')

  await app.close()
})

test('PUT by the owner updates the visibility and returns 200', async () => {
  const { app } = await buildAliasApp()
  const sk = generateSecretKey()

  const created = await put(app, 'alicia', { sk }).response
  assert.equal(created.statusCode, 201)
  assert.equal(created.json().alias.visibility, 'public')

  const updated = await put(app, 'alicia', { sk, visibility: 'private' }).response
  assert.equal(updated.statusCode, 200)
  assert.equal(updated.json().alias.visibility, 'private')

  await app.close()
})

test('PUT on an alias owned by another pubkey returns 409', async () => {
  const { app } = await buildAliasApp()

  assert.equal((await put(app, 'alicia').response).statusCode, 201)

  const taken = await put(app, 'alicia').response
  assert.equal(taken.statusCode, 409)
  assert.equal(taken.json().error, 'alias_taken')

  await app.close()
})

test('PUT rejects an invalid visibility query', async () => {
  const { app } = await buildAliasApp()
  const result = await put(app, 'alicia', { visibility: 'secret' }).response

  assert.equal(result.statusCode, 400)
  assert.equal(result.json().error, 'invalid_visibility')

  await app.close()
})

test('PUT rejects a reserved local part', async () => {
  const { app } = await buildAliasApp()
  const result = await put(app, 'postmaster').response

  assert.equal(result.statusCode, 400)
  assert.equal(result.json().error, 'reserved_local_part')

  await app.close()
})

test('PUT enforces the free plan alias limit', async () => {
  const { app } = await buildAliasApp()
  const sk = generateSecretKey()

  assert.equal((await put(app, 'first1', { sk }).response).statusCode, 201)
  assert.equal((await put(app, 'second', { sk }).response).statusCode, 201)

  const third = await put(app, 'third1', { sk }).response
  assert.equal(third.statusCode, 403)
  assert.equal(third.json().error, 'alias_limit_reached')

  await app.close()
})

test('PUT allows more aliases on a higher plan', async () => {
  const { repo, app } = await buildAliasApp()
  const sk = generateSecretKey()
  repo.setAccount(getPublicKey(sk), { plan: 'premium' })

  for (const name of ['alias1', 'alias2', 'alias3']) {
    assert.equal((await put(app, name, { sk }).response).statusCode, 201)
  }

  await app.close()
})

test('PUT rejects a disabled account', async () => {
  const { repo, app } = await buildAliasApp()
  const sk = generateSecretKey()
  repo.setAccount(getPublicKey(sk), { active: false })

  const result = await put(app, 'alicia', { sk }).response
  assert.equal(result.statusCode, 403)
  assert.equal(result.json().error, 'account_disabled')

  await app.close()
})

test('PUT rejects a domain outside the plan allowed_domains', async () => {
  const { repo, app } = await buildAliasApp()
  await repo.upsertPlan(
    'restricted',
    { perMinute: 5, perHour: 30, perDay: 50, maxMessageBytes: 1, maxRecipients: 5, maxAliases: 5, allowedDomains: ['other.example'] },
    false,
  )
  const sk = generateSecretKey()
  repo.setAccount(getPublicKey(sk), { plan: 'restricted' })

  const result = await put(app, 'alicia', { sk }).response
  assert.equal(result.statusCode, 403)
  assert.equal(result.json().error, 'domain_not_allowed')

  await app.close()
})

test('PUT rejects an unmanaged domain', async () => {
  const { app } = await buildAliasApp()
  const host = 'unknown.example'
  const path = '/aliases/alicia'
  const { token } = authToken({ method: 'PUT', path, host })

  const result = await app.inject({ method: 'PUT', url: path, headers: { host, authorization: token } })
  assert.equal(result.statusCode, 400)
  assert.equal(result.json().error, 'domain_not_managed')

  await app.close()
})

test('PUT rejects a too-short local part', async () => {
  const { app } = await buildAliasApp()
  const result = await put(app, 'bob').response

  assert.equal(result.statusCode, 400)
  assert.equal(result.json().error, 'invalid_local_part')

  await app.close()
})

test('PUT rejects local parts with non-NIP-05 or edge separators', async () => {
  const { app } = await buildAliasApp()

  for (const name of ['.leading', 'trailing-', 'a..b.cd', 'bad+name']) {
    const result = await put(app, name).response
    assert.equal(result.statusCode, 400, name)
    assert.equal(result.json().error, 'invalid_local_part', name)
  }

  await app.close()
})

test('PUT accepts a clean local part with single separators', async () => {
  const { app } = await buildAliasApp()
  const result = await put(app, 'moi.cool-42').response

  assert.equal(result.statusCode, 201)
  assert.equal(result.json().alias.localPart, 'moi.cool-42')

  await app.close()
})

test('PUT rejects a pubkey-encoded local part', async () => {
  const { app } = await buildAliasApp()
  const result = await put(app, 'a'.repeat(64)).response

  assert.equal(result.statusCode, 400)
  assert.equal(result.json().error, 'invalid_local_part')

  await app.close()
})

test('GET lists the pubkey aliases', async () => {
  const { app } = await buildAliasApp()
  const sk = generateSecretKey()

  await put(app, 'alias1', { sk }).response
  await put(app, 'alias2', { sk }).response

  const { token } = authToken({ sk, method: 'GET', path: '/aliases' })
  const result = await app.inject({ method: 'GET', url: '/aliases', headers: { host: domain, authorization: token } })

  assert.equal(result.statusCode, 200)
  const names = result.json().aliases.map((alias: { localPart: string }) => alias.localPart).sort()
  assert.deepEqual(names, ['alias1', 'alias2'])

  await app.close()
})

test('DELETE releases an owned alias', async () => {
  const { repo, app } = await buildAliasApp()
  const sk = generateSecretKey()

  await put(app, 'alicia', { sk }).response

  const path = '/aliases/alicia'
  const { token } = authToken({ sk, method: 'DELETE', path })
  const result = await app.inject({ method: 'DELETE', url: path, headers: { host: domain, authorization: token } })

  assert.equal(result.statusCode, 204)
  assert.equal(await repo.findIdentity(domain, 'alicia'), null)

  await app.close()
})

test('DELETE on an unknown alias returns 404', async () => {
  const { app } = await buildAliasApp()
  const path = '/aliases/ghost1'
  const { token } = authToken({ method: 'DELETE', path })

  const result = await app.inject({ method: 'DELETE', url: path, headers: { host: domain, authorization: token } })
  assert.equal(result.statusCode, 404)
  assert.equal(result.json().error, 'alias_not_found')

  await app.close()
})

test('DELETE by a non-owner returns 403', async () => {
  const { app } = await buildAliasApp()

  await put(app, 'alicia').response

  const path = '/aliases/alicia'
  const { token } = authToken({ method: 'DELETE', path })
  const result = await app.inject({ method: 'DELETE', url: path, headers: { host: domain, authorization: token } })

  assert.equal(result.statusCode, 403)
  assert.equal(result.json().error, 'not_owner')

  await app.close()
})

test('Requests without an Authorization header are rejected', async () => {
  const { app } = await buildAliasApp()
  const result = await app.inject({ method: 'GET', url: '/aliases', headers: { host: domain } })

  assert.equal(result.statusCode, 401)
  assert.equal(result.json().error, 'missing_auth')
  assert.equal(result.headers['www-authenticate'], 'Nostr')

  await app.close()
})

test('A stale NIP-98 token is rejected', async () => {
  const { app } = await buildAliasApp()
  const createdAt = Math.floor(Date.now() / 1000) - 600
  const { token } = authToken({ method: 'GET', path: '/aliases', createdAt })

  const result = await app.inject({ method: 'GET', url: '/aliases', headers: { host: domain, authorization: token } })
  assert.equal(result.statusCode, 401)
  assert.equal(result.json().error, 'stale_event')

  await app.close()
})

test('A token signed for another method is rejected', async () => {
  const { app } = await buildAliasApp()
  const { token } = authToken({ method: 'DELETE', path: '/aliases' })

  const result = await app.inject({ method: 'GET', url: '/aliases', headers: { host: domain, authorization: token } })
  assert.equal(result.statusCode, 401)
  assert.equal(result.json().error, 'method_mismatch')

  await app.close()
})

test('A token signed for another path is rejected', async () => {
  const { app } = await buildAliasApp()
  const { token } = authToken({ method: 'PUT', path: '/aliases/other1' })

  const result = await app.inject({ method: 'PUT', url: '/aliases/alicia', headers: { host: domain, authorization: token } })
  assert.equal(result.statusCode, 401)
  assert.equal(result.json().error, 'url_mismatch')

  await app.close()
})

test('A token signed for another host is rejected', async () => {
  const { app } = await buildAliasApp()
  const { token } = authToken({ method: 'GET', path: '/aliases', host: 'evil.example' })

  const result = await app.inject({ method: 'GET', url: '/aliases', headers: { host: domain, authorization: token } })
  assert.equal(result.statusCode, 401)
  assert.equal(result.json().error, 'url_mismatch')

  await app.close()
})

test('The wrong NIP-98 event kind is rejected', async () => {
  const { app } = await buildAliasApp()
  const { token } = authToken({ method: 'GET', path: '/aliases', kind: 1 })

  const result = await app.inject({ method: 'GET', url: '/aliases', headers: { host: domain, authorization: token } })
  assert.equal(result.statusCode, 401)
  assert.equal(result.json().error, 'invalid_event')

  await app.close()
})

test('A PUT-claimed public alias resolves over NIP-05', async () => {
  const { app } = await buildAliasApp()
  assert.equal((await put(app, 'alicia').response).statusCode, 201)

  const nip05 = await app.inject({ method: 'GET', url: '/.well-known/nostr.json?name=alicia', headers: { host: domain } })
  assert.equal(nip05.statusCode, 200)
  assert.ok(nip05.json().names.alicia, 'alias is published in NIP-05')

  await app.close()
})
