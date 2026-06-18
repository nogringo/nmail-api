import test from 'node:test'
import assert from 'node:assert/strict'
import { buildApp } from '../src/app.js'
import { identity, MemoryIdentityRepository } from './helpers.js'

const appConfig = {
  protectedEmailDomains: new Set(['nmail.li']),
  inboundDecisionToken: 'secret-token',
  adminPassword: 'admin-secret',
}

const baseIdentityPayload = {
  domain: 'NMAIL.LI',
  localPart: 'Alice',
  pubkey: 'A'.repeat(64),
  relays: ['wss://relay.nmail.li'],
  visibility: 'public',
  mailEnabled: true,
  active: true,
}

test('Admin routes are disabled when ADMIN_PASSWORD is absent', async () => {
  const repo = new MemoryIdentityRepository()
  const app = await buildApp(repo, { protectedEmailDomains: new Set(['nmail.li']), inboundDecisionToken: 'secret-token' })

  const response = await app.inject({ method: 'GET', url: '/admin' })

  assert.equal(response.statusCode, 404)

  await app.close()
})

test('Admin API rejects unauthenticated requests', async () => {
  const repo = new MemoryIdentityRepository()
  const app = await buildApp(repo, appConfig)

  const response = await app.inject({ method: 'GET', url: '/admin/api/identities' })

  assert.equal(response.statusCode, 401)
  assert.deepEqual(response.json(), { error: 'unauthorized' })

  await app.close()
})

test('Admin login rejects invalid passwords and sets a session cookie for valid passwords', async () => {
  const repo = new MemoryIdentityRepository()
  const app = await buildApp(repo, appConfig)

  const invalid = await app.inject({
    method: 'POST',
    url: '/admin/login',
    payload: { password: 'wrong' },
  })
  const valid = await app.inject({
    method: 'POST',
    url: '/admin/login',
    payload: { password: 'admin-secret' },
  })

  assert.equal(invalid.statusCode, 401)
  assert.deepEqual(invalid.json(), { error: 'invalid_password' })
  assert.equal(valid.statusCode, 200)
  assert.match(String(valid.headers['set-cookie']), /nmail_admin_session=/)
  assert.match(String(valid.headers['set-cookie']), /HttpOnly/)

  await app.close()
})

test('Admin API creates, lists, updates, toggles, and deletes identities', async () => {
  const repo = new MemoryIdentityRepository()
  const app = await buildApp(repo, appConfig)
  const cookie = await login(app)

  const created = await app.inject({
    method: 'POST',
    url: '/admin/api/identities',
    headers: { cookie },
    payload: baseIdentityPayload,
  })
  assert.equal(created.statusCode, 201)
  assert.equal(created.json().identity.domain, 'nmail.li')
  assert.equal(created.json().identity.localPart, 'alice')
  assert.equal(created.json().identity.pubkey, 'a'.repeat(64))

  const id = created.json().identity.id
  const listed = await app.inject({
    method: 'GET',
    url: '/admin/api/identities?search=alice',
    headers: { cookie },
  })
  assert.equal(listed.statusCode, 200)
  assert.equal(listed.json().identities.length, 1)

  const updated = await app.inject({
    method: 'PUT',
    url: `/admin/api/identities/${id}`,
    headers: { cookie },
    payload: { ...baseIdentityPayload, localPart: 'bob', visibility: 'private', mailEnabled: false },
  })
  assert.equal(updated.statusCode, 200)
  assert.equal(updated.json().identity.localPart, 'bob')
  assert.equal(updated.json().identity.visibility, 'private')
  assert.equal(updated.json().identity.mailEnabled, false)

  const deactivated = await app.inject({
    method: 'POST',
    url: `/admin/api/identities/${id}/deactivate`,
    headers: { cookie },
  })
  assert.equal(deactivated.statusCode, 200)
  assert.equal(deactivated.json().identity.active, false)

  const activated = await app.inject({
    method: 'POST',
    url: `/admin/api/identities/${id}/activate`,
    headers: { cookie },
  })
  assert.equal(activated.statusCode, 200)
  assert.equal(activated.json().identity.active, true)

  const deleted = await app.inject({
    method: 'DELETE',
    url: `/admin/api/identities/${id}`,
    headers: { cookie },
  })
  assert.equal(deleted.statusCode, 204)

  const afterDelete = await app.inject({
    method: 'GET',
    url: '/admin/api/identities',
    headers: { cookie },
  })
  assert.deepEqual(afterDelete.json().identities, [])

  await app.close()
})

test('Admin API returns useful errors for validation and duplicate identities', async () => {
  const repo = new MemoryIdentityRepository()
  repo.add(identity())
  const app = await buildApp(repo, appConfig)
  const cookie = await login(app)

  const invalidPubkey = await app.inject({
    method: 'POST',
    url: '/admin/api/identities',
    headers: { cookie },
    payload: { ...baseIdentityPayload, pubkey: 'bad' },
  })
  const invalidRelay = await app.inject({
    method: 'POST',
    url: '/admin/api/identities',
    headers: { cookie },
    payload: { ...baseIdentityPayload, relays: ['https://relay.nmail.li'] },
  })
  const invalidVisibility = await app.inject({
    method: 'POST',
    url: '/admin/api/identities',
    headers: { cookie },
    payload: { ...baseIdentityPayload, visibility: 'hidden' },
  })
  const duplicate = await app.inject({
    method: 'POST',
    url: '/admin/api/identities',
    headers: { cookie },
    payload: { ...baseIdentityPayload, pubkey: '1'.repeat(64) },
  })

  assert.equal(invalidPubkey.statusCode, 400)
  assert.equal(invalidPubkey.json().error, 'invalid_identity')
  assert.equal(invalidRelay.statusCode, 400)
  assert.equal(invalidRelay.json().error, 'invalid_identity')
  assert.equal(invalidVisibility.statusCode, 400)
  assert.equal(invalidVisibility.json().error, 'invalid_identity')
  assert.equal(duplicate.statusCode, 409)
  assert.deepEqual(duplicate.json(), {
    error: 'identity_already_exists',
    message: 'An identity already exists for this domain and local part',
  })

  await app.close()
})

test('Admin API returns not found for missing identities', async () => {
  const repo = new MemoryIdentityRepository()
  const app = await buildApp(repo, appConfig)
  const cookie = await login(app)

  const update = await app.inject({
    method: 'PUT',
    url: '/admin/api/identities/404',
    headers: { cookie },
    payload: baseIdentityPayload,
  })
  const toggle = await app.inject({
    method: 'POST',
    url: '/admin/api/identities/404/deactivate',
    headers: { cookie },
  })
  const remove = await app.inject({
    method: 'DELETE',
    url: '/admin/api/identities/404',
    headers: { cookie },
  })

  assert.equal(update.statusCode, 404)
  assert.deepEqual(update.json(), { error: 'identity_not_found' })
  assert.equal(toggle.statusCode, 404)
  assert.deepEqual(toggle.json(), { error: 'identity_not_found' })
  assert.equal(remove.statusCode, 404)
  assert.deepEqual(remove.json(), { error: 'identity_not_found' })

  await app.close()
})

async function login(app: Awaited<ReturnType<typeof buildApp>>): Promise<string> {
  const response = await app.inject({
    method: 'POST',
    url: '/admin/login',
    payload: { password: 'admin-secret' },
  })
  assert.equal(response.statusCode, 200)
  return String(response.headers['set-cookie']).split(';')[0]
}
