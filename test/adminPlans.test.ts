import test from 'node:test'
import assert from 'node:assert/strict'
import { buildApp } from '../src/app.js'
import { MemoryIdentityRepository } from './helpers.js'

const appConfig = {
  inboundDecisionToken: 'secret-token',
  adminPassword: 'admin-secret',
}

async function login(app: Awaited<ReturnType<typeof buildApp>>): Promise<string> {
  const response = await app.inject({ method: 'POST', url: '/admin/login', payload: { password: 'admin-secret' } })
  assert.equal(response.statusCode, 200)
  return String(response.headers['set-cookie']).split(';')[0]
}

test('Admin lists the seeded plans', async () => {
  const repo = new MemoryIdentityRepository()
  const app = await buildApp(repo, appConfig)
  const cookie = await login(app)

  const response = await app.inject({ method: 'GET', url: '/admin/api/plans', headers: { cookie } })

  assert.equal(response.statusCode, 200)
  const names = response.json().plans.map((plan: { name: string }) => plan.name)
  assert.deepEqual(names.sort(), ['free', 'premium'])

  await app.close()
})

test('Admin creates and updates a plan', async () => {
  const repo = new MemoryIdentityRepository()
  const app = await buildApp(repo, appConfig)
  const cookie = await login(app)

  const created = await app.inject({
    method: 'PUT',
    url: '/admin/api/plans/business',
    headers: { cookie },
    payload: { perMinute: 20, perHour: 200, perDay: 1000, maxMessageBytes: 50 * 1024 * 1024, maxRecipients: 25, isDefault: false },
  })

  assert.equal(created.statusCode, 200)
  assert.equal(created.json().plan.name, 'business')
  assert.equal(created.json().plan.maxRecipients, 25)

  const updated = await app.inject({
    method: 'PUT',
    url: '/admin/api/plans/business',
    headers: { cookie },
    payload: { perMinute: 30, perHour: 200, perDay: 1000, maxMessageBytes: 50 * 1024 * 1024, maxRecipients: 25, isDefault: false },
  })
  assert.equal(updated.json().plan.perMinute, 30)

  await app.close()
})

test('Admin moving the default flag leaves only one default plan', async () => {
  const repo = new MemoryIdentityRepository()
  const app = await buildApp(repo, appConfig)
  const cookie = await login(app)

  await app.inject({
    method: 'PUT',
    url: '/admin/api/plans/premium',
    headers: { cookie },
    payload: { perMinute: 10, perHour: 100, perDay: 500, maxMessageBytes: 26214400, maxRecipients: 10, isDefault: true },
  })

  const plans = (await app.inject({ method: 'GET', url: '/admin/api/plans', headers: { cookie } })).json().plans
  const defaults = plans.filter((plan: { isDefault: boolean }) => plan.isDefault).map((plan: { name: string }) => plan.name)
  assert.deepEqual(defaults, ['premium'])

  await app.close()
})

test('Admin rejects invalid plan limits', async () => {
  const repo = new MemoryIdentityRepository()
  const app = await buildApp(repo, appConfig)
  const cookie = await login(app)

  const response = await app.inject({
    method: 'PUT',
    url: '/admin/api/plans/broken',
    headers: { cookie },
    payload: { perMinute: -1, perHour: 100, perDay: 500, maxMessageBytes: 100, maxRecipients: 10 },
  })

  assert.equal(response.statusCode, 400)
  assert.equal(response.json().error, 'invalid_plan')

  await app.close()
})

test('Admin will not delete the default plan', async () => {
  const repo = new MemoryIdentityRepository()
  const app = await buildApp(repo, appConfig)
  const cookie = await login(app)

  const response = await app.inject({ method: 'DELETE', url: '/admin/api/plans/free', headers: { cookie } })

  assert.equal(response.statusCode, 409)

  await app.close()
})

test('Admin sets, lists and deletes an account', async () => {
  const repo = new MemoryIdentityRepository()
  const app = await buildApp(repo, appConfig)
  const cookie = await login(app)
  const pubkey = '1'.repeat(64)

  const set = await app.inject({
    method: 'PUT',
    url: `/admin/api/accounts/${pubkey}`,
    headers: { cookie },
    payload: { active: true, mailEnabled: false, plan: 'premium', relays: ['wss://relay.nmail.li'] },
  })
  assert.equal(set.statusCode, 200)
  assert.equal(set.json().account.plan, 'premium')
  assert.equal(set.json().account.mailEnabled, false)
  assert.deepEqual(set.json().account.relays, ['wss://relay.nmail.li'])

  const listed = await app.inject({ method: 'GET', url: '/admin/api/accounts', headers: { cookie } })
  assert.equal(listed.json().accounts.length, 1)

  const deleted = await app.inject({ method: 'DELETE', url: `/admin/api/accounts/${pubkey}`, headers: { cookie } })
  assert.equal(deleted.statusCode, 204)

  await app.close()
})

test('Admin defaults an account to the default plan when plan is null', async () => {
  const repo = new MemoryIdentityRepository()
  const app = await buildApp(repo, appConfig)
  const cookie = await login(app)

  const set = await app.inject({
    method: 'PUT',
    url: `/admin/api/accounts/${'3'.repeat(64)}`,
    headers: { cookie },
    payload: { active: true, mailEnabled: true, plan: null, relays: [] },
  })

  assert.equal(set.statusCode, 200)
  assert.equal(set.json().account.plan, null)

  await app.close()
})

test('Admin rejects an account with an unknown plan or invalid pubkey', async () => {
  const repo = new MemoryIdentityRepository()
  const app = await buildApp(repo, appConfig)
  const cookie = await login(app)

  const unknownPlan = await app.inject({
    method: 'PUT',
    url: `/admin/api/accounts/${'2'.repeat(64)}`,
    headers: { cookie },
    payload: { active: true, mailEnabled: true, plan: 'nope', relays: [] },
  })
  const invalidPubkey = await app.inject({
    method: 'PUT',
    url: '/admin/api/accounts/not-a-pubkey',
    headers: { cookie },
    payload: { active: true, mailEnabled: true, plan: 'free', relays: [] },
  })

  assert.equal(unknownPlan.statusCode, 400)
  assert.equal(unknownPlan.json().error, 'unknown_plan')
  assert.equal(invalidPubkey.statusCode, 400)
  assert.equal(invalidPubkey.json().error, 'invalid_pubkey')

  await app.close()
})

test('Admin adds, lists and deletes a domain', async () => {
  const repo = new MemoryIdentityRepository()
  const app = await buildApp(repo, appConfig)
  const cookie = await login(app)

  const added = await app.inject({
    method: 'POST',
    url: '/admin/api/domains',
    headers: { cookie },
    payload: { domain: 'Example.COM' },
  })
  assert.equal(added.statusCode, 201)
  assert.equal(added.json().domain, 'example.com')

  const listed = await app.inject({ method: 'GET', url: '/admin/api/domains', headers: { cookie } })
  assert.deepEqual(listed.json().domains, ['example.com'])

  const deleted = await app.inject({ method: 'DELETE', url: '/admin/api/domains/example.com', headers: { cookie } })
  assert.equal(deleted.statusCode, 204)

  const empty = await app.inject({ method: 'GET', url: '/admin/api/domains', headers: { cookie } })
  assert.deepEqual(empty.json().domains, [])

  await app.close()
})

test('Admin rejects an invalid domain and a missing one', async () => {
  const repo = new MemoryIdentityRepository()
  const app = await buildApp(repo, appConfig)
  const cookie = await login(app)

  const invalid = await app.inject({ method: 'POST', url: '/admin/api/domains', headers: { cookie }, payload: { domain: '' } })
  const missing = await app.inject({ method: 'DELETE', url: '/admin/api/domains/none.example', headers: { cookie } })

  assert.equal(invalid.statusCode, 400)
  assert.equal(invalid.json().error, 'invalid_domain')
  assert.equal(missing.statusCode, 404)

  await app.close()
})
