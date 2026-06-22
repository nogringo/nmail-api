import test from 'node:test'
import assert from 'node:assert/strict'
import { buildApp } from '../src/app.js'
import { MemoryIdentityRepository } from './helpers.js'

const appConfig = {
  protectedEmailDomains: new Set(['nmail.li']),
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

test('Admin assigns and clears a pubkey plan', async () => {
  const repo = new MemoryIdentityRepository()
  const app = await buildApp(repo, appConfig)
  const cookie = await login(app)
  const pubkey = '1'.repeat(64)

  const assigned = await app.inject({
    method: 'PUT',
    url: `/admin/api/pubkey-plans/${pubkey}`,
    headers: { cookie },
    payload: { plan: 'premium' },
  })
  assert.equal(assigned.statusCode, 200)
  assert.equal(assigned.json().assignment.plan, 'premium')

  const listed = await app.inject({ method: 'GET', url: '/admin/api/pubkey-plans', headers: { cookie } })
  assert.equal(listed.json().assignments.length, 1)

  const cleared = await app.inject({ method: 'DELETE', url: `/admin/api/pubkey-plans/${pubkey}`, headers: { cookie } })
  assert.equal(cleared.statusCode, 204)

  await app.close()
})

test('Admin rejects assignment to an unknown plan or invalid pubkey', async () => {
  const repo = new MemoryIdentityRepository()
  const app = await buildApp(repo, appConfig)
  const cookie = await login(app)

  const unknownPlan = await app.inject({
    method: 'PUT',
    url: `/admin/api/pubkey-plans/${'2'.repeat(64)}`,
    headers: { cookie },
    payload: { plan: 'nope' },
  })
  const invalidPubkey = await app.inject({
    method: 'PUT',
    url: '/admin/api/pubkey-plans/not-a-pubkey',
    headers: { cookie },
    payload: { plan: 'free' },
  })

  assert.equal(unknownPlan.statusCode, 400)
  assert.equal(unknownPlan.json().error, 'unknown_plan')
  assert.equal(invalidPubkey.statusCode, 400)
  assert.equal(invalidPubkey.json().error, 'invalid_pubkey')

  await app.close()
})
