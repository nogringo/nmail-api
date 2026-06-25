import test from 'node:test'
import assert from 'node:assert/strict'
import { createHmac } from 'node:crypto'
import { buildApp } from '../src/app.js'
import { MemoryIdentityRepository } from './helpers.js'

const signingKey = 'role-signing-key'
const appConfig = {
  inboundDecisionToken: 'secret-token',
  roleWebhookSigningKey: signingKey,
}

function signedFields(overrides: Record<string, string> = {}): Record<string, string> {
  const timestamp = String(Math.floor(Date.now() / 1000))
  const token = 'token-123'
  const fields: Record<string, string> = {
    recipient: 'abuse@nmail.li',
    sender: 'reporter@example.com',
    from: 'Reporter <reporter@example.com>',
    subject: 'Spam report',
    'message-headers': JSON.stringify([['Subject', 'Spam report']]),
    timestamp,
    token,
    'body-mime': 'Subject: Spam report\r\n\r\nbody',
    ...overrides,
  }
  if (!('signature' in overrides)) {
    fields.signature = createHmac('sha256', signingKey).update(`${fields.timestamp}${fields.token}`).digest('hex')
  }
  return fields
}

function inject(app: Awaited<ReturnType<typeof buildApp>>, fields: Record<string, string>) {
  return app.inject({
    method: 'POST',
    url: '/inbound/role',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    payload: new URLSearchParams(fields).toString(),
  })
}

test('Role webhook stores a signed message', async () => {
  const repo = new MemoryIdentityRepository()
  const app = await buildApp(repo, appConfig)

  const response = await inject(app, signedFields())

  assert.equal(response.statusCode, 200)
  assert.deepEqual(response.json(), { ok: true })
  assert.equal(repo.roleMessages.length, 1)
  assert.equal(repo.roleMessages[0].recipient, 'abuse@nmail.li')
  assert.equal(repo.roleMessages[0].subject, 'Spam report')
  assert.deepEqual(repo.roleMessages[0].headers, [['Subject', 'Spam report']])

  await app.close()
})

test('Role webhook deduplicates retries with identical body', async () => {
  const repo = new MemoryIdentityRepository()
  const app = await buildApp(repo, appConfig)

  await inject(app, signedFields())
  const retry = await inject(app, signedFields())

  assert.equal(retry.statusCode, 200)
  assert.equal(repo.roleMessages.length, 1)

  await app.close()
})

test('Role webhook rejects an invalid signature', async () => {
  const repo = new MemoryIdentityRepository()
  const app = await buildApp(repo, appConfig)

  const response = await inject(app, signedFields({ signature: 'deadbeef' }))

  assert.equal(response.statusCode, 401)
  assert.equal(repo.roleMessages.length, 0)

  await app.close()
})

test('Role webhook rejects a stale timestamp', async () => {
  const repo = new MemoryIdentityRepository()
  const app = await buildApp(repo, appConfig)

  const timestamp = String(Math.floor(Date.now() / 1000) - 3600)
  const token = 'token-123'
  const signature = createHmac('sha256', signingKey).update(`${timestamp}${token}`).digest('hex')

  const response = await inject(app, signedFields({ timestamp, token, signature }))

  assert.equal(response.statusCode, 401)

  await app.close()
})

test('Role webhook rejects a payload without a body', async () => {
  const repo = new MemoryIdentityRepository()
  const app = await buildApp(repo, appConfig)

  const response = await inject(app, signedFields({ 'body-mime': '' }))

  assert.equal(response.statusCode, 400)

  await app.close()
})

test('Role webhook returns 503 when storage fails', async () => {
  const repo = new MemoryIdentityRepository()
  const app = await buildApp(repo, appConfig)
  repo.fail = true

  const response = await inject(app, signedFields())

  assert.equal(response.statusCode, 503)

  await app.close()
})

test('Role webhook route is not registered without a signing key', async () => {
  const repo = new MemoryIdentityRepository()
  const app = await buildApp(repo, { inboundDecisionToken: 'secret-token' })

  const response = await inject(app, signedFields())

  assert.equal(response.statusCode, 404)

  await app.close()
})
