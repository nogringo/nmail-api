import test from 'node:test'
import assert from 'node:assert/strict'
import { buildApp } from '../src/app.js'
import type { InboundDecisionPayload } from '../src/types.js'
import { identity, MemoryIdentityRepository } from './helpers.js'

const basePayload: InboundDecisionPayload = {
  protocol: 'inbound-mail.decision.v1',
  mode: 'minimal',
  message: {
    id: 'msg-1',
    createdAt: '2026-06-16T10:00:00.000Z',
    sender: 'sender@example.com',
    recipients: ['alice@nmail.li'],
  },
}

const appConfig = {
  protectedEmailDomains: new Set(['nmail.li']),
  inboundDecisionToken: 'secret-token',
}

test('Inbound decision allows unprotected domains', async () => {
  const repo = new MemoryIdentityRepository()
  const app = await buildApp(repo, appConfig)

  const response = await app.inject({
    method: 'POST',
    url: '/inbound/decision',
    headers: { 'x-inbound-decision-token': 'secret-token' },
    payload: {
      ...basePayload,
      message: { ...basePayload.message, recipients: ['unknown@example.com'] },
    },
  })

  assert.equal(response.statusCode, 200)
  assert.deepEqual(response.json(), { decision: 'allow' })

  await app.close()
})

test('Inbound decision allows active identities on protected domains', async () => {
  const repo = new MemoryIdentityRepository()
  repo.add(identity())
  const app = await buildApp(repo, appConfig)

  const response = await app.inject({
    method: 'POST',
    url: '/inbound/decision',
    headers: { 'x-inbound-decision-token': 'secret-token' },
    payload: basePayload,
  })

  assert.equal(response.statusCode, 200)
  assert.deepEqual(response.json(), { decision: 'allow' })

  await app.close()
})

test('Inbound decision allows private mail-enabled identities on protected domains', async () => {
  const repo = new MemoryIdentityRepository()
  repo.add(identity({ visibility: 'private' }))
  const app = await buildApp(repo, appConfig)

  const response = await app.inject({
    method: 'POST',
    url: '/inbound/decision',
    headers: { 'x-inbound-decision-token': 'secret-token' },
    payload: basePayload,
  })

  assert.equal(response.statusCode, 200)
  assert.deepEqual(response.json(), { decision: 'allow' })

  await app.close()
})

test('Inbound decision denies identities with inbound mail disabled', async () => {
  const repo = new MemoryIdentityRepository()
  repo.add(identity({ mailEnabled: false }))
  const app = await buildApp(repo, appConfig)

  const response = await app.inject({
    method: 'POST',
    url: '/inbound/decision',
    headers: { 'x-inbound-decision-token': 'secret-token' },
    payload: basePayload,
  })

  assert.equal(response.statusCode, 200)
  assert.deepEqual(response.json(), {
    decision: 'deny',
    reason: 'unknown_recipient',
    message: 'Recipient is not configured for inbound mail delivery',
  })

  await app.close()
})

test('Inbound decision denies unknown protected recipients', async () => {
  const repo = new MemoryIdentityRepository()
  const app = await buildApp(repo, appConfig)

  const response = await app.inject({
    method: 'POST',
    url: '/inbound/decision',
    headers: { 'x-inbound-decision-token': 'secret-token' },
    payload: basePayload,
  })

  assert.equal(response.statusCode, 200)
  assert.deepEqual(response.json(), {
    decision: 'deny',
    reason: 'unknown_recipient',
    message: 'Recipient is not configured for inbound mail delivery',
  })

  await app.close()
})

test('Inbound decision denies when any protected recipient is unknown', async () => {
  const repo = new MemoryIdentityRepository()
  repo.add(identity())
  const app = await buildApp(repo, appConfig)

  const response = await app.inject({
    method: 'POST',
    url: '/inbound/decision',
    headers: { 'x-inbound-decision-token': 'secret-token' },
    payload: {
      ...basePayload,
      message: { ...basePayload.message, recipients: ['alice@nmail.li', 'bob@nmail.li', 'carol@example.com'] },
    },
  })

  assert.equal(response.statusCode, 200)
  assert.deepEqual(response.json(), {
    decision: 'deny',
    reason: 'unknown_recipient',
    message: 'Recipient is not configured for inbound mail delivery',
  })

  await app.close()
})

test('Inbound decision returns non-200 when identity lookup fails', async () => {
  const repo = new MemoryIdentityRepository()
  repo.fail = true
  const app = await buildApp(repo, appConfig)

  const response = await app.inject({
    method: 'POST',
    url: '/inbound/decision',
    headers: { 'x-inbound-decision-token': 'secret-token' },
    payload: basePayload,
  })

  assert.equal(response.statusCode, 503)
  assert.deepEqual(response.json(), { error: 'policy_unavailable' })

  await app.close()
})

test('Inbound decision rejects missing or invalid tokens', async () => {
  const repo = new MemoryIdentityRepository()
  const app = await buildApp(repo, appConfig)

  const missing = await app.inject({
    method: 'POST',
    url: '/inbound/decision',
    payload: basePayload,
  })
  const invalid = await app.inject({
    method: 'POST',
    url: '/inbound/decision',
    headers: { 'x-inbound-decision-token': 'wrong-token' },
    payload: basePayload,
  })

  assert.equal(missing.statusCode, 401)
  assert.deepEqual(missing.json(), { error: 'unauthorized' })
  assert.equal(invalid.statusCode, 401)
  assert.deepEqual(invalid.json(), { error: 'unauthorized' })

  await app.close()
})

test('Inbound decision accepts bearer and query-string tokens', async () => {
  const repo = new MemoryIdentityRepository()
  const app = await buildApp(repo, appConfig)

  const bearer = await app.inject({
    method: 'POST',
    url: '/inbound/decision',
    headers: { authorization: 'Bearer secret-token' },
    payload: { ...basePayload, message: { ...basePayload.message, recipients: ['unknown@example.com'] } },
  })
  const queryString = await app.inject({
    method: 'POST',
    url: '/inbound/decision?token=secret-token',
    payload: { ...basePayload, message: { ...basePayload.message, recipients: ['unknown@example.com'] } },
  })

  assert.equal(bearer.statusCode, 200)
  assert.deepEqual(bearer.json(), { decision: 'allow' })
  assert.equal(queryString.statusCode, 200)
  assert.deepEqual(queryString.json(), { decision: 'allow' })

  await app.close()
})
