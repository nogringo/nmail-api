import test from 'node:test'
import assert from 'node:assert/strict'
import { buildApp } from '../src/app.js'
import type { OutboundDecisionPayload } from '../src/types.js'
import { identity, MemoryIdentityRepository } from './helpers.js'

const SENDER = '0'.repeat(64)

const basePayload: OutboundDecisionPayload = {
  protocol: 'nostr-smtp.decision.v1',
  mode: 'minimal',
  giftWrapId: 'wrap-1',
  nostrSender: SENDER,
  rumor: { tags: [['mail-from', 'alice@nmail.li'], ['rcpt-to', 'bob@example.com']] },
  headers: [['From', 'alice@nmail.li']],
}

const appConfig = {
  inboundDecisionToken: 'inbound-token',
  outboundDecisionToken: 'outbound-token',
}

const deniedSender = {
  decision: 'deny',
  reason: 'unauthorized_sender',
  message: 'Sender is not authorized to send mail from this address',
}

test('Outbound decision allows the pubkey that owns a mail-enabled From identity', async () => {
  const repo = new MemoryIdentityRepository()
  repo.add(identity({ localPart: 'alice', pubkey: SENDER }))
  const app = await buildApp(repo, appConfig)

  const response = await app.inject({
    method: 'POST',
    url: '/outbound/decision',
    headers: { 'x-outbound-decision-token': 'outbound-token' },
    payload: basePayload,
  })

  assert.equal(response.statusCode, 200)
  assert.deepEqual(response.json(), { decision: 'allow' })

  await app.close()
})

test('Outbound decision resolves npub From local parts', async () => {
  const repo = new MemoryIdentityRepository()
  repo.add(identity({ localPart: 'alice', pubkey: SENDER }))
  const app = await buildApp(repo, appConfig)
  const address = 'npub1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqzqujme@nmail.li'

  const response = await app.inject({
    method: 'POST',
    url: '/outbound/decision',
    headers: { 'x-outbound-decision-token': 'outbound-token' },
    payload: {
      ...basePayload,
      rumor: { tags: [['mail-from', address], ['rcpt-to', 'bob@example.com']] },
      headers: [['From', `Alice <${address}>`]],
    },
  })

  assert.equal(response.statusCode, 200)
  assert.deepEqual(response.json(), { decision: 'allow' })

  await app.close()
})

test('Outbound decision matches mail-from to the From address case-insensitively', async () => {
  const repo = new MemoryIdentityRepository()
  repo.add(identity({ localPart: 'alice', pubkey: SENDER }))
  const app = await buildApp(repo, appConfig)

  const response = await app.inject({
    method: 'POST',
    url: '/outbound/decision',
    headers: { 'x-outbound-decision-token': 'outbound-token' },
    payload: {
      ...basePayload,
      rumor: { tags: [['mail-from', 'Alice@NMail.li'], ['rcpt-to', 'bob@example.com']] },
      headers: [['From', 'Alice <Alice@NMail.li>']],
    },
  })

  assert.equal(response.statusCode, 200)
  assert.deepEqual(response.json(), { decision: 'allow' })

  await app.close()
})

test('Outbound decision denies a mail-from other than the From address', async () => {
  const repo = new MemoryIdentityRepository()
  repo.add(identity({ localPart: 'alice', pubkey: SENDER }))
  repo.add(identity({ localPart: 'bob', pubkey: '1'.repeat(64) }))
  const app = await buildApp(repo, appConfig)

  const forgedEnvelopes = [
    [['mail-from', 'victim@example.com']],
    [['mail-from', 'bob@nmail.li']],
    [['mail-from', 'alice@nmail.li'], ['mail-from', 'victim@example.com']],
    [['mail-from', 'Alice <alice@nmail.li>']],
    [],
  ]

  for (const mailFrom of forgedEnvelopes) {
    const response = await app.inject({
      method: 'POST',
      url: '/outbound/decision',
      headers: { 'x-outbound-decision-token': 'outbound-token' },
      payload: { ...basePayload, rumor: { tags: [...mailFrom, ['rcpt-to', 'bob@example.com']] } },
    })

    assert.equal(response.statusCode, 200)
    assert.deepEqual(response.json(), deniedSender, JSON.stringify(mailFrom))
  }

  await app.close()
})

test('Outbound decision denies payloads without a rumor', async () => {
  const repo = new MemoryIdentityRepository()
  repo.add(identity({ localPart: 'alice', pubkey: SENDER }))
  const app = await buildApp(repo, appConfig)

  const response = await app.inject({
    method: 'POST',
    url: '/outbound/decision',
    headers: { 'x-outbound-decision-token': 'outbound-token' },
    payload: { ...basePayload, rumor: undefined },
  })

  assert.equal(response.statusCode, 200)
  assert.deepEqual(response.json(), deniedSender)

  await app.close()
})

test('Outbound decision denies a From domain that is not protected', async () => {
  const repo = new MemoryIdentityRepository()
  repo.add(identity({ localPart: 'alice', pubkey: SENDER }))
  const app = await buildApp(repo, appConfig)

  const response = await app.inject({
    method: 'POST',
    url: '/outbound/decision',
    headers: { 'x-outbound-decision-token': 'outbound-token' },
    payload: { ...basePayload, headers: [['From', 'alice@example.com']] },
  })

  assert.equal(response.statusCode, 200)
  assert.deepEqual(response.json(), deniedSender)

  await app.close()
})

test('Outbound decision denies when the sender pubkey does not own the From address', async () => {
  const repo = new MemoryIdentityRepository()
  repo.add(identity({ localPart: 'alice', pubkey: '1'.repeat(64) }))
  const app = await buildApp(repo, appConfig)

  const response = await app.inject({
    method: 'POST',
    url: '/outbound/decision',
    headers: { 'x-outbound-decision-token': 'outbound-token' },
    payload: basePayload,
  })

  assert.equal(response.statusCode, 200)
  assert.deepEqual(response.json(), deniedSender)

  await app.close()
})

test('Outbound decision denies when the account has mail disabled', async () => {
  const repo = new MemoryIdentityRepository()
  repo.add(identity({ localPart: 'alice', pubkey: SENDER }))
  repo.setAccount(SENDER, { mailEnabled: false })
  const app = await buildApp(repo, appConfig)

  const response = await app.inject({
    method: 'POST',
    url: '/outbound/decision',
    headers: { 'x-outbound-decision-token': 'outbound-token' },
    payload: basePayload,
  })

  assert.equal(response.statusCode, 200)
  assert.equal(response.json().decision, 'deny')
  assert.equal(response.json().reason, 'account_disabled')

  await app.close()
})

test('Outbound decision denies when the From header is missing', async () => {
  const repo = new MemoryIdentityRepository()
  repo.add(identity({ localPart: 'alice', pubkey: SENDER }))
  const app = await buildApp(repo, appConfig)

  const response = await app.inject({
    method: 'POST',
    url: '/outbound/decision',
    headers: { 'x-outbound-decision-token': 'outbound-token' },
    payload: { ...basePayload, headers: [] },
  })

  assert.equal(response.statusCode, 200)
  assert.deepEqual(response.json(), deniedSender)

  await app.close()
})

test('Outbound decision denies a From that is not exactly one address', async () => {
  const repo = new MemoryIdentityRepository()
  repo.add(identity({ localPart: 'alice', pubkey: SENDER }))
  const app = await buildApp(repo, appConfig)

  const forgedHeaders: Array<Array<[string, string]>> = [
    [['From', 'alice@nmail.li'], ['From', 'ceo@bank.com']],
    [['From', '<alice@nmail.li>, <ceo@bank.com>']],
    [['From', 'ceo@bank.com, <alice@nmail.li>']],
    [['From', '"<alice@nmail.li>" <ceo@bank.com>']],
  ]

  for (const headers of forgedHeaders) {
    const response = await app.inject({
      method: 'POST',
      url: '/outbound/decision',
      headers: { 'x-outbound-decision-token': 'outbound-token' },
      payload: { ...basePayload, headers },
    })

    assert.equal(response.statusCode, 200)
    assert.deepEqual(response.json(), deniedSender, JSON.stringify(headers))
  }

  await app.close()
})

test('Outbound decision rejects payloads without a nostr sender', async () => {
  const repo = new MemoryIdentityRepository()
  const app = await buildApp(repo, appConfig)

  const response = await app.inject({
    method: 'POST',
    url: '/outbound/decision',
    headers: { 'x-outbound-decision-token': 'outbound-token' },
    payload: { ...basePayload, nostrSender: undefined },
  })

  assert.equal(response.statusCode, 400)
  assert.deepEqual(response.json(), { error: 'invalid decision payload' })

  await app.close()
})

test('Outbound decision returns non-200 when identity lookup fails', async () => {
  const repo = new MemoryIdentityRepository()
  repo.add(identity({ localPart: 'alice', pubkey: SENDER }))
  repo.fail = true
  const app = await buildApp(repo, appConfig)

  const response = await app.inject({
    method: 'POST',
    url: '/outbound/decision',
    headers: { 'x-outbound-decision-token': 'outbound-token' },
    payload: basePayload,
  })

  assert.equal(response.statusCode, 503)
  assert.deepEqual(response.json(), { error: 'policy_unavailable' })

  await app.close()
})

test('Outbound decision rejects missing or invalid tokens', async () => {
  const repo = new MemoryIdentityRepository()
  repo.add(identity({ localPart: 'alice', pubkey: SENDER }))
  const app = await buildApp(repo, appConfig)

  const missing = await app.inject({ method: 'POST', url: '/outbound/decision', payload: basePayload })
  const invalid = await app.inject({
    method: 'POST',
    url: '/outbound/decision',
    headers: { 'x-outbound-decision-token': 'wrong-token' },
    payload: basePayload,
  })

  assert.equal(missing.statusCode, 401)
  assert.deepEqual(missing.json(), { error: 'unauthorized' })
  assert.equal(invalid.statusCode, 401)
  assert.deepEqual(invalid.json(), { error: 'unauthorized' })

  await app.close()
})

test('Outbound decision accepts bearer tokens', async () => {
  const repo = new MemoryIdentityRepository()
  repo.add(identity({ localPart: 'alice', pubkey: SENDER }))
  const app = await buildApp(repo, appConfig)

  const response = await app.inject({
    method: 'POST',
    url: '/outbound/decision',
    headers: { authorization: 'Bearer outbound-token' },
    payload: basePayload,
  })

  assert.equal(response.statusCode, 200)
  assert.deepEqual(response.json(), { decision: 'allow' })

  await app.close()
})

test('Outbound decision route is not registered without an outbound token', async () => {
  const repo = new MemoryIdentityRepository()
  const app = await buildApp(repo, { ...appConfig, outboundDecisionToken: undefined })

  const response = await app.inject({
    method: 'POST',
    url: '/outbound/decision',
    headers: { 'x-outbound-decision-token': 'outbound-token' },
    payload: basePayload,
  })

  assert.equal(response.statusCode, 404)

  await app.close()
})
