import test from 'node:test'
import assert from 'node:assert/strict'
import { buildApp } from '../src/app.js'
import type { OutboundDecisionPayload } from '../src/types.js'
import { identity, MemoryIdentityRepository } from './helpers.js'

const SENDER = '0'.repeat(64)

const appConfig = {
  inboundDecisionToken: 'inbound-token',
  outboundDecisionToken: 'outbound-token',
}

function payload(overrides: Partial<OutboundDecisionPayload> = {}): OutboundDecisionPayload {
  return {
    protocol: 'nostr-smtp.decision.v1',
    mode: 'full',
    giftWrapId: 'wrap-1',
    nostrSender: SENDER,
    headers: [['From', 'alice@nmail.li']],
    ...overrides,
  }
}

function send(app: Awaited<ReturnType<typeof buildApp>>, body: OutboundDecisionPayload) {
  return app.inject({
    method: 'POST',
    url: '/outbound/decision',
    headers: { 'x-outbound-decision-token': 'outbound-token' },
    payload: body,
  })
}

async function withSender() {
  const repo = new MemoryIdentityRepository()
  repo.add(identity({ localPart: 'alice', pubkey: SENDER }))
  const app = await buildApp(repo, appConfig)
  return { repo, app }
}

test('Outbound policy denies messages with more recipients than the plan allows', async () => {
  const { app } = await withSender()

  const response = await send(app, payload({
    headers: [
      ['From', 'alice@nmail.li'],
      ['To', 'a@x.com, b@x.com, c@x.com'],
      ['Cc', 'd@x.com, e@x.com, f@x.com'],
    ],
  }))

  assert.equal(response.statusCode, 200)
  assert.equal(response.json().decision, 'deny')
  assert.equal(response.json().reason, 'too_many_recipients')

  await app.close()
})

test('Outbound policy allows recipient counts at the plan limit', async () => {
  const { app } = await withSender()

  const response = await send(app, payload({
    headers: [
      ['From', 'alice@nmail.li'],
      ['To', 'a@x.com, b@x.com, c@x.com, d@x.com, e@x.com'],
    ],
  }))

  assert.equal(response.statusCode, 200)
  assert.deepEqual(response.json(), { decision: 'allow' })

  await app.close()
})

test('Outbound policy denies messages larger than the plan size limit', async () => {
  const { app } = await withSender()

  const response = await send(app, payload({ rawMime: 'x'.repeat(10 * 1024 * 1024 + 1) }))

  assert.equal(response.statusCode, 200)
  assert.equal(response.json().decision, 'deny')
  assert.equal(response.json().reason, 'message_too_large')

  await app.close()
})

test('Outbound policy allows messages within the plan size limit', async () => {
  const { app } = await withSender()

  const response = await send(app, payload({ rawMime: 'x'.repeat(1024) }))

  assert.equal(response.statusCode, 200)
  assert.deepEqual(response.json(), { decision: 'allow' })

  await app.close()
})

test('Outbound policy enforces the per-minute rate limit of the default plan', async () => {
  const { app } = await withSender()

  for (let index = 0; index < 5; index += 1) {
    const allowed = await send(app, payload({ giftWrapId: 'wrap-' + index }))
    assert.deepEqual(allowed.json(), { decision: 'allow' }, 'send ' + index + ' should be allowed')
  }

  const blocked = await send(app, payload({ giftWrapId: 'wrap-over' }))
  assert.equal(blocked.json().decision, 'deny')
  assert.equal(blocked.json().reason, 'rate_limited')

  await app.close()
})

test('Outbound policy uses the plan assigned to the pubkey', async () => {
  const { repo, app } = await withSender()
  repo.setAccount(SENDER, { plan: 'premium' })

  // 10 recipients is over free (5) but within premium (10).
  const recipients = Array.from({ length: 10 }, (_, index) => 'r' + index + '@x.com').join(', ')
  const response = await send(app, payload({
    headers: [
      ['From', 'alice@nmail.li'],
      ['To', recipients],
    ],
  }))

  assert.equal(response.statusCode, 200)
  assert.deepEqual(response.json(), { decision: 'allow' })

  await app.close()
})

test('Outbound policy is idempotent for an already-recorded gift wrap', async () => {
  const { repo, app } = await withSender()

  for (let index = 0; index < 5; index += 1) {
    await send(app, payload({ giftWrapId: 'wrap-' + index }))
  }

  // The minute window is full, but re-asking about wrap-0 must still be allowed.
  const replay = await send(app, payload({ giftWrapId: 'wrap-0' }))
  assert.deepEqual(replay.json(), { decision: 'allow' })
  assert.equal(repo.sends.length, 5)

  await app.close()
})
