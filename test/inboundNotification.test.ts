import test from 'node:test'
import assert from 'node:assert/strict'
import { buildApp } from '../src/app.js'
import type { InboundNotification, PushNotificationDispatcher } from '../src/types.js'
import { MemoryIdentityRepository } from './helpers.js'

const appConfig = {
  inboundDecisionToken: 'secret-token',
  inboundNotificationToken: 'notify-token',
}

const recipient = '0'.repeat(64)
const otherRecipient = '1'.repeat(64)
const relayPubkey = '2'.repeat(64)
const relays = ['wss://relay.example.net']

function captureDispatcher(deliveries: InboundNotification[]): PushNotificationDispatcher {
  return {
    async dispatch(notification) {
      deliveries.push(notification)
    },
  }
}

async function post(
  app: Awaited<ReturnType<typeof buildApp>>,
  payload: unknown,
  authorization = 'Bearer notify-token',
) {
  const body = typeof payload === 'string' ? payload : JSON.stringify(payload)

  return app.inject({
    method: 'POST',
    url: '/inbound/notifications',
    headers: {
      'content-type': 'application/json',
      ...(authorization ? { authorization } : {}),
    },
    payload: body,
  })
}

test('POST accepts an email notification and dispatches matching push subscriptions', async () => {
  const repo = new MemoryIdentityRepository()
  await repo.upsertPushSubscription({ pubkey: recipient, transport: 'fcm', destination: 'fcm-token' })
  await repo.upsertPushSubscription({ pubkey: otherRecipient, transport: 'fcm', destination: 'other-token' })
  const deliveries: InboundNotification[] = []
  const app = await buildApp(repo, appConfig, captureDispatcher(deliveries))

  const response = await post(app, {
    recipientPubkey: recipient.toUpperCase(),
    relays,
    event: {
      id: 'a'.repeat(64),
      pubkey: 'b'.repeat(64),
      created_at: 1_789_999_999,
      kind: 1,
      tags: [['p', recipient]],
      content: 'Public email body',
      sig: 'c'.repeat(128),
    },
    email: {
      from: { address: 'alice@example.net', name: 'Alice' },
      subject: 'Hello',
      preview: 'Short plaintext preview',
    },
  })

  assert.equal(response.statusCode, 202)
  assert.deepEqual(response.json(), { status: 'accepted' })
  assert.equal(deliveries.length, 1)
  assert.equal(deliveries[0].recipientPubkey, recipient)
  assert.deepEqual(deliveries[0].relays, relays)
  assert.equal(deliveries[0].event.content, 'Public email body')
  assert.equal(deliveries[0].event.sig, 'c'.repeat(128))
  assert.deepEqual(deliveries[0].subscriptions, [
    {
      pubkey: recipient,
      transport: 'fcm',
      destination: 'fcm-token',
      p256dh: null,
      auth: null,
      instance: null,
    },
  ])
  assert.deepEqual(deliveries[0].email, {
    from: { address: 'alice@example.net', name: 'Alice' },
    subject: 'Hello',
    preview: 'Short plaintext preview',
  })

  await app.close()
})

test('POST accepts a generic gift wrap notification with authenticated pubkeys', async () => {
  const repo = new MemoryIdentityRepository()
  await repo.upsertPushSubscription({
    pubkey: recipient,
    transport: 'unifiedpush',
    destination: 'https://push.example/abc',
    p256dh: 'key',
    auth: 'auth-secret',
    instance: 'phone',
  })
  const deliveries: InboundNotification[] = []
  const app = await buildApp(repo, appConfig, captureDispatcher(deliveries))

  const response = await post(app, {
    recipientPubkey: recipient,
    relays: [...relays, ...relays],
    event: { tags: [['p', otherRecipient]] },
    authenticatedPubkeys: [relayPubkey.toUpperCase(), relayPubkey],
  })

  assert.equal(response.statusCode, 202)
  assert.equal(deliveries[0].recipientPubkey, recipient)
  assert.deepEqual(deliveries[0].relays, relays)
  assert.deepEqual(deliveries[0].authenticatedPubkeys, [relayPubkey])
  assert.equal(deliveries[0].subscriptions[0].transport, 'unifiedpush')
  assert.equal(deliveries[0].email, undefined)

  await app.close()
})

test('POST uses INBOUND_NOTIFICATION_TOKEN only', async () => {
  const repo = new MemoryIdentityRepository()
  const app = await buildApp(repo, appConfig)
  const payload = { recipientPubkey: recipient, relays, event: {}, authenticatedPubkeys: [] }

  const decisionToken = await post(app, payload, 'Bearer secret-token')
  assert.equal(decisionToken.statusCode, 401)

  const notificationToken = await post(app, payload, 'Bearer notify-token')
  assert.equal(notificationToken.statusCode, 202)

  await app.close()
})

test('POST rejects every bearer when INBOUND_NOTIFICATION_TOKEN is not configured', async () => {
  const repo = new MemoryIdentityRepository()
  const app = await buildApp(repo, { inboundDecisionToken: 'secret-token' })
  const payload = { recipientPubkey: recipient, relays, event: {} }

  const response = await post(app, payload, 'Bearer secret-token')

  assert.equal(response.statusCode, 401)
  assert.equal(response.json().error, 'unauthorized')

  await app.close()
})

test('POST rejects missing or invalid bearer authentication', async () => {
  const repo = new MemoryIdentityRepository()
  const app = await buildApp(repo, appConfig)
  const payload = { recipientPubkey: recipient, relays, event: {} }

  const missing = await post(app, payload, '')
  assert.equal(missing.statusCode, 401)
  assert.equal(missing.json().error, 'unauthorized')

  const wrongScheme = await post(app, payload, 'Nostr token')
  assert.equal(wrongScheme.statusCode, 401)

  const wrongToken = await post(app, payload, 'Bearer wrong')
  assert.equal(wrongToken.statusCode, 401)

  await app.close()
})

test('POST rejects invalid notification payloads', async () => {
  const repo = new MemoryIdentityRepository()
  const app = await buildApp(repo, appConfig)

  for (const body of [
    {},
    { recipientPubkey: 'not-a-pubkey', relays, event: {} },
    { recipientPubkey: recipient, event: {} },
    { recipientPubkey: recipient, relays: ['https://relay.example.net'], event: {} },
    { recipientPubkey: recipient, relays, event: { content: 'encrypted' } },
    { recipientPubkey: recipient, relays, event: { sig: 'a'.repeat(128) } },
    { recipientPubkey: recipient, relays, event: {}, email: { rawMime: 'message' } },
    { recipientPubkey: recipient, relays, event: {}, email: { subject: 'Missing public event body' } },
    { recipientPubkey: recipient, relays, event: {}, authenticatedPubkeys: ['bad'] },
    { giftWrap: { tags: [['p', recipient]] } },
  ]) {
    const response = await post(app, body)
    assert.equal(response.statusCode, 400)
    assert.equal(response.json().error, 'invalid_notification_payload')
  }

  await app.close()
})

test('POST returns 503 when push subscription lookup or dispatch fails', async () => {
  const repo = new MemoryIdentityRepository()
  repo.fail = true
  const app = await buildApp(repo, appConfig)

  const response = await post(app, { recipientPubkey: recipient, relays, event: {} })

  assert.equal(response.statusCode, 503)
  assert.equal(response.json().error, 'notification_unavailable')

  await app.close()
})
