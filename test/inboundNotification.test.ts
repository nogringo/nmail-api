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

function freshCreatedAt(): number {
  return Math.floor(Date.now() / 1000)
}

function nostrEvent(overrides: Record<string, unknown> = {}) {
  return { created_at: freshCreatedAt(), tags: [], ...overrides }
}

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
      created_at: freshCreatedAt(),
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
      language: 'en',
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

test('POST deduplicates inbound notifications by recipient and event id', async () => {
  const repo = new MemoryIdentityRepository()
  await repo.upsertPushSubscription({ pubkey: recipient, transport: 'fcm', destination: 'fcm-token' })
  const deliveries: InboundNotification[] = []
  const app = await buildApp(repo, appConfig, captureDispatcher(deliveries))
  const payload = {
    recipientPubkey: recipient,
    relays,
    event: nostrEvent({ id: 'a'.repeat(64), tags: [['p', recipient]] }),
    authenticatedPubkeys: [],
  }

  const first = await post(app, payload)
  const duplicate = await post(app, payload)

  assert.equal(first.statusCode, 202)
  assert.equal(duplicate.statusCode, 202)
  assert.equal(deliveries.length, 1)
  assert.equal(deliveries[0].event.id, 'a'.repeat(64))

  await app.close()
})

test('POST deduplication is scoped to the recipient pubkey', async () => {
  const repo = new MemoryIdentityRepository()
  await repo.upsertPushSubscription({ pubkey: recipient, transport: 'fcm', destination: 'fcm-token' })
  await repo.upsertPushSubscription({ pubkey: otherRecipient, transport: 'fcm', destination: 'other-token' })
  const deliveries: InboundNotification[] = []
  const app = await buildApp(repo, appConfig, captureDispatcher(deliveries))
  const event = nostrEvent({ id: 'a'.repeat(64) })

  const first = await post(app, { recipientPubkey: recipient, relays, event })
  const second = await post(app, { recipientPubkey: otherRecipient, relays, event })

  assert.equal(first.statusCode, 202)
  assert.equal(second.statusCode, 202)
  assert.equal(deliveries.length, 2)
  assert.deepEqual(
    deliveries.map((delivery) => delivery.recipientPubkey),
    [recipient, otherRecipient],
  )

  await app.close()
})

test('POST releases the deduplication claim when dispatch fails so upstream retries can send', async () => {
  const repo = new MemoryIdentityRepository()
  await repo.upsertPushSubscription({ pubkey: recipient, transport: 'fcm', destination: 'fcm-token' })
  const deliveries: InboundNotification[] = []
  let attempts = 0
  const app = await buildApp(repo, appConfig, {
    async dispatch(notification) {
      attempts += 1
      if (attempts === 1) throw new Error('temporary push outage')
      deliveries.push(notification)
    },
  })
  const payload = {
    recipientPubkey: recipient,
    relays,
    event: nostrEvent({ id: 'a'.repeat(64), tags: [['p', recipient]] }),
  }

  const failed = await post(app, payload)
  const retried = await post(app, payload)

  assert.equal(failed.statusCode, 503)
  assert.equal(retried.statusCode, 202)
  assert.equal(attempts, 2)
  assert.equal(deliveries.length, 1)

  await app.close()
})

test('POST skips stale or future notification events without claiming delivery', async () => {
  const repo = new MemoryIdentityRepository()
  await repo.upsertPushSubscription({ pubkey: recipient, transport: 'fcm', destination: 'fcm-token' })
  const deliveries: InboundNotification[] = []
  const app = await buildApp(repo, appConfig, captureDispatcher(deliveries))
  const now = freshCreatedAt()
  const stale = {
    recipientPubkey: recipient,
    relays,
    event: nostrEvent({ id: 'a'.repeat(64), created_at: now - 8 * 24 * 60 * 60 }),
  }
  const future = {
    recipientPubkey: recipient,
    relays,
    event: nostrEvent({ id: 'b'.repeat(64), created_at: now + 24 * 60 * 60 }),
  }

  const staleResponse = await post(app, stale)
  const futureResponse = await post(app, future)

  assert.equal(staleResponse.statusCode, 202)
  assert.equal(futureResponse.statusCode, 202)
  assert.equal(deliveries.length, 0)
  assert.equal(repo.inboundNotificationDeliveries.size, 0)

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
    event: nostrEvent({ tags: [['p', otherRecipient]] }),
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
  const payload = { recipientPubkey: recipient, relays, event: nostrEvent(), authenticatedPubkeys: [] }

  const decisionToken = await post(app, payload, 'Bearer secret-token')
  assert.equal(decisionToken.statusCode, 401)

  const notificationToken = await post(app, payload, 'Bearer notify-token')
  assert.equal(notificationToken.statusCode, 202)

  await app.close()
})

test('POST rejects every bearer when INBOUND_NOTIFICATION_TOKEN is not configured', async () => {
  const repo = new MemoryIdentityRepository()
  const app = await buildApp(repo, { inboundDecisionToken: 'secret-token' })
  const payload = { recipientPubkey: recipient, relays, event: nostrEvent() }

  const response = await post(app, payload, 'Bearer secret-token')

  assert.equal(response.statusCode, 401)
  assert.equal(response.json().error, 'unauthorized')

  await app.close()
})

test('POST rejects missing or invalid bearer authentication', async () => {
  const repo = new MemoryIdentityRepository()
  const app = await buildApp(repo, appConfig)
  const payload = { recipientPubkey: recipient, relays, event: nostrEvent() }

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
    { recipientPubkey: recipient, relays: ['https://relay.example.net'], event: nostrEvent() },
    { recipientPubkey: recipient, relays, event: {} },
    { recipientPubkey: recipient, relays, event: nostrEvent({ content: 'encrypted' }) },
    { recipientPubkey: recipient, relays, event: nostrEvent({ sig: 'a'.repeat(128) }) },
    { recipientPubkey: recipient, relays, event: {}, email: { rawMime: 'message' } },
    { recipientPubkey: recipient, relays, event: {}, email: { subject: 'Missing public event body' } },
    { recipientPubkey: recipient, relays, event: nostrEvent(), authenticatedPubkeys: ['bad'] },
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

  const response = await post(app, { recipientPubkey: recipient, relays, event: nostrEvent() })

  assert.equal(response.statusCode, 503)
  assert.equal(response.json().error, 'notification_unavailable')

  await app.close()
})
