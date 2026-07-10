import test from 'node:test'
import assert from 'node:assert/strict'
import { nip19 } from 'nostr-tools'
import {
  createPushNotificationDispatcher,
  toFirebaseMessage,
  toPushPayload,
  type PushDeliveryProviders,
  type PushPayload,
} from '../src/pushNotificationDispatcher.js'
import type { InboundNotification, PushSubscription } from '../src/types.js'
import { MemoryIdentityRepository } from './helpers.js'

const recipient = '0'.repeat(64)

function notification(subscriptions: PushSubscription[]): InboundNotification {
  return {
    recipientPubkey: recipient,
    relays: ['wss://relay.example.net'],
    event: {
      id: 'a'.repeat(64),
      pubkey: 'b'.repeat(64),
      created_at: 1_789_999_999,
      kind: 1,
      tags: [['p', recipient]],
      content: 'The full public email body must not enter a push payload',
      sig: 'c'.repeat(128),
    },
    authenticatedPubkeys: ['d'.repeat(64)],
    email: {
      from: { address: 'alice@example.net', name: 'Alice' },
      subject: 'Hello',
      preview: 'Short plaintext preview',
    },
    subscriptions,
  }
}

function fcmSubscription(): PushSubscription {
  return {
    pubkey: recipient,
    transport: 'fcm',
    destination: 'fcm-token',
    language: 'en',
    p256dh: null,
    auth: null,
    instance: null,
  }
}

function unifiedPushSubscription(): PushSubscription {
  return {
    pubkey: recipient,
    transport: 'unifiedpush',
    destination: 'https://push.example/abc',
    language: 'en',
    p256dh: 'receiver-public-key',
    auth: 'receiver-auth-secret',
    instance: 'phone',
  }
}

test('dispatcher delivers compact payloads to FCM and UnifiedPush', async () => {
  const repo = new MemoryIdentityRepository()
  const fcmPayloads: PushPayload[] = []
  const webPushPayloads: string[] = []
  const providers: PushDeliveryProviders = {
    async sendFcm(_token, payload) {
      fcmPayloads.push(payload)
    },
    async sendWebPush(_subscription, payload) {
      webPushPayloads.push(payload)
    },
  }
  const dispatcher = createPushNotificationDispatcher(repo, {}, providers)

  await dispatcher.dispatch(notification([fcmSubscription(), unifiedPushSubscription()]))

  assert.equal(fcmPayloads.length, 1)
  assert.equal(webPushPayloads.length, 1)
  assert.deepEqual(JSON.parse(webPushPayloads[0]), fcmPayloads[0])
  assert.equal(fcmPayloads[0].title, 'New email from Alice')
  assert.equal(fcmPayloads[0].body, 'Hello')
  assert.ok(fcmPayloads[0].nevent)

  const decoded = nip19.decode(fcmPayloads[0].nevent)
  assert.equal(decoded.type, 'nevent')
  assert.deepEqual(decoded.data, {
    id: 'a'.repeat(64),
    relays: ['wss://relay.example.net'],
    author: 'b'.repeat(64),
    kind: 1,
  })

  const fcmMessage = toFirebaseMessage('fcm-token', fcmPayloads[0])
  assert.deepEqual(fcmMessage.notification, {
    title: 'New email from Alice',
    body: 'Hello',
  })
  assert.deepEqual(fcmMessage.data, { nevent: fcmPayloads[0].nevent })
})

test('dispatcher uses generic text and omits nevent when the event has no id', async () => {
  const repo = new MemoryIdentityRepository()
  const payloads: PushPayload[] = []
  const dispatcher = createPushNotificationDispatcher(repo, {}, {
    async sendFcm(_token, payload) {
      payloads.push(payload)
    },
    async sendWebPush() {},
  })
  const generic = notification([fcmSubscription()])
  generic.event = { created_at: Math.floor(Date.now() / 1000), tags: [] }
  generic.email = undefined

  await dispatcher.dispatch(generic)

  assert.deepEqual(payloads[0], {
    title: 'New message',
    body: 'You received a new message',
  })
})

test('dispatcher localizes generic notification text from the subscription language', () => {
  const generic = notification([])
  generic.event = { created_at: Math.floor(Date.now() / 1000), tags: [] }
  generic.email = undefined

  const expectedPayloads = new Map([
    ['de', { title: 'Neue Nachricht', body: 'Sie haben eine neue Nachricht erhalten' }],
    ['en', { title: 'New message', body: 'You received a new message' }],
    ['es', { title: 'Nuevo mensaje', body: 'Has recibido un nuevo mensaje' }],
    ['fi', { title: 'Uusi viesti', body: 'Sait uuden viestin' }],
    ['fr-FR', { title: 'Nouveau message', body: 'Vous avez reçu un nouveau message' }],
    ['it', { title: 'Nuovo messaggio', body: 'Hai ricevuto un nuovo messaggio' }],
    ['ja', { title: '新しいメッセージ', body: '新しいメッセージを受信しました' }],
    ['pt', { title: 'Nova mensagem', body: 'Recebeu uma nova mensagem' }],
    ['pt-BR', { title: 'Nova mensagem', body: 'Você recebeu uma nova mensagem' }],
    ['ru', { title: 'Новое сообщение', body: 'Вы получили новое сообщение' }],
    ['zh', { title: '新消息', body: '你收到了一条新消息' }],
    ['nl', { title: 'New message', body: 'You received a new message' }],
  ])

  for (const [language, expected] of expectedPayloads) {
    assert.deepEqual(toPushPayload(generic, language), expected)
  }
})

test('dispatcher localizes email notification fallback text', () => {
  const email = notification([])
  email.email = { from: { name: 'Alice', address: 'alice@example.net' } }

  assert.equal(toPushPayload(email, 'es').title, 'Nuevo correo de Alice')
  assert.equal(toPushPayload(email, 'es').body, 'Has recibido un nuevo correo')
  assert.equal(toPushPayload(email, 'de').title, 'Neue E-Mail von Alice')
  assert.equal(toPushPayload(email, 'de').body, 'Sie haben eine neue E-Mail erhalten')
  assert.equal(toPushPayload(email, 'ja').title, 'Aliceから新しいメール')
  assert.equal(toPushPayload(email, 'ja').body, '新しいメールを受信しました')
  assert.equal(toPushPayload(email, 'pt-BR').title, 'Novo e-mail de Alice')
  assert.equal(toPushPayload(email, 'pt-BR').body, 'Você recebeu um novo e-mail')
})

test('dispatcher removes permanently invalid FCM and UnifiedPush subscriptions', async () => {
  const repo = new MemoryIdentityRepository()
  const fcm = fcmSubscription()
  const unifiedPush = unifiedPushSubscription()
  await repo.upsertPushSubscription(fcm)
  await repo.upsertPushSubscription(unifiedPush)

  const dispatcher = createPushNotificationDispatcher(repo, {}, {
    async sendFcm() {
      throw Object.assign(new Error('unregistered'), { code: 'messaging/registration-token-not-registered' })
    },
    async sendWebPush() {
      throw Object.assign(new Error('gone'), { statusCode: 410 })
    },
  })

  await dispatcher.dispatch(notification([fcm, unifiedPush]))

  assert.equal(repo.pushSubscriptions.size, 0)
})

test('dispatcher delivers UnifiedPush payloads without encryption keys', async () => {
  const repo = new MemoryIdentityRepository()
  const subscription = { ...unifiedPushSubscription(), p256dh: null, auth: null }
  await repo.upsertPushSubscription(subscription)
  const payloads: string[] = []
  const dispatcher = createPushNotificationDispatcher(repo, {}, {
    async sendFcm() {},
    async sendWebPush(_subscription, payload) {
      payloads.push(payload)
    },
  })

  await dispatcher.dispatch(notification([subscription]))

  assert.equal(payloads.length, 1)
  assert.equal(repo.pushSubscriptions.size, 1)
})

test('dispatcher reports temporary delivery errors and retains the subscription', async () => {
  const repo = new MemoryIdentityRepository()
  const subscription = fcmSubscription()
  await repo.upsertPushSubscription(subscription)
  const dispatcher = createPushNotificationDispatcher(repo, {}, {
    async sendFcm() {
      throw Object.assign(new Error('unavailable'), { code: 'messaging/server-unavailable' })
    },
    async sendWebPush() {},
  })

  await assert.rejects(() => dispatcher.dispatch(notification([subscription])), /could not be delivered/)
  assert.equal(repo.pushSubscriptions.size, 1)
})

test('dispatcher rejects payloads that exceed push transport limits', async () => {
  const repo = new MemoryIdentityRepository()
  let attempted = false
  const dispatcher = createPushNotificationDispatcher(repo, {}, {
    async sendFcm() {
      attempted = true
    },
    async sendWebPush() {},
  })
  const oversized = notification([fcmSubscription()])
  oversized.relays = Array.from({ length: 3 }, (_, index) => `wss://relay${index}.example/${'x'.repeat(800)}`)

  await assert.rejects(() => dispatcher.dispatch(oversized), /exceeds the transport limit/)
  assert.equal(attempted, false)
})
