import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import { buildApp } from '../src/app.js'
import { NIP98_KIND } from '../src/nip98.js'
import { MemoryIdentityRepository } from './helpers.js'

const domain = 'nmail.li'
const path = '/push/subscriptions'
const appConfig = { inboundDecisionToken: 'secret-token' }

interface TokenOptions {
  sk?: Uint8Array
  method?: string
  path?: string
  host?: string
  body?: string
  payloadHash?: string
  includePayload?: boolean
}

function authToken(options: TokenOptions = {}) {
  const sk = options.sk ?? generateSecretKey()
  const requestPath = options.path ?? path
  const url = `https://${options.host ?? domain}${requestPath}`
  const tags = [
    ['u', url],
    ['method', options.method ?? 'POST'],
  ]

  if (options.includePayload !== false) {
    tags.push(['payload', options.payloadHash ?? sha256Hex(options.body ?? '')])
  }

  const event = finalizeEvent(
    {
      kind: NIP98_KIND,
      created_at: Math.floor(Date.now() / 1000),
      tags,
      content: '',
    },
    sk,
  )

  return { token: `Nostr ${Buffer.from(JSON.stringify(event)).toString('base64')}`, sk, pubkey: getPublicKey(sk) }
}

async function buildPushApp() {
  const repo = new MemoryIdentityRepository()
  const app = await buildApp(repo, appConfig)
  return { repo, app }
}

async function post(
  app: Awaited<ReturnType<typeof buildApp>>,
  bodyValue: unknown,
  options: TokenOptions & { authorization?: string | null } = {},
) {
  const body = typeof bodyValue === 'string' ? bodyValue : JSON.stringify(bodyValue)
  const authorization = options.authorization === undefined ? authToken({ ...options, body }).token : options.authorization

  return app.inject({
    method: 'POST',
    url: path,
    headers: {
      host: domain,
      'content-type': 'application/json',
      ...(authorization ? { authorization } : {}),
    },
    payload: body,
  })
}

test('POST registers an FCM subscription for the signing pubkey', async () => {
  const { repo, app } = await buildPushApp()

  const result = await post(app, { action: 'register', transport: { type: 'fcm', token: 'token-1' } })

  assert.equal(result.statusCode, 204)
  const subscription = [...repo.pushSubscriptions.values()][0]
  assert.equal(subscription.transport, 'fcm')
  assert.equal(subscription.destination, 'token-1')
  assert.ok(await repo.getAccount(subscription.pubkey), 'account is created')

  await app.close()
})

test('POST registers a UnifiedPush subscription with optional fields', async () => {
  const { repo, app } = await buildPushApp()

  const result = await post(app, {
    action: 'register',
    transport: {
      type: 'unifiedpush',
      endpoint: 'https://push.example/abc',
      p256dh: 'key',
      auth: 'auth-secret',
      instance: 'nmail',
    },
  })

  assert.equal(result.statusCode, 204)
  assert.deepEqual([...repo.pushSubscriptions.values()][0], {
    pubkey: [...repo.pushSubscriptions.values()][0].pubkey,
    transport: 'unifiedpush',
    destination: 'https://push.example/abc',
    p256dh: 'key',
    auth: 'auth-secret',
    instance: 'nmail',
  })

  await app.close()
})

test('POST updates an existing push subscription destination', async () => {
  const { repo, app } = await buildPushApp()
  const sk = generateSecretKey()

  const first = await post(
    app,
    {
      action: 'register',
      transport: { type: 'unifiedpush', endpoint: 'https://push.example/abc', p256dh: 'old', auth: 'old-auth' },
    },
    { sk },
  )
  assert.equal(first.statusCode, 204)

  const second = await post(
    app,
    {
      action: 'register',
      transport: { type: 'unifiedpush', endpoint: 'https://push.example/abc', p256dh: 'new', auth: 'new-auth', instance: 'phone' },
    },
    { sk },
  )

  assert.equal(second.statusCode, 204)
  assert.equal(repo.pushSubscriptions.size, 1)
  const subscription = [...repo.pushSubscriptions.values()][0]
  assert.equal(subscription.p256dh, 'new')
  assert.equal(subscription.auth, 'new-auth')
  assert.equal(subscription.instance, 'phone')

  await app.close()
})

test('POST disables a push subscription idempotently', async () => {
  const { repo, app } = await buildPushApp()
  const sk = generateSecretKey()
  const body = { action: 'register', transport: { type: 'fcm', token: 'token-1' } }

  assert.equal((await post(app, body, { sk })).statusCode, 204)
  assert.equal(repo.pushSubscriptions.size, 1)

  const disable = { action: 'disable', transport: { type: 'fcm', token: 'token-1' } }
  assert.equal((await post(app, disable, { sk })).statusCode, 204)
  assert.equal((await post(app, disable, { sk })).statusCode, 204)
  assert.equal(repo.pushSubscriptions.size, 0)

  await app.close()
})

test('POST rejects missing or invalid NIP-98 authentication', async () => {
  const { app } = await buildPushApp()
  const body = { action: 'register', transport: { type: 'fcm', token: 'token-1' } }

  const missing = await post(app, body, { authorization: null })
  assert.equal(missing.statusCode, 401)
  assert.equal(missing.json().error, 'missing_auth')

  const wrongMethod = await post(app, body, { method: 'GET' })
  assert.equal(wrongMethod.statusCode, 401)
  assert.equal(wrongMethod.json().error, 'method_mismatch')

  const wrongPath = await post(app, body, { path: '/push/other' })
  assert.equal(wrongPath.statusCode, 401)
  assert.equal(wrongPath.json().error, 'url_mismatch')

  const wrongHost = await post(app, body, { host: 'evil.example' })
  assert.equal(wrongHost.statusCode, 401)
  assert.equal(wrongHost.json().error, 'url_mismatch')

  await app.close()
})

test('POST rejects missing or mismatched NIP-98 payload hashes', async () => {
  const { app } = await buildPushApp()
  const body = { action: 'register', transport: { type: 'fcm', token: 'token-1' } }

  const missingPayload = await post(app, body, { includePayload: false })
  assert.equal(missingPayload.statusCode, 401)
  assert.equal(missingPayload.json().error, 'missing_payload')

  const mismatch = await post(app, body, { payloadHash: sha256Hex('different body') })
  assert.equal(mismatch.statusCode, 401)
  assert.equal(mismatch.json().error, 'payload_mismatch')

  await app.close()
})

test('POST rejects invalid push registration bodies', async () => {
  const { app } = await buildPushApp()

  for (const body of [
    { action: 'sync', transport: { type: 'fcm', token: 'token-1' } },
    { action: 'register', transport: { type: 'fcm', token: '' } },
    { action: 'register', transport: { type: 'unifiedpush', endpoint: '' } },
    { action: 'register', transport: { type: 'apns', token: 'token-1' } },
  ]) {
    const result = await post(app, body)
    assert.equal(result.statusCode, 400)
    assert.equal(result.json().error, 'invalid_push_registration')
  }

  await app.close()
})

test('POST returns 503 when push subscription storage is unavailable', async () => {
  const { repo, app } = await buildPushApp()
  repo.fail = true

  const result = await post(app, { action: 'register', transport: { type: 'fcm', token: 'token-1' } })

  assert.equal(result.statusCode, 503)
  assert.equal(result.json().error, 'push_registration_unavailable')

  await app.close()
})

function sha256Hex(value: string): string {
  return createHash('sha256').update(Buffer.from(value, 'utf8')).digest('hex')
}
