import test from 'node:test'
import assert from 'node:assert/strict'
import { loadConfig } from '../src/config.js'

test('loadConfig requires INBOUND_DECISION_TOKEN', () => {
  assert.throws(
    () => loadConfig({ DATABASE_URL: 'postgres://localhost/nmail' }),
    /INBOUND_DECISION_TOKEN is required/,
  )
})

test('loadConfig includes the inbound decision token', () => {
  const config = loadConfig({
    DATABASE_URL: 'postgres://localhost/nmail',
    INBOUND_DECISION_TOKEN: 'secret-token',
    INBOUND_NOTIFICATION_TOKEN: 'notify-token',
  })

  assert.equal(config.inboundDecisionToken, 'secret-token')
  assert.equal(config.inboundNotificationToken, 'notify-token')
})

test('loadConfig parses account deletion relay URLs', () => {
  const config = loadConfig({
    DATABASE_URL: 'postgres://localhost/nmail',
    INBOUND_DECISION_TOKEN: 'secret-token',
    ACCOUNT_DELETION_RELAY_URLS: 'wss://Relay.Example.com/, ws://localhost:7777/path/',
  })

  assert.deepEqual(config.accountDeletionRelayUrls, ['wss://relay.example.com', 'ws://localhost:7777/path'])
})

test('loadConfig rejects invalid account deletion relay URLs', () => {
  assert.throws(
    () =>
      loadConfig({
        DATABASE_URL: 'postgres://localhost/nmail',
        INBOUND_DECISION_TOKEN: 'secret-token',
        ACCOUNT_DELETION_RELAY_URLS: 'https://relay.example.com',
      }),
    /ACCOUNT_DELETION_RELAY_URLS/,
  )
})

test('loadConfig enables admin only when ADMIN_PASSWORD is set', () => {
  const withoutAdmin = loadConfig({
    DATABASE_URL: 'postgres://localhost/nmail',
    INBOUND_DECISION_TOKEN: 'secret-token',
  })
  const withAdmin = loadConfig({
    DATABASE_URL: 'postgres://localhost/nmail',
    INBOUND_DECISION_TOKEN: 'secret-token',
    ADMIN_PASSWORD: 'admin-secret',
  })

  assert.equal(withoutAdmin.adminPassword, undefined)
  assert.equal(withAdmin.adminPassword, 'admin-secret')
})

test('loadConfig includes Web Push delivery configuration', () => {
  const config = loadConfig({
    DATABASE_URL: 'postgres://localhost/nmail',
    INBOUND_DECISION_TOKEN: 'secret-token',
    WEB_PUSH_VAPID_SUBJECT: 'mailto:admin@example.com',
    WEB_PUSH_VAPID_PUBLIC_KEY: 'public-key',
    WEB_PUSH_VAPID_PRIVATE_KEY: 'private-key',
  })

  assert.equal(config.webPushVapidSubject, 'mailto:admin@example.com')
  assert.equal(config.webPushVapidPublicKey, 'public-key')
  assert.equal(config.webPushVapidPrivateKey, 'private-key')
})

test('loadConfig rejects partial VAPID configuration', () => {
  assert.throws(
    () =>
      loadConfig({
        DATABASE_URL: 'postgres://localhost/nmail',
        INBOUND_DECISION_TOKEN: 'secret-token',
        WEB_PUSH_VAPID_PUBLIC_KEY: 'public-key',
      }),
    /must be configured together/,
  )
})
