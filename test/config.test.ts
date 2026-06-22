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
  })

  assert.equal(config.inboundDecisionToken, 'secret-token')
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
