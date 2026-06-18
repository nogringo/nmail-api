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
  assert.deepEqual([...config.protectedEmailDomains], ['nmail.li'])
})
