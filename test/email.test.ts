import test from 'node:test'
import assert from 'node:assert/strict'
import { normalizeDomain, parseEmailAddress } from '../src/email.js'

test('normalizeDomain lowercases and strips ports', () => {
  assert.equal(normalizeDomain('NMAIL.LI:3000'), 'nmail.li')
  assert.equal(normalizeDomain('example.com.'), 'example.com')
})

test('parseEmailAddress handles plain and display-name addresses', () => {
  assert.deepEqual(parseEmailAddress('Alice <ALICE@NMAIL.LI>'), {
    localPart: 'alice',
    domain: 'nmail.li',
  })
  assert.deepEqual(parseEmailAddress('mailto:bob@example.com'), {
    localPart: 'bob',
    domain: 'example.com',
  })
  assert.equal(parseEmailAddress('not-an-email'), null)
})
