import test from 'node:test'
import assert from 'node:assert/strict'
import { normalizeDomain, parseEmailAddress, parseSingleMailbox } from '../src/email.js'

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

test('parseSingleMailbox reads the address of exactly one mailbox', () => {
  const alice = { localPart: 'alice', domain: 'nmail.li' }
  for (const value of [
    'alice@nmail.li',
    'Alice <ALICE@NMAIL.LI>',
    '"Doe, Alice" <alice@nmail.li>',
    '"Alice "AJ" Doe" <alice@nmail.li>',
    '"<ceo@bank.com>" <alice@nmail.li>',
  ]) {
    assert.deepEqual(parseSingleMailbox(value), alice, value)
  }

  for (const value of [
    '<alice@nmail.li>, <ceo@bank.com>',
    'ceo@bank.com, <alice@nmail.li>',
    '<alice@nmail.li> <ceo@bank.com>',
    '(x " y) <ceo@bank.com>, "z" <alice@nmail.li>',
    '"a\\" b" <ceo@bank.com>, "z" <alice@nmail.li>',
    'friends: alice@nmail.li, ceo@bank.com;',
  ]) {
    assert.equal(parseSingleMailbox(value), null, value)
  }
})
