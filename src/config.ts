import { normalizeDomain } from './email.js'
import type { AppConfig } from './types.js'

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const databaseUrl = env.DATABASE_URL
  if (!databaseUrl) {
    throw new Error('DATABASE_URL is required')
  }

  const inboundDecisionToken = parseRequiredSecret(env.INBOUND_DECISION_TOKEN, 'INBOUND_DECISION_TOKEN')

  return {
    port: parsePort(env.PORT),
    databaseUrl,
    protectedEmailDomains: parseProtectedDomains(env.PROTECTED_EMAIL_DOMAINS),
    inboundDecisionToken,
    adminPassword: parseOptionalSecret(env.ADMIN_PASSWORD),
  }
}

function parsePort(value: string | undefined): number {
  if (!value) return 3000

  const port = Number(value)
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error('PORT must be an integer between 1 and 65535')
  }

  return port
}

export function parseProtectedDomains(value: string | undefined): Set<string> {
  const rawDomains = value && value.trim() ? value.split(',') : ['nmail.li']
  const domains = rawDomains.map((domain) => normalizeDomain(domain)).filter(Boolean)

  if (domains.length === 0) {
    throw new Error('PROTECTED_EMAIL_DOMAINS must include at least one valid domain')
  }

  return new Set(domains)
}

function parseRequiredSecret(value: string | undefined, name: string): string {
  const secret = value?.trim()
  if (!secret) {
    throw new Error(`${name} is required`)
  }

  return secret
}

function parseOptionalSecret(value: string | undefined): string | undefined {
  const secret = value?.trim()
  return secret || undefined
}
