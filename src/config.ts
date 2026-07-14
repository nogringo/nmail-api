import type { AppConfig } from './types.js'
import { normalizeRelayUrl } from './nostr.js'

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const databaseUrl = env.DATABASE_URL
  if (!databaseUrl) {
    throw new Error('DATABASE_URL is required')
  }

  const inboundDecisionToken = parseRequiredSecret(env.INBOUND_DECISION_TOKEN, 'INBOUND_DECISION_TOKEN')
  const webPushVapid = parseWebPushVapid(env)

  return {
    port: parsePort(env.PORT),
    databaseUrl,
    inboundDecisionToken,
    inboundNotificationToken: parseOptionalSecret(env.INBOUND_NOTIFICATION_TOKEN),
    ...webPushVapid,
    outboundDecisionToken: parseOptionalSecret(env.OUTBOUND_DECISION_TOKEN),
    outboundMaxBodyBytes: parseMaxBodyBytes(env.OUTBOUND_MAX_BODY_BYTES, 'OUTBOUND_MAX_BODY_BYTES'),
    adminPassword: parseOptionalSecret(env.ADMIN_PASSWORD),
    roleWebhookSigningKey: parseOptionalSecret(env.WEBHOOK_SIGNING_KEY),
    roleWebhookMaxBodyBytes: parseMaxBodyBytes(env.ROLE_WEBHOOK_MAX_BODY_BYTES, 'ROLE_WEBHOOK_MAX_BODY_BYTES'),
    accountDeletionRelayUrls: parseRelayUrls(env.ACCOUNT_DELETION_RELAY_URLS),
  }
}

function parseWebPushVapid(env: NodeJS.ProcessEnv): {
  webPushVapidSubject?: string
  webPushVapidPublicKey?: string
  webPushVapidPrivateKey?: string
} {
  const subject = parseOptionalSecret(env.WEB_PUSH_VAPID_SUBJECT)
  const publicKey = parseOptionalSecret(env.WEB_PUSH_VAPID_PUBLIC_KEY)
  const privateKey = parseOptionalSecret(env.WEB_PUSH_VAPID_PRIVATE_KEY)
  const configured = [subject, publicKey, privateKey].filter(Boolean).length

  if (configured !== 0 && configured !== 3) {
    throw new Error(
      'WEB_PUSH_VAPID_SUBJECT, WEB_PUSH_VAPID_PUBLIC_KEY and WEB_PUSH_VAPID_PRIVATE_KEY must be configured together',
    )
  }

  return configured === 3
    ? {
        webPushVapidSubject: subject,
        webPushVapidPublicKey: publicKey,
        webPushVapidPrivateKey: privateKey,
      }
    : {}
}

function parsePort(value: string | undefined): number {
  if (!value) return 3000

  const port = Number(value)
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error('PORT must be an integer between 1 and 65535')
  }

  return port
}

function parseMaxBodyBytes(value: string | undefined, name: string): number {
  const defaultBytes = 32 * 1024 * 1024
  if (!value) return defaultBytes

  const bytes = Number(value)
  if (!Number.isInteger(bytes) || bytes <= 0) {
    throw new Error(`${name} must be a positive integer`)
  }

  return bytes
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

function parseRelayUrls(value: string | undefined): string[] {
  const entries = value
    ?.split(',')
    .map((entry) => entry.trim())
    .filter(Boolean)

  if (!entries?.length) return []

  return entries.map((entry) => {
    const relayUrl = normalizeRelayUrl(entry)
    if (!relayUrl) {
      throw new Error('ACCOUNT_DELETION_RELAY_URLS must contain comma-separated ws:// or wss:// URLs')
    }
    return relayUrl
  })
}
