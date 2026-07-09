import { applicationDefault, getApps, initializeApp } from 'firebase-admin/app'
import { getMessaging, type Message } from 'firebase-admin/messaging'
import { nip19 } from 'nostr-tools'
import webPush from 'web-push'
import type {
  AppConfig,
  InboundNotification,
  PushNotificationDispatcher,
  PushSubscription,
  PushSubscriptionRepository,
} from './types.js'

const FIREBASE_APP_NAME = 'nmail-push'
const MAX_PUSH_PAYLOAD_BYTES = 3_000

type DispatcherConfig = Pick<
  AppConfig,
  'webPushVapidSubject' | 'webPushVapidPublicKey' | 'webPushVapidPrivateKey'
>

export interface PushPayload {
  title: string
  body: string
  nevent?: string
}

export interface PushDeliveryProviders {
  sendFcm(token: string, payload: PushPayload): Promise<void>
  sendWebPush(subscription: PushSubscription, serializedPayload: string): Promise<void>
}

export function createPushNotificationDispatcher(
  repo: PushSubscriptionRepository,
  config: DispatcherConfig,
  providerOverrides: Partial<PushDeliveryProviders> = {},
): PushNotificationDispatcher {
  const providers = createProviders(config, providerOverrides)

  return {
    async dispatch(notification) {
      const payload = toPushPayload(notification)
      const serializedPayload = JSON.stringify(payload)
      if (Buffer.byteLength(serializedPayload) > MAX_PUSH_PAYLOAD_BYTES) {
        throw new Error('Push notification payload exceeds the transport limit')
      }

      const results = await Promise.allSettled(
        notification.subscriptions.map(async (subscription) => {
          try {
            if (subscription.transport === 'fcm') {
              await providers.sendFcm(subscription.destination, payload)
            } else {
              if (!subscription.p256dh || !subscription.auth) {
                await removeSubscription(repo, subscription)
                return
              }
              await providers.sendWebPush(subscription, serializedPayload)
            }
          } catch (error) {
            if (isPermanentDeliveryError(subscription.transport, error)) {
              await removeSubscription(repo, subscription)
              return
            }
            throw error
          }
        }),
      )

      const failures = results
        .filter((result): result is PromiseRejectedResult => result.status === 'rejected')
        .map((result) => result.reason)
      if (failures.length > 0) {
        throw new AggregateError(failures, 'One or more push notifications could not be delivered')
      }
    },
  }
}

export function toPushPayload(notification: InboundNotification): PushPayload {
  const sender = notification.email?.from?.name ?? notification.email?.from?.address
  const title = truncate(sender ? `New email from ${sender}` : 'New message', 120)!
  const body = truncate(
    notification.email?.subject ??
      notification.email?.preview ??
      (notification.email ? 'You received a new email' : 'You received a new message'),
    240,
  )!
  const nevent = notification.event.id
    ? nip19.neventEncode({
        id: notification.event.id,
        relays: notification.relays.slice(0, 3),
        ...(notification.event.pubkey ? { author: notification.event.pubkey } : {}),
        ...(notification.event.kind !== undefined ? { kind: notification.event.kind } : {}),
      })
    : undefined

  return {
    title,
    body,
    ...(nevent ? { nevent } : {}),
  }
}

function createProviders(
  config: DispatcherConfig,
  overrides: Partial<PushDeliveryProviders>,
): PushDeliveryProviders {
  const vapidDetails =
    config.webPushVapidSubject && config.webPushVapidPublicKey && config.webPushVapidPrivateKey
      ? {
          subject: config.webPushVapidSubject,
          publicKey: config.webPushVapidPublicKey,
          privateKey: config.webPushVapidPrivateKey,
        }
      : undefined

  return {
    sendFcm:
      overrides.sendFcm ??
      (async (token, payload) => {
        const existingApp = getApps().find((app) => app.name === FIREBASE_APP_NAME)
        const app =
          existingApp ??
          initializeApp(
            {
              credential: applicationDefault(),
            },
            FIREBASE_APP_NAME,
          )

        await getMessaging(app).send(toFirebaseMessage(token, payload))
      }),
    sendWebPush:
      overrides.sendWebPush ??
      (async (subscription, payload) => {
        await webPush.sendNotification(
          {
            endpoint: subscription.destination,
            keys: {
              p256dh: subscription.p256dh!,
              auth: subscription.auth!,
            },
          },
          payload,
          {
            TTL: 60 * 60,
            urgency: 'high',
            contentEncoding: 'aes128gcm',
            ...(vapidDetails ? { vapidDetails } : {}),
          },
        )
      }),
  }
}

export function toFirebaseMessage(token: string, payload: PushPayload): Message {
  return {
    token,
    data: {
      ...(payload.nevent ? { nevent: payload.nevent } : {}),
    },
    notification: {
      title: payload.title,
      body: payload.body,
    },
    android: {
      priority: 'high',
    },
    apns: {
      headers: { 'apns-priority': '10' },
      payload: {
        aps: {
          contentAvailable: true,
          sound: 'default',
        },
      },
    },
  }
}

function truncate(value: string | undefined, maxLength: number): string | undefined {
  if (!value || value.length <= maxLength) return value
  return `${value.slice(0, maxLength - 1)}…`
}

async function removeSubscription(repo: PushSubscriptionRepository, subscription: PushSubscription): Promise<void> {
  await repo.deletePushSubscription(subscription.pubkey, subscription.transport, subscription.destination)
}

function isPermanentDeliveryError(transport: PushSubscription['transport'], error: unknown): boolean {
  if (transport === 'unifiedpush') {
    const statusCode = errorValue(error, 'statusCode')
    return statusCode === 404 || statusCode === 410
  }

  const code = errorValue(error, 'code')
  return code === 'messaging/registration-token-not-registered' || code === 'messaging/invalid-registration-token'
}

function errorValue(error: unknown, key: string): unknown {
  return error && typeof error === 'object' && key in error ? (error as Record<string, unknown>)[key] : undefined
}
