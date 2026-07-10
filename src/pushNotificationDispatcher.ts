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

interface NotificationCopy {
  messageTitle: string
  messageBody: string
  emailTitle(sender?: string): string
  emailBody: string
}

const NOTIFICATION_COPY: Record<string, NotificationCopy> = {
  de: {
    messageTitle: 'Neue Nachricht',
    messageBody: 'Sie haben eine neue Nachricht erhalten',
    emailTitle: (sender) => (sender ? `Neue E-Mail von ${sender}` : 'Neue E-Mail'),
    emailBody: 'Sie haben eine neue E-Mail erhalten',
  },
  en: {
    messageTitle: 'New message',
    messageBody: 'You received a new message',
    emailTitle: (sender) => (sender ? `New email from ${sender}` : 'New email'),
    emailBody: 'You received a new email',
  },
  es: {
    messageTitle: 'Nuevo mensaje',
    messageBody: 'Has recibido un nuevo mensaje',
    emailTitle: (sender) => (sender ? `Nuevo correo de ${sender}` : 'Nuevo correo'),
    emailBody: 'Has recibido un nuevo correo',
  },
  fi: {
    messageTitle: 'Uusi viesti',
    messageBody: 'Sait uuden viestin',
    emailTitle: (sender) => (sender ? `Uusi sähköposti lähettäjältä ${sender}` : 'Uusi sähköposti'),
    emailBody: 'Sait uuden sähköpostin',
  },
  fr: {
    messageTitle: 'Nouveau message',
    messageBody: 'Vous avez reçu un nouveau message',
    emailTitle: (sender) => (sender ? `Nouvel e-mail de ${sender}` : 'Nouvel e-mail'),
    emailBody: 'Vous avez reçu un nouvel e-mail',
  },
  it: {
    messageTitle: 'Nuovo messaggio',
    messageBody: 'Hai ricevuto un nuovo messaggio',
    emailTitle: (sender) => (sender ? `Nuova e-mail da ${sender}` : 'Nuova e-mail'),
    emailBody: 'Hai ricevuto una nuova e-mail',
  },
  ja: {
    messageTitle: '新しいメッセージ',
    messageBody: '新しいメッセージを受信しました',
    emailTitle: (sender) => (sender ? `${sender}から新しいメール` : '新しいメール'),
    emailBody: '新しいメールを受信しました',
  },
  pt: {
    messageTitle: 'Nova mensagem',
    messageBody: 'Recebeu uma nova mensagem',
    emailTitle: (sender) => (sender ? `Novo e-mail de ${sender}` : 'Novo e-mail'),
    emailBody: 'Recebeu um novo e-mail',
  },
  'pt-br': {
    messageTitle: 'Nova mensagem',
    messageBody: 'Você recebeu uma nova mensagem',
    emailTitle: (sender) => (sender ? `Novo e-mail de ${sender}` : 'Novo e-mail'),
    emailBody: 'Você recebeu um novo e-mail',
  },
  ru: {
    messageTitle: 'Новое сообщение',
    messageBody: 'Вы получили новое сообщение',
    emailTitle: (sender) => (sender ? `Новое письмо от ${sender}` : 'Новое письмо'),
    emailBody: 'Вы получили новое письмо',
  },
  zh: {
    messageTitle: '新消息',
    messageBody: '你收到了一条新消息',
    emailTitle: (sender) => (sender ? `来自 ${sender} 的新邮件` : '新邮件'),
    emailBody: '你收到了一封新邮件',
  },
}

export function createPushNotificationDispatcher(
  repo: PushSubscriptionRepository,
  config: DispatcherConfig,
  providerOverrides: Partial<PushDeliveryProviders> = {},
): PushNotificationDispatcher {
  const providers = createProviders(config, providerOverrides)

  return {
    async dispatch(notification) {
      const deliveries = notification.subscriptions.map((subscription) => {
        const payload = toPushPayload(notification, subscription.language)
        const serializedPayload = JSON.stringify(payload)
        if (Buffer.byteLength(serializedPayload) > MAX_PUSH_PAYLOAD_BYTES) {
          throw new Error('Push notification payload exceeds the transport limit')
        }

        return { subscription, payload, serializedPayload }
      })

      const results = await Promise.allSettled(
        deliveries.map(async ({ subscription, payload, serializedPayload }) => {
          try {
            if (subscription.transport === 'fcm') {
              await providers.sendFcm(subscription.destination, payload)
            } else {
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

export function toPushPayload(notification: InboundNotification, language = 'en'): PushPayload {
  const copy = notificationCopy(language)
  const sender = notification.email?.from?.name ?? notification.email?.from?.address
  const title = truncate(notification.email ? copy.emailTitle(sender) : copy.messageTitle, 120)!
  const body = truncate(
    notification.email?.subject ??
      notification.email?.preview ??
      (notification.email ? copy.emailBody : copy.messageBody),
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
        if (subscription.p256dh && subscription.auth) {
          await webPush.sendNotification(
            {
              endpoint: subscription.destination,
              keys: {
                p256dh: subscription.p256dh,
                auth: subscription.auth,
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
          return
        }

        const response = await fetch(subscription.destination, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            ttl: String(60 * 60),
            urgency: 'high',
          },
          body: payload,
        })
        if (!response.ok) {
          throw Object.assign(new Error(`UnifiedPush delivery failed with status ${response.status}`), {
            statusCode: response.status,
          })
        }
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

function notificationCopy(language: string): NotificationCopy {
  const normalizedLanguage = language.toLowerCase()
  const baseLanguage = normalizedLanguage.split('-')[0]
  return NOTIFICATION_COPY[normalizedLanguage] ?? NOTIFICATION_COPY[baseLanguage] ?? NOTIFICATION_COPY.en
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
