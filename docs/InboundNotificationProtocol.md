# Inbound notification protocol

Internal push notification route.

Auth:

```http
Authorization: Bearer <token>
```

`POST /inbound/notifications`

`recipientPubkey` is the pubkey whose push subscriptions receive the
notification.

`relays` lists the relay URLs where the event can be fetched.

`event` is the Nostr event that triggered the notification. A public email
event is sent in full, including `content` and `sig`. For a gift wrap,
`content` and `sig` are omitted.

## Email notification

Sent by `nostr-mail-inbound-webhook`.

```json
{
  "recipientPubkey": "6e3ab85d79988fe2d8c64c8d45e17a1d0dd73c8f4d4514fd02d9bf5f5dc11f2a",
  "relays": ["wss://relay.example.net"],
  "event": {},
  "email": {
    "from": { "address": "alice@example.net", "name": "Alice" },
    "subject": "Hello",
    "preview": "Short plaintext preview"
  }
}
```

`email` is only notification metadata. Do not send `rawMime` or full message
bodies inside `email`; the public Nostr message body belongs in
`event.content`.

## Generic gift wrap notification

Sent by `nostr-relay`.

```json
{
  "recipientPubkey": "6e3ab85d79988fe2d8c64c8d45e17a1d0dd73c8f4d4514fd02d9bf5f5dc11f2a",
  "relays": ["wss://relay.example.net"],
  "event": {},
  "authenticatedPubkeys": [
    "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b70407587144"
  ]
}
```

`authenticatedPubkeys` is used for notification policy/anti-spam and may be
shown as "deposited by" context. It does not identify the decrypted sender.

Success: `202 { "status": "accepted" }`.
