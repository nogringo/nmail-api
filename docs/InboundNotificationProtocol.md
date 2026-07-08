# Inbound notification protocol

Internal push notification route.

Auth:

```http
Authorization: Bearer <token>
```

`POST /inbound/notifications`

`giftWrap` is sent without `content` and without `sig`.

## Email notification

Sent by `nostr-mail-inbound-webhook`.

```json
{
  "giftWrap": {},
  "email": {
    "from": { "address": "alice@example.net", "name": "Alice" },
    "subject": "Hello",
    "preview": "Short plaintext preview"
  }
}
```

`email` is only notification metadata. Do not send `rawMime` or full message
bodies.

## Generic gift wrap notification

Sent by `nostr-relay`.

```json
{
  "giftWrap": {},
  "authenticatedPubkeys": [
    "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b70407587144"
  ]
}
```

`authenticatedPubkeys` is used for notification policy/anti-spam and may be
shown as "deposited by" context. It does not identify the decrypted sender.

Success: `202 { "status": "accepted" }`.
