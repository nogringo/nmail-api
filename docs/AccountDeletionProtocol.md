# Account deletion protocol

## Endpoint

```http
POST /accounts/vanish
```

Callable by anyone.

## Body

```json
{
  "event": {
    "kind": 62,
    "pubkey": "<hex pubkey>",
    "created_at": 1234567890,
    "tags": [["relay", "<relay url>"]],
    "content": "",
    "id": "<event id>",
    "sig": "<signature>"
  }
}
```

## Validation

- `event` is a complete Nostr event.
- `event.kind === 62`.
- `event.sig` is valid.
- `event.created_at >= now - 7 days`.
- `event.created_at <= now + 1 day`.
- `event.tags` contains `["relay", "<configured nmail relay url>"]` or `["relay", "ALL_RELAYS"]`.

## Effect

If valid, delete all database data linked to `event.pubkey`.

Idempotent.

## Responses

- `202 { "status": "accepted" }`
- `400 { "error": "invalid_request" }`

Reference: [NIP-62](https://github.com/nostr-protocol/nips/blob/master/62.md).
