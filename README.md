# nmail-api

TypeScript API for identity resolution and inbound mail policy:

- `GET /.well-known/nostr.json?name=<local_part>` resolves NIP-05 identities.
- `POST /inbound/decision` answers the inbound SMTP decision protocol.
- `POST /outbound/decision` answers the outbound (nostr → SMTP) decision protocol, enabled only when `OUTBOUND_DECISION_TOKEN` is set.

## Configuration

```sh
cp .env.example .env
```

Environment variables:

- `PORT`: HTTP port, default `3000`.
- `DATABASE_URL`: Postgres connection string.
- `PROTECTED_EMAIL_DOMAINS`: comma-separated domains that require a known mail-enabled pubkey before inbound mail is accepted. Defaults to `nmail.li`.
- `INBOUND_DECISION_TOKEN`: shared secret required by `POST /inbound/decision`.
- `OUTBOUND_DECISION_TOKEN`: optional shared secret that enables and protects `POST /outbound/decision`. When unset, the outbound route is not registered.
- `OUTBOUND_MAX_BODY_BYTES`: max accepted body size for `POST /outbound/decision`, default `33554432` (32 MB). Must be larger than the biggest plan message size so the full `.eml` fits.
- `ADMIN_PASSWORD`: optional password that enables the `/admin` identity management UI.

## Identity Model

`identities` stores the address identities used by both NIP-05 resolution
and inbound mail policy.

- `visibility = 'public'`: resolvable by anyone through `/.well-known/nostr.json`.
- `visibility = 'private'`: hidden from public NIP-05 resolution.
- `mail_enabled = true`: usable by the inbound mail decision endpoint.
- `active = false`: disabled everywhere.

For protected inbound mail domains, recipients may use a local identity
(`alice@nmail.li`), an encoded Nostr pubkey (`npub...@nmail.li`), a raw
64-character hex pubkey, or a base36-encoded pubkey. The decision endpoint
resolves the recipient to a pubkey, then accepts delivery when an active,
mail-enabled identity exists with the same protected domain and pubkey. Local
identities are checked before base36 decoding so normal aliases keep working.

## Database

Run the API with an external Postgres database:

```sh
docker compose up -d
```

Run the all-in-one stack with the API and Postgres:

```sh
docker compose -f docker-compose.aio.yml up -d
```

Apply migrations against the target database, in order:

```sh
for migration in migrations/*.sql; do psql "$DATABASE_URL" -f "$migration"; done
```

When using the all-in-one Compose file, the exposed local database URL is:

```sh
for migration in migrations/*.sql; do \
  psql "postgres://nmail:nmail@localhost:5432/nmail" -f "$migration"; \
done
```

Example identity:

```sql
insert into identities (domain, local_part, pubkey, relays)
values (
  'nmail.li',
  'alice',
  'b479e0d9afe3cf3caf43f1ded62da06d248d171d93f04c759431879afc371457',
  '["wss://relay.nmail.li"]'::jsonb
);
```

## Admin UI

Set `ADMIN_PASSWORD` to enable the built-in admin console:

```sh
ADMIN_PASSWORD=change-me npm run dev
```

Open `http://localhost:3000/admin` and sign in with the configured password.
The console has three tabs:

- **Identities**: create, update, activate/deactivate, and delete identities.
- **Plans**: edit the limits of each plan, add new plans, and choose the default.
- **Pubkey plans**: assign a plan to a pubkey, or remove an assignment so the
  pubkey falls back to the default plan.

If `ADMIN_PASSWORD` is not set, the admin routes are not registered.

## Development

```sh
npm install
npm run typecheck
npm test
npm run dev
```

`npm run dev` loads `.env` automatically when the file exists.

Run the local development database:

```sh
docker compose -f docker-compose.dev.yml up -d
```

The dev database uses `nmail:nmail` on `localhost:5432`, matching the
`DATABASE_URL` from `.env.example`.

Apply the database migrations to the dev Postgres container:

```sh
for migration in migrations/*.sql; do \
  docker compose -f docker-compose.dev.yml exec -T postgres \
    psql -U nmail -d nmail < "$migration"; \
done
```

Then run the API directly on your machine:

```sh
npm run dev
```

## Container

The production image is published to GitHub Container Registry:

```sh
docker pull ghcr.io/nogringo/nmail-api:main
```

Tagged releases matching `v*.*.*` also publish semver tags.

## Inbound SMTP

Configure the SMTP receiver decision URL with:

```sh
WEBHOOK_DECISION_URL=http://nmail-api:3000/inbound/decision
WEBHOOK_DECISION_PAYLOAD_MODE=minimal
```

Send `INBOUND_DECISION_TOKEN` with `Authorization: Bearer <token>` or
`x-inbound-decision-token: <token>`. If the SMTP receiver cannot send custom
headers, the endpoint also accepts `?token=<token>` as a compatibility fallback.

## Outbound (nostr to SMTP)

Configure the nostr-to-SMTP bridge decision URL with:

```sh
DECISION_URL=http://nmail-api:3000/outbound/decision
DECISION_PAYLOAD_MODE=full
```

Use `full` mode so the bridge forwards the complete `.eml` (`rawMime`); the
message size limit can only be enforced when the `.eml` is present.

The bridge posts the authenticated seal pubkey as `nostrSender` and the message
MIME `headers`. The endpoint applies, in order:

1. **Ownership**: the `From` address must sit on a protected domain and resolve
   to an active, mail-enabled identity whose pubkey matches `nostrSender`, so a
   key can only send as an address it owns.
2. **Plan limits** for the sender pubkey (see below): recipient count
   (`To` + `Cc` + `Bcc`), message size (the `.eml` byte length), and a sliding
   send-rate window (per minute, hour, day).

A passing message returns `{ "decision": "allow" }` and is recorded for rate
limiting. A blocked message returns `{ "decision": "deny", "reason": ..., "message": ... }`
with reason `unauthorized_sender`, `too_many_recipients`, `message_too_large`, or
`rate_limited`. Lookup failures return `503` so the bridge retries. Re-asking
about an already-recorded `giftWrapId` is idempotent and is not double counted.

Send `OUTBOUND_DECISION_TOKEN` with `Authorization: Bearer <token>`,
`x-outbound-decision-token: <token>`, or `?token=<token>`.

### Plans

Outbound limits are grouped into **plans**. Each pubkey is mapped to a plan;
pubkeys with no mapping fall back to the default plan. Two plans are seeded by
migration `003`:

| Plan | Per minute | Per hour | Per day | Max `.eml` size | Max recipients |
|---|---|---|---|---|---|
| `free` (default) | 5 | 30 | 50 | 10 MB | 5 |
| `premium` | 10 | 100 | 500 | 25 MB | 10 |

Plans and pubkey assignments are managed from the admin UI (`Plans` and
`Pubkey plans` tabs), and new plans can be added. The message size limit is
measured on the encoded `.eml`, matching how SMTP servers enforce `SIZE`; because
attachments are base64-encoded (about +37%), 10 MB of raw files is roughly a
13.7 MB `.eml`, so set the limit on the message accordingly.
