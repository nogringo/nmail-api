# nmail-api

TypeScript API for identity resolution and inbound mail policy:

- `GET /.well-known/nostr.json?name=<local_part>` resolves NIP-05 identities.
- `POST /inbound/decision` answers the inbound SMTP decision protocol.
- `POST /outbound/decision` answers the outbound (nostr → SMTP) decision protocol, enabled only when `OUTBOUND_DECISION_TOKEN` is set.
- `PUT/GET/DELETE /aliases[/{name}]` is the REST alias lifecycle (claim, list, release) authenticated with [NIP-98](https://github.com/nostr-protocol/nips/blob/master/98.md) (`Authorization: Nostr <base64 kind-27235 event>`); the signing pubkey owns the aliases it claims, served on the alias domain (request Host). Enforces the per-plan `max_aliases` limit (free 2, premium 10). See [docs/AliasProtocol.md](docs/AliasProtocol.md) and [docs/AccountModel.md](docs/AccountModel.md).
- `POST /push/subscriptions` registers or disables app push destinations (FCM or UnifiedPush), authenticated with NIP-98 and its `payload` tag bound to the exact JSON body bytes.
- `POST /inbound/notifications` is the internal notification event route for trusted SMTP/relay services to trigger push delivery. See [docs/InboundNotificationProtocol.md](docs/InboundNotificationProtocol.md).
- `POST /inbound/role` receives mail addressed to reserved role mailboxes (`abuse@`, `postmaster@`, ...) from the `haraka-webhook` role webhook and stores it for the operator to read in `/admin`. Enabled only when `WEBHOOK_SIGNING_KEY` is set. The request is `application/x-www-form-urlencoded` (Mailgun-style: `recipient`, `sender`, `from`, `subject`, `message-headers`, `timestamp`, `token`, `signature`, `body-mime`); auth is the plugin's `HMAC-SHA256(timestamp+token)` signature.

## Configuration

```sh
cp .env.example .env
```

Environment variables:

- `PORT`: HTTP port, default `3000`.
- `DATABASE_URL`: Postgres connection string.
- `INBOUND_DECISION_TOKEN`: shared secret required by `POST /inbound/decision`.
- `INBOUND_NOTIFICATION_TOKEN`: shared secret required by
  `POST /inbound/notifications`.
- `OUTBOUND_DECISION_TOKEN`: optional shared secret that enables and protects `POST /outbound/decision`. When unset, the outbound route is not registered.
- `OUTBOUND_MAX_BODY_BYTES`: max accepted body size for `POST /outbound/decision`, default `33554432` (32 MB). Must be larger than the biggest plan message size so the full `.eml` fits.
- `ADMIN_PASSWORD`: optional password that enables the `/admin` identity management UI.
- `WEBHOOK_SIGNING_KEY`: optional HMAC key that enables and protects `POST /inbound/role`. When unset, the role route is not registered. Must equal the `haraka-webhook` plugin's `WEBHOOK_SIGNING_KEY` (the plugin signs both webhooks with it), and the plugin's `WEBHOOK_ROLE_URL` should point at this route.
- `ROLE_WEBHOOK_MAX_BODY_BYTES`: max accepted body size for `POST /inbound/role`, default `33554432` (32 MB), so the full `.eml` fits.

## Account and identity model

The data model separates the **account** (the user, keyed by pubkey) from the
**identity** (a human-readable alias pointing at a pubkey). See
[docs/AccountModel.md](docs/AccountModel.md) for the full design.

- `accounts` holds person-level state: `active`, `mail_enabled`, `plan`
  (`NULL` = the default plan) and `relays`. The service is **open**: a pubkey
  with no account row behaves as active, mail enabled, default plan.
- `identities` maps an alias (`local_part@domain`) to a pubkey and carries only
  `visibility` (`public` is resolvable through `/.well-known/nostr.json`,
  `private` is hidden).
- `plans` hold quotas (rate, max `.eml` size, max recipients) and
  `allowed_domains` (which domains the plan may create/use addresses on).

Addresses come in two classes: a **provisioned alias** (`alice@example.com`, has an
`identities` row) and a **pubkey-encoded** address (`npub...@`, raw 64-char hex,
or base36-encoded pubkey) which resolves to its pubkey without a row. NIP-05
relays are served from the account of the resolved pubkey.

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

Example account and identity (the account row is created automatically when an
identity is added, so it is only needed to override the defaults):

```sql
insert into accounts (pubkey, relays)
values (
  'b479e0d9afe3cf3caf43f1ded62da06d248d171d93f04c759431879afc371457',
  '["wss://relay.example.com"]'::jsonb
)
on conflict (pubkey) do nothing;

insert into identities (domain, local_part, pubkey)
values (
  'example.com',
  'alice',
  'b479e0d9afe3cf3caf43f1ded62da06d248d171d93f04c759431879afc371457'
);
```

## Admin UI

Set `ADMIN_PASSWORD` to enable the built-in admin console:

```sh
ADMIN_PASSWORD=change-me npm run dev
```

Open `http://localhost:3000/admin` and sign in with the configured password.
The console has four tabs:

- **Identities**: create, update, and delete alias to pubkey mappings (domain,
  local part, pubkey, visibility).
- **Accounts**: per pubkey, toggle `active` and `mail_enabled`, set the plan, and
  edit relays. Deleting an account row reverts the pubkey to the defaults.
- **Plans**: edit quotas and allowed domains, add new plans, and choose the default.
- **Domains**: add or remove the domains the service handles.

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

1. **Ownership**: the `From` domain must be a managed domain, and either a matching
   `identities` alias is owned by `nostrSender` (a provisioned alias, which keeps
   working regardless of the current plan), or the local part decodes to
   `nostrSender` (a pubkey-encoded address). Encoded addresses also auto-create a
   free account and must be on a domain allowed by the current plan.
2. **Account**: the sender account must be `active` and `mail_enabled`.
3. **Plan limits** for the sender pubkey: recipient count (`To` + `Cc` + `Bcc`),
   message size (the `.eml` byte length), and a sliding send-rate window (per
   minute, hour, day).

A passing message returns `{ "decision": "allow" }` and is recorded for rate
limiting. A blocked message returns `{ "decision": "deny", "reason": ..., "message": ... }`
with reason `unauthorized_sender`, `account_disabled`, `domain_not_allowed`,
`too_many_recipients`, `message_too_large`, or `rate_limited`. Lookup failures
return `503` so the bridge retries. Re-asking about an already-recorded
`giftWrapId` is idempotent and is not double counted.

Send `OUTBOUND_DECISION_TOKEN` with `Authorization: Bearer <token>`,
`x-outbound-decision-token: <token>`, or `?token=<token>`.

## Push subscriptions

Configure the Flutter app with:

```sh
NMAIL_PUSH_ENDPOINT=https://api.example.com/push/subscriptions
```

The app posts `application/json` with `action: "register"` or `"disable"` and a
transport destination (`fcm.token` or `unifiedpush.endpoint`). Authentication is
NIP-98 (`Authorization: Nostr <base64 kind-27235 event>`) and this route requires
the event `payload` tag to equal the SHA-256 hash of the exact UTF-8 JSON body.
A valid register or disable returns `204 No Content`.

### Plans

Outbound limits are grouped into **plans**. Each account references a plan
(`accounts.plan`); accounts with no plan fall back to the default. Two plans are
seeded by migration `003`:

| Plan | Per minute | Per hour | Per day | Max `.eml` size | Max recipients | Max aliases |
|---|---|---|---|---|---|---|
| `free` (default) | 5 | 30 | 50 | 10 MB | 5 | 2 |
| `premium` | 10 | 100 | 500 | 25 MB | 10 | 10 |

Plans are managed from the admin UI (`Plans` tab) and per-pubkey plan choice
from the `Accounts` tab; new plans can be added. `max_aliases` caps how many
provisioned aliases an account may claim via `PUT /aliases/{name}`
(pubkey-encoded addresses are not aliases and do not count). Each plan also has
`allowed_domains`: the domains it may create or send pubkey-encoded addresses on
(empty = all managed domains; provisioned aliases are exempt and keep working
after a downgrade). The message size limit is measured on the encoded `.eml`,
matching how SMTP servers enforce `SIZE`; because attachments are base64-encoded
(about +37%), 10 MB of raw files is roughly a 13.7 MB `.eml`, so set the limit on
the message accordingly.
