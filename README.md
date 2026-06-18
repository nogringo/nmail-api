# nmail-api

TypeScript API for identity resolution and inbound mail policy:

- `GET /.well-known/nostr.json?name=<local_part>` resolves NIP-05 identities.
- `POST /inbound/decision` answers the inbound SMTP decision protocol.

## Configuration

```sh
cp .env.example .env
```

Environment variables:

- `PORT`: HTTP port, default `3000`.
- `DATABASE_URL`: Postgres connection string.
- `PROTECTED_EMAIL_DOMAINS`: comma-separated domains that require an active NIP-05 identity before inbound mail is accepted. Defaults to `nmail.li`.
- `INBOUND_DECISION_TOKEN`: shared secret required by `POST /inbound/decision`.

## Identity Model

`identities` stores the address identities used by both NIP-05 resolution
and inbound mail policy.

- `visibility = 'public'`: resolvable by anyone through `/.well-known/nostr.json`.
- `visibility = 'private'`: hidden from public NIP-05 resolution.
- `mail_enabled = true`: usable by the inbound mail decision endpoint.
- `active = false`: disabled everywhere.

## Database

Run the API with an external Postgres database:

```sh
docker compose up -d
```

Run the all-in-one stack with the API and Postgres:

```sh
docker compose -f docker-compose.aio.yml up -d
```

Apply migrations against the target database:

```sh
psql "$DATABASE_URL" -f migrations/001_create_identities.sql
```

When using the all-in-one Compose file, the exposed local database URL is:

```sh
psql "postgres://nmail:nmail@localhost:5432/nmail" \
  -f migrations/001_create_identities.sql
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

## Development

```sh
npm install
npm run typecheck
npm test
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
