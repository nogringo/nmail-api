# Account model

This document is the source of truth for how accounts, identities and plans
relate, and how the inbound/outbound decisions use them. It exists so the design
survives context loss between sessions.

## Entities

```
plans      (name PK)     per_minute, per_hour, per_day, max_message_bytes,
                         max_recipients, max_aliases, allowed_domains (jsonb[]),
                         is_default
accounts   (pubkey PK)   active, mail_enabled, plan -> plans (NULL = default),
                         relays (jsonb[]), created_at, updated_at
identities (domain,      pubkey -> accounts, visibility, created_at, updated_at
            local_part)
domains    (domain PK)   the domains the service handles, managed from /admin
outbound_sends           pubkey, gift_wrap_id, created_at
```

- **account = the user**, keyed by its nostr pubkey. Holds everything that is a
  property of the *person*: `active`, `mail_enabled`, `plan`, `relays`.
- **identity = a human-readable alias** (`alice@example.com`) pointing at a pubkey.
  Holds only what is specific to the name: `visibility` (NIP-05 public/private).
  It no longer carries `mail_enabled`, `active` or `relays` (moved to account).
- **plan** = quotas + `allowed_domains` (the domains the plan may *create/use*
  addresses on) + `max_aliases` (how many provisioned aliases the account may
  claim: free = 2, premium = 10). `NULL` plan on an account means "use the
  default plan".

## Two classes of sending address

| Class | Example | identities row? | ownership proof |
|-------|---------|-----------------|-----------------|
| Provisioned alias | `alice@example.com` | yes | the row maps alias -> pubkey |
| Pubkey-encoded | `npub1...@`, `<hex64>@`, `<base36>@` | not required | the localpart decodes to the pubkey |

## Open service / auto-create

The service is **open**: any pubkey can use it. A pubkey with no `accounts` row
behaves as `active = true`, `mail_enabled = true`, default plan.

- **Outbound** from an encoded address auto-creates a free account
  (`getOrCreateAccount`) so the user becomes manageable (bannable, upgradable).
- **Inbound** never persists an account; a missing account is treated as the
  permissive default (so encoded recipients are deliverable by default).

## Outbound decision (`/outbound/decision`)

For `localPart@domain` with authenticated `nostrSender`:

1. `domain` must be in the `domains` table, else `deny unauthorized_sender`
   (anti open-relay).
2. Ownership:
   - if an `identities` row exists for `(domain, localPart)`: its pubkey must be
     the sender. Alias exists => **grandfathered**, no domain/plan check.
   - else if `localPart` decodes to the sender pubkey: it is an **encoded**
     address; auto-create the account and require `domain` to be in the plan's
     `allowed_domains` (empty list = all managed domains).
   - else `deny unauthorized_sender`.
3. Account must be `active` and `mail_enabled`, else `deny account_disabled`.
4. Plan quotas: recipients (`To`+`Cc`+`Bcc`), `.eml` size (`rawMime`), sliding
   rate window (minute/hour/day). Over limit => `deny` with the matching reason.
5. Idempotent on `giftWrapId` (already recorded => allow without recounting).

Grandfathering: sending only checks alias existence + ownership, so an alias
created while premium keeps working after a downgrade (its row persists). Encoded
addresses are re-derivable, so they are gated by the *current* plan instead.

## Inbound decision (`/inbound/decision`)

For each recipient on a managed domain: resolve the pubkey (alias row or
encoded decode). Unknown alias that does not decode => `deny unknown_recipient`.
If the resolved pubkey has an account that is `active = false` or
`mail_enabled = false` => `deny unknown_recipient`. Missing account = allowed.

## Alias lifecycle (`/aliases`, `/aliases/{name}`)

Lets a user manage their provisioned aliases themselves (the admin UI is no
longer the only way to create one). The REST protocol in `docs/AliasProtocol.md`
is served on the alias domain (the request **Host**, i.e. the NIP-05 domain) and
authenticated with [NIP-98](https://github.com/nostr-protocol/nips/blob/master/98.md)
(`Authorization: Nostr <base64 kind-27235 event>`); the signing pubkey owns the
alias and the name is the URL path.

- `PUT /aliases/{name}?visibility=public|private` claims a free name (`201`) or,
  for the owner, updates its visibility (`200`, idempotent). `409 alias_taken`,
  `400`/`403` on policy rejection.
- `GET /aliases` lists the authenticated pubkey's aliases (`200 { aliases }`).
- `DELETE /aliases/{name}` releases it: `204`, `404 alias_not_found`,
  `403 not_owner`.

Provisioning (`provisionAlias` in `src/aliases.ts`) checks, in order: local part
not reserved and length **6-47** / NIP-05 charset (the 47 cap also keeps aliases
clear of the 48-52 char base36-encoded range, so no pubkey-encoded address can be
claimed), domain is managed, the alias is free (or already owned by the same
pubkey => idempotent), the account is `active`, the domain is in the plan's
`allowed_domains` (empty = all managed domains), and the pubkey's current
non-encoded alias count is `< plan.max_aliases`. On success it inserts the
`identities` row (auto-creating the account). Rejections: `invalid_local_part`,
`reserved_local_part`, `encoded_not_claimable`, `domain_not_managed`,
`alias_taken`, `account_disabled`, `domain_not_allowed`, `alias_limit_reached`.

Unlike outbound sending (where existing aliases are grandfathered past the plan's
`allowed_domains`), **claiming** a *new* alias is gated by `allowed_domains`: the
plan that creates the address must be allowed on its domain. An already-owned
alias still returns idempotently regardless of the current plan.

NIP-98 binding (`src/nip98.ts`): kind `27235`, `created_at` within ±60 s, the
`method` tag matches the request, and the `u` tag's host + path match the request.
Scheme and query string are not compared (TLS is proxy-terminated; the query only
carries the idempotent `visibility` preference). Auth failures return `401` with a
`WWW-Authenticate: Nostr` header.

## NIP-05 (`/.well-known/nostr.json`)

`name` -> public identity (alias) -> pubkey, then `relays` come from the
**account** of that pubkey.

## Migrations

- `003` creates `plans`, `accounts`, `outbound_sends` (no `pubkey_plans`).
- `004` backfills `accounts` from the existing `identities` (`bool_or(active)`,
  `bool_or(mail_enabled)`, relays), then drops `active`/`mail_enabled`/`relays`
  from `identities` and adds the FK `identities.pubkey -> accounts.pubkey`.
- `005` creates the `domains` table (managed from /admin), replacing the
  `PROTECTED_EMAIL_DOMAINS` environment variable.
- `006` adds `plans.max_aliases` (free = 2, premium = 10) and an index on
  `identities (pubkey)` to count a pubkey's aliases.
