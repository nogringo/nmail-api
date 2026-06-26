# Alias protocol

REST API for the alias lifecycle, served on the NIP-05 domain of the address: to
manage `name@domain` you call `https://<domain>/...`. The signing pubkey owns the
aliases it claims.

Auth is [NIP-98](https://github.com/nostr-protocol/nips/blob/master/98.md).

## Endpoints

`{name}` is the local part; the domain is the host. Claim `alice@example.com` ->
`PUT https://example.com/aliases/alice`.

| Method | Path | Action |
| --- | --- | --- |
| `PUT` | `/aliases/{name}?visibility=public\|private` | claim or set visibility (idempotent) |
| `GET` | `/aliases` | list the pubkey's aliases |
| `DELETE` | `/aliases/{name}` | release |

- **PUT**: creates the alias if the name is free, or updates its visibility if
  the pubkey already owns it. `visibility` defaults to `public`. On create the
  server may reject the name or the claim per its own policy. `201` created,
  `200` updated, `400` rejected, `403` not permitted, `409 alias_taken`.
- **GET**: `200 { aliases: [...] }` owned by the pubkey.
- **DELETE**: only the owner may delete. `204`, `404 alias_not_found`,
  `403 not_owner`.
