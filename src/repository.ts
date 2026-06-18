import pg from 'pg'
import type { IdentityRepository, IdentityVisibility, UserIdentity } from './types.js'

const { Pool } = pg

interface IdentityRow {
  domain: string
  local_part: string
  pubkey: string
  relays: unknown
  visibility: IdentityVisibility
  mail_enabled: boolean
  active: boolean
}

export class PgIdentityRepository implements IdentityRepository {
  private readonly pool: pg.Pool

  constructor(databaseUrl: string) {
    this.pool = new Pool({ connectionString: databaseUrl })
  }

  async findPublicIdentity(domain: string, localPart: string): Promise<UserIdentity | null> {
    const result = await this.pool.query<IdentityRow>(
      `
        select domain, local_part, pubkey, relays, visibility, mail_enabled, active
        from identities
        where domain = $1 and local_part = $2 and active = true and visibility = 'public'
        limit 1
      `,
      [domain, localPart],
    )

    const row = result.rows[0]
    return row ? toIdentity(row) : null
  }

  async findMailEnabledIdentities(domain: string, localParts: string[]): Promise<Map<string, UserIdentity>> {
    if (localParts.length === 0) return new Map()

    const result = await this.pool.query<IdentityRow>(
      `
        select domain, local_part, pubkey, relays, visibility, mail_enabled, active
        from identities
        where domain = $1 and local_part = any($2::text[]) and active = true and mail_enabled = true
      `,
      [domain, localParts],
    )

    return new Map(result.rows.map((row) => [row.local_part, toIdentity(row)]))
  }

  async close(): Promise<void> {
    await this.pool.end()
  }
}

function toIdentity(row: IdentityRow): UserIdentity {
  const relays = Array.isArray(row.relays) ? row.relays.filter((relay): relay is string => typeof relay === 'string') : []

  return {
    domain: row.domain,
    localPart: row.local_part,
    pubkey: row.pubkey,
    relays,
    visibility: row.visibility,
    mailEnabled: row.mail_enabled,
    active: row.active,
  }
}
