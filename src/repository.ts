import pg from 'pg'
import type { AdminIdentity, IdentityInput, IdentityRepository, IdentityVisibility, UserIdentity } from './types.js'

const { Pool } = pg

interface IdentityRow {
  id?: string
  domain: string
  local_part: string
  pubkey: string
  relays: unknown
  visibility: IdentityVisibility
  mail_enabled: boolean
  active: boolean
  created_at?: Date | string
  updated_at?: Date | string
}

export class PgIdentityRepository implements IdentityRepository {
  private readonly pool: pg.Pool

  constructor(databaseUrl: string) {
    this.pool = new Pool({ connectionString: databaseUrl })
  }

  async findIdentity(domain: string, localPart: string): Promise<UserIdentity | null> {
    const result = await this.pool.query<IdentityRow>(
      `
        select domain, local_part, pubkey, relays, visibility, mail_enabled, active
        from identities
        where domain = $1 and local_part = $2
        limit 1
      `,
      [domain, localPart],
    )

    const row = result.rows[0]
    return row ? toIdentity(row) : null
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

  async findMailEnabledIdentitiesByPubkeys(domain: string, pubkeys: string[]): Promise<Map<string, UserIdentity>> {
    if (pubkeys.length === 0) return new Map()

    const result = await this.pool.query<IdentityRow>(
      `
        select domain, local_part, pubkey, relays, visibility, mail_enabled, active
        from identities
        where domain = $1 and pubkey = any($2::text[]) and active = true and mail_enabled = true
      `,
      [domain, pubkeys],
    )

    return new Map(result.rows.map((row) => [row.pubkey, toIdentity(row)]))
  }

  async listIdentities(search = ''): Promise<AdminIdentity[]> {
    const normalizedSearch = search.trim().toLowerCase()
    const result = normalizedSearch
      ? await this.pool.query<IdentityRow>(
          `
            select id, domain, local_part, pubkey, relays, visibility, mail_enabled, active, created_at, updated_at
            from identities
            where domain like $1 or local_part like $1 or pubkey like $1
            order by domain asc, local_part asc
            limit 200
          `,
          [`%${normalizedSearch}%`],
        )
      : await this.pool.query<IdentityRow>(
          `
            select id, domain, local_part, pubkey, relays, visibility, mail_enabled, active, created_at, updated_at
            from identities
            order by domain asc, local_part asc
            limit 200
          `,
        )

    return result.rows.map(toAdminIdentity)
  }

  async createIdentity(identity: IdentityInput): Promise<AdminIdentity> {
    const result = await this.pool.query<IdentityRow>(
      `
        insert into identities (domain, local_part, pubkey, relays, visibility, mail_enabled, active)
        values ($1, $2, $3, $4::jsonb, $5, $6, $7)
        returning id, domain, local_part, pubkey, relays, visibility, mail_enabled, active, created_at, updated_at
      `,
      [
        identity.domain,
        identity.localPart,
        identity.pubkey,
        JSON.stringify(identity.relays),
        identity.visibility,
        identity.mailEnabled,
        identity.active,
      ],
    )

    return toAdminIdentity(result.rows[0])
  }

  async updateIdentity(id: string, identity: IdentityInput): Promise<AdminIdentity | null> {
    const result = await this.pool.query<IdentityRow>(
      `
        update identities
        set domain = $2,
            local_part = $3,
            pubkey = $4,
            relays = $5::jsonb,
            visibility = $6,
            mail_enabled = $7,
            active = $8,
            updated_at = now()
        where id = $1
        returning id, domain, local_part, pubkey, relays, visibility, mail_enabled, active, created_at, updated_at
      `,
      [
        id,
        identity.domain,
        identity.localPart,
        identity.pubkey,
        JSON.stringify(identity.relays),
        identity.visibility,
        identity.mailEnabled,
        identity.active,
      ],
    )

    const row = result.rows[0]
    return row ? toAdminIdentity(row) : null
  }

  async setIdentityActive(id: string, active: boolean): Promise<AdminIdentity | null> {
    const result = await this.pool.query<IdentityRow>(
      `
        update identities
        set active = $2,
            updated_at = now()
        where id = $1
        returning id, domain, local_part, pubkey, relays, visibility, mail_enabled, active, created_at, updated_at
      `,
      [id, active],
    )

    const row = result.rows[0]
    return row ? toAdminIdentity(row) : null
  }

  async deleteIdentity(id: string): Promise<boolean> {
    const result = await this.pool.query('delete from identities where id = $1', [id])
    return (result.rowCount ?? 0) > 0
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

function toAdminIdentity(row: IdentityRow): AdminIdentity {
  return {
    id: String(row.id),
    ...toIdentity(row),
    createdAt: toIsoString(row.created_at),
    updatedAt: toIsoString(row.updated_at),
  }
}

function toIsoString(value: Date | string | undefined): string {
  if (value instanceof Date) return value.toISOString()
  return value ?? ''
}
