import pg from 'pg'
import { FREE_PLAN } from './policy.js'
import type {
  AdminIdentity,
  IdentityInput,
  IdentityRepository,
  IdentityVisibility,
  OutboundSendCounts,
  Plan,
  PlanLimits,
  PolicyRepository,
  PubkeyPlan,
  UserIdentity,
} from './types.js'

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

interface PlanRow {
  name: string
  per_minute: number | string
  per_hour: number | string
  per_day: number | string
  max_message_bytes: number | string
  max_recipients: number | string
  is_default: boolean
  created_at?: Date | string
  updated_at?: Date | string
}

interface SendCountsRow {
  per_minute: number | string
  per_hour: number | string
  per_day: number | string
}

interface PubkeyPlanRow {
  pubkey: string
  plan: string
  updated_at?: Date | string
}

export class PgIdentityRepository implements IdentityRepository, PolicyRepository {
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

  async getPlanForPubkey(pubkey: string): Promise<Plan> {
    const result = await this.pool.query<PlanRow>(
      `
        select p.name, p.per_minute, p.per_hour, p.per_day, p.max_message_bytes, p.max_recipients, p.is_default
        from plans p
        left join pubkey_plans pp on pp.plan = p.name and pp.pubkey = $1
        where pp.pubkey is not null or p.is_default = true
        order by (pp.pubkey is not null) desc
        limit 1
      `,
      [pubkey],
    )

    const row = result.rows[0]
    return row ? toPlan(row) : FREE_PLAN
  }

  async countOutboundSends(pubkey: string): Promise<OutboundSendCounts> {
    const result = await this.pool.query<SendCountsRow>(
      `
        select
          count(*) filter (where created_at > now() - interval '1 minute') as per_minute,
          count(*) filter (where created_at > now() - interval '1 hour') as per_hour,
          count(*) as per_day
        from outbound_sends
        where pubkey = $1 and created_at > now() - interval '1 day'
      `,
      [pubkey],
    )

    const row = result.rows[0]
    return {
      minute: row ? Number(row.per_minute) : 0,
      hour: row ? Number(row.per_hour) : 0,
      day: row ? Number(row.per_day) : 0,
    }
  }

  async recordOutboundSend(pubkey: string, giftWrapId?: string): Promise<void> {
    await this.pool.query(
      `
        insert into outbound_sends (pubkey, gift_wrap_id)
        values ($1, $2)
        on conflict (gift_wrap_id) do nothing
      `,
      [pubkey, giftWrapId ?? null],
    )
  }

  async hasOutboundSend(giftWrapId: string): Promise<boolean> {
    const result = await this.pool.query('select 1 from outbound_sends where gift_wrap_id = $1 limit 1', [giftWrapId])
    return (result.rowCount ?? 0) > 0
  }

  async listPlans(): Promise<Plan[]> {
    const result = await this.pool.query<PlanRow>(
      `
        select name, per_minute, per_hour, per_day, max_message_bytes, max_recipients, is_default, created_at, updated_at
        from plans
        order by is_default desc, name asc
      `,
    )

    return result.rows.map(toPlan)
  }

  async upsertPlan(name: string, limits: PlanLimits, isDefault: boolean): Promise<Plan> {
    const client = await this.pool.connect()
    try {
      await client.query('begin')
      if (isDefault) {
        await client.query('update plans set is_default = false, updated_at = now() where is_default = true and name <> $1', [name])
      }

      const result = await client.query<PlanRow>(
        `
          insert into plans (name, per_minute, per_hour, per_day, max_message_bytes, max_recipients, is_default)
          values ($1, $2, $3, $4, $5, $6, $7)
          on conflict (name) do update set
            per_minute = excluded.per_minute,
            per_hour = excluded.per_hour,
            per_day = excluded.per_day,
            max_message_bytes = excluded.max_message_bytes,
            max_recipients = excluded.max_recipients,
            is_default = excluded.is_default,
            updated_at = now()
          returning name, per_minute, per_hour, per_day, max_message_bytes, max_recipients, is_default, created_at, updated_at
        `,
        [name, limits.perMinute, limits.perHour, limits.perDay, limits.maxMessageBytes, limits.maxRecipients, isDefault],
      )

      await client.query('commit')
      return toPlan(result.rows[0])
    } catch (error) {
      await client.query('rollback')
      throw error
    } finally {
      client.release()
    }
  }

  async deletePlan(name: string): Promise<boolean> {
    const result = await this.pool.query('delete from plans where name = $1 and is_default = false', [name])
    return (result.rowCount ?? 0) > 0
  }

  async getPubkeyPlan(pubkey: string): Promise<string | null> {
    const result = await this.pool.query<PubkeyPlanRow>('select plan from pubkey_plans where pubkey = $1 limit 1', [pubkey])
    return result.rows[0]?.plan ?? null
  }

  async setPubkeyPlan(pubkey: string, planName: string): Promise<PubkeyPlan | null> {
    const result = await this.pool.query<PubkeyPlanRow>(
      `
        insert into pubkey_plans (pubkey, plan)
        values ($1, $2)
        on conflict (pubkey) do update set plan = excluded.plan, updated_at = now()
        returning pubkey, plan, updated_at
      `,
      [pubkey, planName],
    )

    const row = result.rows[0]
    return row ? toPubkeyPlan(row) : null
  }

  async clearPubkeyPlan(pubkey: string): Promise<boolean> {
    const result = await this.pool.query('delete from pubkey_plans where pubkey = $1', [pubkey])
    return (result.rowCount ?? 0) > 0
  }

  async listPubkeyPlans(search = ''): Promise<PubkeyPlan[]> {
    const normalizedSearch = search.trim().toLowerCase()
    const result = normalizedSearch
      ? await this.pool.query<PubkeyPlanRow>(
          `
            select pubkey, plan, updated_at from pubkey_plans
            where pubkey like $1 or plan like $1
            order by updated_at desc
            limit 200
          `,
          [`%${normalizedSearch}%`],
        )
      : await this.pool.query<PubkeyPlanRow>(
          `
            select pubkey, plan, updated_at from pubkey_plans
            order by updated_at desc
            limit 200
          `,
        )

    return result.rows.map(toPubkeyPlan)
  }

  async close(): Promise<void> {
    await this.pool.end()
  }
}

function toPlan(row: PlanRow): Plan {
  return {
    name: row.name,
    perMinute: Number(row.per_minute),
    perHour: Number(row.per_hour),
    perDay: Number(row.per_day),
    maxMessageBytes: Number(row.max_message_bytes),
    maxRecipients: Number(row.max_recipients),
    isDefault: row.is_default,
    createdAt: toIsoString(row.created_at),
    updatedAt: toIsoString(row.updated_at),
  }
}

function toPubkeyPlan(row: PubkeyPlanRow): PubkeyPlan {
  return {
    pubkey: row.pubkey,
    plan: row.plan,
    updatedAt: toIsoString(row.updated_at),
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
