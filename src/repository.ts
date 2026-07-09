import pg from 'pg'
import { FREE_PLAN } from './policy.js'
import type {
  Account,
  AccountInput,
  AccountRepository,
  AdminIdentity,
  DomainRepository,
  IdentityInput,
  IdentityRepository,
  IdentityVisibility,
  InboundNotificationRepository,
  OutboundSendCounts,
  Plan,
  PlanLimits,
  PolicyRepository,
  PushSubscriptionInput,
  PushSubscription,
  PushSubscriptionRepository,
  PushTransportType,
  RoleMessage,
  RoleMessageInput,
  RoleMessageRepository,
  RoleMessageSummary,
  UserIdentity,
} from './types.js'

const { Pool } = pg

interface IdentityRow {
  id?: string
  domain: string
  local_part: string
  pubkey: string
  visibility: IdentityVisibility
  created_at?: Date | string
  updated_at?: Date | string
}

interface AccountRow {
  pubkey: string
  active: boolean
  mail_enabled: boolean
  plan: string | null
  relays: unknown
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
  max_aliases: number | string
  allowed_domains: unknown
  is_default: boolean
  created_at?: Date | string
  updated_at?: Date | string
}

interface SendCountsRow {
  per_minute: number | string
  per_hour: number | string
  per_day: number | string
}

interface RoleMessageRow {
  id: number | string
  recipient: string
  sender: string
  from_addr: string
  subject: string
  headers?: unknown
  body_mime?: string
  received_at?: Date | string
}

interface PushSubscriptionRow {
  pubkey: string
  transport: PushTransportType
  destination: string
  p256dh: string | null
  auth: string | null
  instance: string | null
}

export class PgIdentityRepository
  implements
    IdentityRepository,
    AccountRepository,
    PolicyRepository,
    DomainRepository,
    RoleMessageRepository,
    InboundNotificationRepository,
    PushSubscriptionRepository
{
  private readonly pool: pg.Pool

  constructor(databaseUrl: string) {
    this.pool = new Pool({ connectionString: databaseUrl })
  }

  async findIdentity(domain: string, localPart: string): Promise<UserIdentity | null> {
    const result = await this.pool.query<IdentityRow>(
      `
        select domain, local_part, pubkey, visibility
        from identities
        where domain = $1 and local_part = $2
        limit 1
      `,
      [domain, localPart],
    )

    const row = result.rows[0]
    return row ? toIdentity(row) : null
  }

  async listIdentitiesByPubkey(pubkey: string): Promise<UserIdentity[]> {
    const result = await this.pool.query<IdentityRow>(
      `
        select domain, local_part, pubkey, visibility
        from identities
        where pubkey = $1
      `,
      [pubkey],
    )

    return result.rows.map(toIdentity)
  }

  async findPublicIdentity(domain: string, localPart: string): Promise<UserIdentity | null> {
    const result = await this.pool.query<IdentityRow>(
      `
        select i.domain, i.local_part, i.pubkey, i.visibility
        from identities i
        left join accounts a on a.pubkey = i.pubkey
        where i.domain = $1 and i.local_part = $2 and i.visibility = 'public'
          and coalesce(a.active, true) = true
        limit 1
      `,
      [domain, localPart],
    )

    const row = result.rows[0]
    return row ? toIdentity(row) : null
  }

  async listIdentities(search = ''): Promise<AdminIdentity[]> {
    const normalizedSearch = search.trim().toLowerCase()
    const result = normalizedSearch
      ? await this.pool.query<IdentityRow>(
          `
            select id, domain, local_part, pubkey, visibility, created_at, updated_at
            from identities
            where domain like $1 or local_part like $1 or pubkey like $1
            order by domain asc, local_part asc
            limit 200
          `,
          [`%${normalizedSearch}%`],
        )
      : await this.pool.query<IdentityRow>(
          `
            select id, domain, local_part, pubkey, visibility, created_at, updated_at
            from identities
            order by domain asc, local_part asc
            limit 200
          `,
        )

    return result.rows.map(toAdminIdentity)
  }

  async createIdentity(identity: IdentityInput): Promise<AdminIdentity> {
    const client = await this.pool.connect()
    try {
      await client.query('begin')
      await client.query('insert into accounts (pubkey) values ($1) on conflict (pubkey) do nothing', [identity.pubkey])
      const result = await client.query<IdentityRow>(
        `
          insert into identities (domain, local_part, pubkey, visibility)
          values ($1, $2, $3, $4)
          returning id, domain, local_part, pubkey, visibility, created_at, updated_at
        `,
        [identity.domain, identity.localPart, identity.pubkey, identity.visibility],
      )
      await client.query('commit')
      return toAdminIdentity(result.rows[0])
    } catch (error) {
      await client.query('rollback')
      throw error
    } finally {
      client.release()
    }
  }

  async updateIdentity(id: string, identity: IdentityInput): Promise<AdminIdentity | null> {
    const client = await this.pool.connect()
    try {
      await client.query('begin')
      await client.query('insert into accounts (pubkey) values ($1) on conflict (pubkey) do nothing', [identity.pubkey])
      const result = await client.query<IdentityRow>(
        `
          update identities
          set domain = $2,
              local_part = $3,
              pubkey = $4,
              visibility = $5,
              updated_at = now()
          where id = $1
          returning id, domain, local_part, pubkey, visibility, created_at, updated_at
        `,
        [id, identity.domain, identity.localPart, identity.pubkey, identity.visibility],
      )
      await client.query('commit')
      const row = result.rows[0]
      return row ? toAdminIdentity(row) : null
    } catch (error) {
      await client.query('rollback')
      throw error
    } finally {
      client.release()
    }
  }

  async deleteIdentity(id: string): Promise<boolean> {
    const result = await this.pool.query('delete from identities where id = $1', [id])
    return (result.rowCount ?? 0) > 0
  }

  async setIdentityVisibility(
    domain: string,
    localPart: string,
    pubkey: string,
    visibility: IdentityVisibility,
  ): Promise<UserIdentity | null> {
    const result = await this.pool.query<IdentityRow>(
      `
        update identities
        set visibility = $4, updated_at = now()
        where domain = $1 and local_part = $2 and pubkey = $3
        returning domain, local_part, pubkey, visibility
      `,
      [domain, localPart, pubkey, visibility],
    )

    const row = result.rows[0]
    return row ? toIdentity(row) : null
  }

  async deleteIdentityByName(domain: string, localPart: string): Promise<boolean> {
    const result = await this.pool.query('delete from identities where domain = $1 and local_part = $2', [domain, localPart])
    return (result.rowCount ?? 0) > 0
  }

  async getAccount(pubkey: string): Promise<Account | null> {
    const result = await this.pool.query<AccountRow>(
      `
        select pubkey, active, mail_enabled, plan, relays, created_at, updated_at
        from accounts
        where pubkey = $1
        limit 1
      `,
      [pubkey],
    )

    const row = result.rows[0]
    return row ? toAccount(row) : null
  }

  async getOrCreateAccount(pubkey: string): Promise<Account> {
    const result = await this.pool.query<AccountRow>(
      `
        insert into accounts (pubkey)
        values ($1)
        on conflict (pubkey) do update set pubkey = excluded.pubkey
        returning pubkey, active, mail_enabled, plan, relays, created_at, updated_at
      `,
      [pubkey],
    )

    return toAccount(result.rows[0])
  }

  async listAccounts(search = ''): Promise<Account[]> {
    const normalizedSearch = search.trim().toLowerCase()
    const result = normalizedSearch
      ? await this.pool.query<AccountRow>(
          `
            select pubkey, active, mail_enabled, plan, relays, created_at, updated_at
            from accounts
            where pubkey like $1 or coalesce(plan, '') like $1
            order by updated_at desc
            limit 200
          `,
          [`%${normalizedSearch}%`],
        )
      : await this.pool.query<AccountRow>(
          `
            select pubkey, active, mail_enabled, plan, relays, created_at, updated_at
            from accounts
            order by updated_at desc
            limit 200
          `,
        )

    return result.rows.map(toAccount)
  }

  async upsertAccount(pubkey: string, input: AccountInput): Promise<Account> {
    const result = await this.pool.query<AccountRow>(
      `
        insert into accounts (pubkey, active, mail_enabled, plan, relays)
        values ($1, $2, $3, $4, $5::jsonb)
        on conflict (pubkey) do update set
          active = excluded.active,
          mail_enabled = excluded.mail_enabled,
          plan = excluded.plan,
          relays = excluded.relays,
          updated_at = now()
        returning pubkey, active, mail_enabled, plan, relays, created_at, updated_at
      `,
      [pubkey, input.active, input.mailEnabled, input.plan, JSON.stringify(input.relays)],
    )

    return toAccount(result.rows[0])
  }

  async deleteAccount(pubkey: string): Promise<boolean> {
    const result = await this.pool.query('delete from accounts where pubkey = $1', [pubkey])
    return (result.rowCount ?? 0) > 0
  }

  async getPlan(name: string | null): Promise<Plan> {
    if (name) {
      const named = await this.pool.query<PlanRow>(
        `
          select name, per_minute, per_hour, per_day, max_message_bytes, max_recipients, max_aliases, allowed_domains, is_default
          from plans where name = $1 limit 1
        `,
        [name],
      )
      if (named.rows[0]) return toPlan(named.rows[0])
    }

    const fallback = await this.pool.query<PlanRow>(
      `
        select name, per_minute, per_hour, per_day, max_message_bytes, max_recipients, max_aliases, allowed_domains, is_default
        from plans where is_default = true limit 1
      `,
    )

    return fallback.rows[0] ? toPlan(fallback.rows[0]) : FREE_PLAN
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
        on conflict (gift_wrap_id) where gift_wrap_id is not null do nothing
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
        select name, per_minute, per_hour, per_day, max_message_bytes, max_recipients, max_aliases, allowed_domains, is_default, created_at, updated_at
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
          insert into plans (name, per_minute, per_hour, per_day, max_message_bytes, max_recipients, max_aliases, allowed_domains, is_default)
          values ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9)
          on conflict (name) do update set
            per_minute = excluded.per_minute,
            per_hour = excluded.per_hour,
            per_day = excluded.per_day,
            max_message_bytes = excluded.max_message_bytes,
            max_recipients = excluded.max_recipients,
            max_aliases = excluded.max_aliases,
            allowed_domains = excluded.allowed_domains,
            is_default = excluded.is_default,
            updated_at = now()
          returning name, per_minute, per_hour, per_day, max_message_bytes, max_recipients, max_aliases, allowed_domains, is_default, created_at, updated_at
        `,
        [
          name,
          limits.perMinute,
          limits.perHour,
          limits.perDay,
          limits.maxMessageBytes,
          limits.maxRecipients,
          limits.maxAliases,
          JSON.stringify(limits.allowedDomains),
          isDefault,
        ],
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

  async listDomains(): Promise<string[]> {
    const result = await this.pool.query<{ domain: string }>('select domain from domains order by domain asc')
    return result.rows.map((row) => row.domain)
  }

  async addDomain(domain: string): Promise<string> {
    await this.pool.query('insert into domains (domain) values ($1) on conflict (domain) do nothing', [domain])
    return domain
  }

  async deleteDomain(domain: string): Promise<boolean> {
    const result = await this.pool.query('delete from domains where domain = $1', [domain])
    return (result.rowCount ?? 0) > 0
  }

  async recordRoleMessage(input: RoleMessageInput): Promise<void> {
    await this.pool.query(
      `
        insert into role_messages (recipient, sender, from_addr, subject, headers, body_mime, content_hash)
        values ($1, $2, $3, $4, $5::jsonb, $6, $7)
        on conflict (content_hash) do nothing
      `,
      [input.recipient, input.sender, input.from, input.subject, JSON.stringify(input.headers ?? []), input.bodyMime, input.contentHash],
    )
  }

  async listRoleMessages(search = ''): Promise<RoleMessageSummary[]> {
    const normalizedSearch = search.trim().toLowerCase()
    const result = normalizedSearch
      ? await this.pool.query<RoleMessageRow>(
          `
            select id, recipient, sender, from_addr, subject, received_at
            from role_messages
            where recipient like $1 or sender like $1 or subject like $1
            order by received_at desc
            limit 200
          `,
          [`%${normalizedSearch}%`],
        )
      : await this.pool.query<RoleMessageRow>(
          `
            select id, recipient, sender, from_addr, subject, received_at
            from role_messages
            order by received_at desc
            limit 200
          `,
        )

    return result.rows.map(toRoleMessageSummary)
  }

  async getRoleMessage(id: string): Promise<RoleMessage | null> {
    if (!/^\d+$/.test(id)) return null
    const result = await this.pool.query<RoleMessageRow>(
      `
        select id, recipient, sender, from_addr, subject, headers, body_mime, received_at
        from role_messages
        where id = $1
        limit 1
      `,
      [id],
    )

    const row = result.rows[0]
    return row ? toRoleMessage(row) : null
  }

  async deleteRoleMessage(id: string): Promise<boolean> {
    if (!/^\d+$/.test(id)) return false
    const result = await this.pool.query('delete from role_messages where id = $1', [id])
    return (result.rowCount ?? 0) > 0
  }

  async upsertPushSubscription(input: PushSubscriptionInput): Promise<void> {
    const client = await this.pool.connect()
    try {
      await client.query('begin')
      await client.query('insert into accounts (pubkey) values ($1) on conflict (pubkey) do nothing', [input.pubkey])
      await client.query(
        `
          insert into push_subscriptions (pubkey, transport, destination, p256dh, auth, instance)
          values ($1, $2, $3, $4, $5, $6)
          on conflict (pubkey, transport, destination) do update set
            p256dh = excluded.p256dh,
            auth = excluded.auth,
            instance = excluded.instance
        `,
        [
          input.pubkey,
          input.transport,
          input.destination,
          input.p256dh ?? null,
          input.auth ?? null,
          input.instance ?? null,
        ],
      )
      await client.query('commit')
    } catch (error) {
      await client.query('rollback')
      throw error
    } finally {
      client.release()
    }
  }

  async deletePushSubscription(pubkey: string, transport: PushTransportType, destination: string): Promise<boolean> {
    const result = await this.pool.query(
      'delete from push_subscriptions where pubkey = $1 and transport = $2 and destination = $3',
      [pubkey, transport, destination],
    )
    return (result.rowCount ?? 0) > 0
  }

  async listPushSubscriptions(pubkeys: string[]): Promise<PushSubscription[]> {
    if (pubkeys.length === 0) return []

    const result = await this.pool.query<PushSubscriptionRow>(
      `
        select pubkey, transport, destination, p256dh, auth, instance
        from push_subscriptions
        where pubkey = any($1::char(64)[])
        order by pubkey asc, transport asc, destination asc
      `,
      [pubkeys],
    )

    return result.rows.map(toPushSubscription)
  }

  async claimInboundNotificationDelivery(recipientPubkey: string, eventId: string): Promise<boolean> {
    const result = await this.pool.query(
      `
        insert into inbound_notification_deliveries (recipient_pubkey, event_id)
        values ($1, $2)
        on conflict (recipient_pubkey, event_id) do nothing
      `,
      [recipientPubkey, eventId],
    )

    return (result.rowCount ?? 0) > 0
  }

  async releaseInboundNotificationDelivery(recipientPubkey: string, eventId: string): Promise<void> {
    await this.pool.query(
      `
        delete from inbound_notification_deliveries
        where recipient_pubkey = $1 and event_id = $2
      `,
      [recipientPubkey, eventId],
    )
  }

  async close(): Promise<void> {
    await this.pool.end()
  }
}

function toStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === 'string') : []
}

function toPlan(row: PlanRow): Plan {
  return {
    name: row.name,
    perMinute: Number(row.per_minute),
    perHour: Number(row.per_hour),
    perDay: Number(row.per_day),
    maxMessageBytes: Number(row.max_message_bytes),
    maxRecipients: Number(row.max_recipients),
    maxAliases: Number(row.max_aliases),
    allowedDomains: toStringArray(row.allowed_domains),
    isDefault: row.is_default,
    createdAt: toIsoString(row.created_at),
    updatedAt: toIsoString(row.updated_at),
  }
}

function toAccount(row: AccountRow): Account {
  return {
    pubkey: row.pubkey,
    active: row.active,
    mailEnabled: row.mail_enabled,
    plan: row.plan,
    relays: toStringArray(row.relays),
    createdAt: toIsoString(row.created_at),
    updatedAt: toIsoString(row.updated_at),
  }
}

function toIdentity(row: IdentityRow): UserIdentity {
  return {
    domain: row.domain,
    localPart: row.local_part,
    pubkey: row.pubkey,
    visibility: row.visibility,
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

function toRoleMessageSummary(row: RoleMessageRow): RoleMessageSummary {
  return {
    id: String(row.id),
    recipient: row.recipient,
    sender: row.sender,
    from: row.from_addr,
    subject: row.subject,
    receivedAt: toIsoString(row.received_at),
  }
}

function toRoleMessage(row: RoleMessageRow): RoleMessage {
  return {
    ...toRoleMessageSummary(row),
    headers: row.headers ?? [],
    bodyMime: row.body_mime ?? '',
  }
}

function toPushSubscription(row: PushSubscriptionRow): PushSubscription {
  return {
    pubkey: row.pubkey,
    transport: row.transport,
    destination: row.destination,
    p256dh: row.p256dh,
    auth: row.auth,
    instance: row.instance,
  }
}

function toIsoString(value: Date | string | undefined): string {
  if (value instanceof Date) return value.toISOString()
  return value ?? ''
}
