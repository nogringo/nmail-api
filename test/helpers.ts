import { DEFAULT_PLANS, FREE_PLAN } from '../src/policy.js'
import type {
  Account,
  AccountInput,
  AccountRepository,
  AdminIdentity,
  DomainRepository,
  IdentityInput,
  IdentityRepository,
  IdentityVisibility,
  OutboundSendCounts,
  Plan,
  PlanLimits,
  PolicyRepository,
  PushSubscriptionInput,
  PushSubscriptionRepository,
  PushTransportType,
  RoleMessage,
  RoleMessageInput,
  RoleMessageRepository,
  RoleMessageSummary,
  UserIdentity,
} from '../src/types.js'

interface SendEntry {
  pubkey: string
  giftWrapId?: string
  at: number
}

export class MemoryIdentityRepository
  implements
    IdentityRepository,
    AccountRepository,
    PolicyRepository,
    DomainRepository,
    RoleMessageRepository,
    PushSubscriptionRepository
{
  readonly identities = new Map<string, AdminIdentity>()
  readonly accounts = new Map<string, Account>()
  readonly plans = new Map<string, Plan>(DEFAULT_PLANS.map((plan) => [plan.name, { ...plan }]))
  readonly domains = new Set<string>()
  readonly sends: SendEntry[] = []
  readonly roleMessages: RoleMessage[] = []
  readonly pushSubscriptions = new Map<string, PushSubscriptionInput>()
  fail = false
  private nextId = 1

  add(identity: UserIdentity): void {
    this.ensureAccount(identity.pubkey)
    this.domains.add(identity.domain)
    this.identities.set(key(identity.domain, identity.localPart), toAdminIdentity(String(this.nextId++), identity))
  }

  setAccount(pubkey: string, overrides: Partial<AccountInput> = {}): Account {
    const account: Account = {
      pubkey,
      active: overrides.active ?? true,
      mailEnabled: overrides.mailEnabled ?? true,
      plan: overrides.plan ?? null,
      relays: overrides.relays ?? [],
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    }
    this.accounts.set(pubkey, account)
    return account
  }

  async findIdentity(domain: string, localPart: string): Promise<UserIdentity | null> {
    if (this.fail) throw new Error('database unavailable')

    return this.identities.get(key(domain, localPart)) ?? null
  }

  async listIdentitiesByPubkey(pubkey: string): Promise<UserIdentity[]> {
    if (this.fail) throw new Error('database unavailable')

    return [...this.identities.values()].filter((identity) => identity.pubkey === pubkey)
  }

  async findPublicIdentity(domain: string, localPart: string): Promise<UserIdentity | null> {
    if (this.fail) throw new Error('database unavailable')

    const identity = this.identities.get(key(domain, localPart))
    if (!identity || identity.visibility !== 'public') return null

    const account = this.accounts.get(identity.pubkey)
    return !account || account.active ? identity : null
  }

  async listIdentities(search = ''): Promise<AdminIdentity[]> {
    const normalizedSearch = search.trim().toLowerCase()
    return [...this.identities.values()]
      .filter(
        (identity) =>
          !normalizedSearch ||
          identity.domain.includes(normalizedSearch) ||
          identity.localPart.includes(normalizedSearch) ||
          identity.pubkey.includes(normalizedSearch),
      )
      .sort((left, right) => `${left.domain}:${left.localPart}`.localeCompare(`${right.domain}:${right.localPart}`))
  }

  async createIdentity(input: IdentityInput): Promise<AdminIdentity> {
    const identity = toAdminIdentity(String(this.nextId++), input)
    const identityKey = key(identity.domain, identity.localPart)
    if (this.identities.has(identityKey)) {
      throw Object.assign(new Error('duplicate'), { code: '23505', constraint: 'identities_unique_name' })
    }

    this.ensureAccount(input.pubkey)
    this.identities.set(identityKey, identity)
    return identity
  }

  async updateIdentity(id: string, input: IdentityInput): Promise<AdminIdentity | null> {
    const current = this.findById(id)
    if (!current) return null

    const next = { ...toAdminIdentity(id, input), createdAt: current.createdAt }
    const oldKey = key(current.domain, current.localPart)
    const newKey = key(next.domain, next.localPart)
    const duplicate = this.identities.get(newKey)
    if (duplicate && duplicate.id !== id) {
      throw Object.assign(new Error('duplicate'), { code: '23505', constraint: 'identities_unique_name' })
    }

    this.ensureAccount(input.pubkey)
    this.identities.delete(oldKey)
    this.identities.set(newKey, next)
    return next
  }

  async deleteIdentity(id: string): Promise<boolean> {
    const current = this.findById(id)
    if (!current) return false

    this.identities.delete(key(current.domain, current.localPart))
    return true
  }

  async setIdentityVisibility(
    domain: string,
    localPart: string,
    pubkey: string,
    visibility: IdentityVisibility,
  ): Promise<UserIdentity | null> {
    if (this.fail) throw new Error('database unavailable')

    const current = this.identities.get(key(domain, localPart))
    if (!current || current.pubkey !== pubkey) return null

    const next = { ...current, visibility, updatedAt: new Date().toISOString() }
    this.identities.set(key(domain, localPart), next)
    return { domain: next.domain, localPart: next.localPart, pubkey: next.pubkey, visibility: next.visibility }
  }

  async deleteIdentityByName(domain: string, localPart: string): Promise<boolean> {
    if (this.fail) throw new Error('database unavailable')

    return this.identities.delete(key(domain, localPart))
  }

  async getAccount(pubkey: string): Promise<Account | null> {
    if (this.fail) throw new Error('database unavailable')

    return this.accounts.get(pubkey) ?? null
  }

  async getOrCreateAccount(pubkey: string): Promise<Account> {
    if (this.fail) throw new Error('database unavailable')

    return this.accounts.get(pubkey) ?? this.ensureAccount(pubkey)
  }

  async listAccounts(search = ''): Promise<Account[]> {
    const normalizedSearch = search.trim().toLowerCase()
    return [...this.accounts.values()]
      .filter((account) => !normalizedSearch || account.pubkey.includes(normalizedSearch) || (account.plan ?? '').includes(normalizedSearch))
      .map((account) => ({ ...account }))
  }

  async upsertAccount(pubkey: string, input: AccountInput): Promise<Account> {
    return this.setAccount(pubkey, input)
  }

  async deleteAccount(pubkey: string): Promise<boolean> {
    return this.accounts.delete(pubkey)
  }

  async getPlan(name: string | null): Promise<Plan> {
    if (this.fail) throw new Error('database unavailable')

    if (name) {
      const plan = this.plans.get(name)
      if (plan) return { ...plan }
    }

    const fallback = [...this.plans.values()].find((plan) => plan.isDefault)
    return fallback ? { ...fallback } : { ...FREE_PLAN }
  }

  async countOutboundSends(pubkey: string): Promise<OutboundSendCounts> {
    if (this.fail) throw new Error('database unavailable')

    const now = Date.now()
    const within = (windowMs: number) =>
      this.sends.filter((entry) => entry.pubkey === pubkey && now - entry.at < windowMs).length

    return {
      minute: within(60 * 1000),
      hour: within(60 * 60 * 1000),
      day: within(24 * 60 * 60 * 1000),
    }
  }

  async recordOutboundSend(pubkey: string, giftWrapId?: string): Promise<void> {
    if (this.fail) throw new Error('database unavailable')

    if (giftWrapId && this.sends.some((entry) => entry.giftWrapId === giftWrapId)) return
    this.sends.push({ pubkey, giftWrapId, at: Date.now() })
  }

  async hasOutboundSend(giftWrapId: string): Promise<boolean> {
    if (this.fail) throw new Error('database unavailable')

    return this.sends.some((entry) => entry.giftWrapId === giftWrapId)
  }

  async listPlans(): Promise<Plan[]> {
    return [...this.plans.values()]
      .map((plan) => ({ ...plan }))
      .sort((left, right) => Number(right.isDefault) - Number(left.isDefault) || left.name.localeCompare(right.name))
  }

  async upsertPlan(name: string, limits: PlanLimits, isDefault: boolean): Promise<Plan> {
    if (isDefault) {
      for (const [planName, plan] of this.plans) {
        if (planName !== name && plan.isDefault) this.plans.set(planName, { ...plan, isDefault: false })
      }
    }

    const plan: Plan = { name, ...limits, isDefault }
    this.plans.set(name, plan)
    return { ...plan }
  }

  async deletePlan(name: string): Promise<boolean> {
    const plan = this.plans.get(name)
    if (!plan || plan.isDefault) return false
    return this.plans.delete(name)
  }

  async listDomains(): Promise<string[]> {
    if (this.fail) throw new Error('database unavailable')

    return [...this.domains].sort()
  }

  async addDomain(domain: string): Promise<string> {
    this.domains.add(domain)
    return domain
  }

  async deleteDomain(domain: string): Promise<boolean> {
    return this.domains.delete(domain)
  }

  async recordRoleMessage(input: RoleMessageInput): Promise<void> {
    if (this.fail) throw new Error('database unavailable')

    if (this.roleHashes.has(input.contentHash)) return
    this.roleHashes.add(input.contentHash)
    this.roleMessages.push({
      id: String(this.nextId++),
      recipient: input.recipient,
      sender: input.sender,
      from: input.from,
      subject: input.subject,
      headers: input.headers,
      bodyMime: input.bodyMime,
      receivedAt: new Date().toISOString(),
    })
  }

  async listRoleMessages(search = ''): Promise<RoleMessageSummary[]> {
    const normalizedSearch = search.trim().toLowerCase()
    return this.roleMessages
      .filter(
        (message) =>
          !normalizedSearch ||
          message.recipient.includes(normalizedSearch) ||
          message.sender.includes(normalizedSearch) ||
          message.subject.toLowerCase().includes(normalizedSearch),
      )
      .map(({ headers: _headers, bodyMime: _bodyMime, ...summary }) => summary)
  }

  async getRoleMessage(id: string): Promise<RoleMessage | null> {
    return this.roleMessages.find((message) => message.id === id) ?? null
  }

  async deleteRoleMessage(id: string): Promise<boolean> {
    const index = this.roleMessages.findIndex((message) => message.id === id)
    if (index === -1) return false
    this.roleMessages.splice(index, 1)
    return true
  }

  async upsertPushSubscription(input: PushSubscriptionInput): Promise<void> {
    if (this.fail) throw new Error('database unavailable')

    this.ensureAccount(input.pubkey)
    this.pushSubscriptions.set(pushKey(input.pubkey, input.transport, input.destination), {
      pubkey: input.pubkey,
      transport: input.transport,
      destination: input.destination,
      p256dh: input.p256dh ?? null,
      auth: input.auth ?? null,
      instance: input.instance ?? null,
    })
  }

  async deletePushSubscription(pubkey: string, transport: PushTransportType, destination: string): Promise<boolean> {
    if (this.fail) throw new Error('database unavailable')

    return this.pushSubscriptions.delete(pushKey(pubkey, transport, destination))
  }

  private readonly roleHashes = new Set<string>()

  private ensureAccount(pubkey: string): Account {
    const existing = this.accounts.get(pubkey)
    if (existing) return existing
    return this.setAccount(pubkey)
  }

  private findById(id: string): AdminIdentity | null {
    return [...this.identities.values()].find((identity) => identity.id === id) ?? null
  }
}

export function identity(overrides: Partial<UserIdentity> = {}): UserIdentity {
  return {
    domain: 'nmail.li',
    localPart: 'alice',
    pubkey: '0'.repeat(64),
    visibility: 'public',
    ...overrides,
  }
}

function key(domain: string, localPart: string): string {
  return `${domain}:${localPart}`
}

function pushKey(pubkey: string, transport: PushTransportType, destination: string): string {
  return `${pubkey}:${transport}:${destination}`
}

function toAdminIdentity(id: string, identity: UserIdentity): AdminIdentity {
  const now = new Date().toISOString()
  return {
    id,
    domain: identity.domain,
    localPart: identity.localPart,
    pubkey: identity.pubkey,
    visibility: identity.visibility,
    createdAt: now,
    updatedAt: now,
  }
}
