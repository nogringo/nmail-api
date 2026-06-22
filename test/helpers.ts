import { DEFAULT_PLANS, FREE_PLAN } from '../src/policy.js'
import type {
  AdminIdentity,
  IdentityInput,
  IdentityRepository,
  OutboundSendCounts,
  Plan,
  PlanLimits,
  PolicyRepository,
  PubkeyPlan,
  UserIdentity,
} from '../src/types.js'

interface SendEntry {
  pubkey: string
  giftWrapId?: string
  at: number
}

export class MemoryIdentityRepository implements IdentityRepository, PolicyRepository {
  readonly identities = new Map<string, AdminIdentity>()
  readonly plans = new Map<string, Plan>(DEFAULT_PLANS.map((plan) => [plan.name, { ...plan }]))
  readonly pubkeyPlans = new Map<string, PubkeyPlan>()
  readonly sends: SendEntry[] = []
  fail = false
  private nextId = 1

  add(identity: UserIdentity): void {
    this.identities.set(
      key(identity.domain, identity.localPart),
      toAdminIdentity(String(this.nextId++), identity),
    )
  }

  async findIdentity(domain: string, localPart: string): Promise<UserIdentity | null> {
    if (this.fail) throw new Error('database unavailable')

    return this.identities.get(key(domain, localPart)) ?? null
  }

  async findPublicIdentity(domain: string, localPart: string): Promise<UserIdentity | null> {
    if (this.fail) throw new Error('database unavailable')

    const identity = this.identities.get(key(domain, localPart))
    return identity?.active && identity.visibility === 'public' ? identity : null
  }

  async findMailEnabledIdentities(domain: string, localParts: string[]): Promise<Map<string, UserIdentity>> {
    if (this.fail) throw new Error('database unavailable')

    const found = new Map<string, UserIdentity>()
    for (const localPart of localParts) {
      const identity = this.identities.get(key(domain, localPart))
      if (identity?.active && identity.mailEnabled) found.set(localPart, identity)
    }

    return found
  }

  async findMailEnabledIdentitiesByPubkeys(domain: string, pubkeys: string[]): Promise<Map<string, UserIdentity>> {
    if (this.fail) throw new Error('database unavailable')

    const requiredPubkeys = new Set(pubkeys)
    const found = new Map<string, UserIdentity>()

    for (const identity of this.identities.values()) {
      if (identity.domain === domain && requiredPubkeys.has(identity.pubkey) && identity.active && identity.mailEnabled) {
        found.set(identity.pubkey, identity)
      }
    }

    return found
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

    this.identities.delete(oldKey)
    this.identities.set(newKey, next)
    return next
  }

  async setIdentityActive(id: string, active: boolean): Promise<AdminIdentity | null> {
    const current = this.findById(id)
    if (!current) return null

    const next = { ...current, active, updatedAt: new Date().toISOString() }
    this.identities.set(key(next.domain, next.localPart), next)
    return next
  }

  async deleteIdentity(id: string): Promise<boolean> {
    const current = this.findById(id)
    if (!current) return false

    this.identities.delete(key(current.domain, current.localPart))
    return true
  }

  async getPlanForPubkey(pubkey: string): Promise<Plan> {
    if (this.fail) throw new Error('database unavailable')

    const assigned = this.pubkeyPlans.get(pubkey)
    if (assigned) {
      const plan = this.plans.get(assigned.plan)
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

  async getPubkeyPlan(pubkey: string): Promise<string | null> {
    return this.pubkeyPlans.get(pubkey)?.plan ?? null
  }

  async setPubkeyPlan(pubkey: string, planName: string): Promise<PubkeyPlan | null> {
    const entry: PubkeyPlan = { pubkey, plan: planName, updatedAt: new Date().toISOString() }
    this.pubkeyPlans.set(pubkey, entry)
    return { ...entry }
  }

  async clearPubkeyPlan(pubkey: string): Promise<boolean> {
    return this.pubkeyPlans.delete(pubkey)
  }

  async listPubkeyPlans(search = ''): Promise<PubkeyPlan[]> {
    const normalizedSearch = search.trim().toLowerCase()
    return [...this.pubkeyPlans.values()]
      .filter((entry) => !normalizedSearch || entry.pubkey.includes(normalizedSearch) || entry.plan.includes(normalizedSearch))
      .map((entry) => ({ ...entry }))
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
    relays: ['wss://relay.damus.io'],
    visibility: 'public',
    mailEnabled: true,
    active: true,
    ...overrides,
  }
}

function key(domain: string, localPart: string): string {
  return `${domain}:${localPart}`
}

function toAdminIdentity(id: string, identity: UserIdentity): AdminIdentity {
  const now = new Date().toISOString()
  return {
    ...identity,
    id,
    createdAt: now,
    updatedAt: now,
  }
}
