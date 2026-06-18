import type { AdminIdentity, IdentityInput, IdentityRepository, UserIdentity } from '../src/types.js'

export class MemoryIdentityRepository implements IdentityRepository {
  readonly identities = new Map<string, AdminIdentity>()
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
