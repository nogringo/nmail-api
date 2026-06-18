import type { IdentityRepository, UserIdentity } from '../src/types.js'

export class MemoryIdentityRepository implements IdentityRepository {
  readonly identities = new Map<string, UserIdentity>()
  fail = false

  add(identity: UserIdentity): void {
    this.identities.set(key(identity.domain, identity.localPart), identity)
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
