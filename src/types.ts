export interface AppConfig {
  port: number
  databaseUrl: string
  protectedEmailDomains: Set<string>
  inboundDecisionToken: string
  adminPassword?: string
}

export type IdentityVisibility = 'public' | 'private'

export interface UserIdentity {
  domain: string
  localPart: string
  pubkey: string
  relays: string[]
  visibility: IdentityVisibility
  mailEnabled: boolean
  active: boolean
}

export interface AdminIdentity extends UserIdentity {
  id: string
  createdAt: string
  updatedAt: string
}

export interface IdentityInput {
  domain: string
  localPart: string
  pubkey: string
  relays: string[]
  visibility: IdentityVisibility
  mailEnabled: boolean
  active: boolean
}

export interface IdentityRepository {
  findIdentity(domain: string, localPart: string): Promise<UserIdentity | null>
  findPublicIdentity(domain: string, localPart: string): Promise<UserIdentity | null>
  findMailEnabledIdentities(domain: string, localParts: string[]): Promise<Map<string, UserIdentity>>
  findMailEnabledIdentitiesByPubkeys(domain: string, pubkeys: string[]): Promise<Map<string, UserIdentity>>
  listIdentities?(search?: string): Promise<AdminIdentity[]>
  createIdentity?(identity: IdentityInput): Promise<AdminIdentity>
  updateIdentity?(id: string, identity: IdentityInput): Promise<AdminIdentity | null>
  setIdentityActive?(id: string, active: boolean): Promise<AdminIdentity | null>
  deleteIdentity?(id: string): Promise<boolean>
  close?(): Promise<void>
}

export interface InboundDecisionPayload {
  protocol?: string
  mode: 'minimal' | 'summary' | 'full'
  message: {
    id: string
    createdAt: string
    sender: string
    recipients: string[]
    from?: string
    subject?: string
    remote?: {
      ip?: string
      host?: string
      helo?: string
    }
    headers?: Array<[string, string]>
    rawMime?: string
  }
}

export type InboundDecisionResponse =
  | { decision: 'allow' }
  | { decision: 'deny'; reason: string; message: string }
  | { decision: 'silent_deny'; reason: string; message: string }

export interface Nip05Response {
  names: Record<string, string>
  relays: Record<string, string[]>
}
