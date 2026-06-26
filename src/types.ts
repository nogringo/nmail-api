export interface AppConfig {
  port: number
  databaseUrl: string
  inboundDecisionToken: string
  outboundDecisionToken?: string
  outboundMaxBodyBytes: number
  adminPassword?: string
  roleWebhookSigningKey?: string
  roleWebhookMaxBodyBytes: number
}

export type IdentityVisibility = 'public' | 'private'

// An account is the user, keyed by its nostr pubkey. It owns everything that is
// a property of the person rather than of a single address.
export interface Account {
  pubkey: string
  active: boolean
  mailEnabled: boolean
  plan: string | null // null means "use the default plan"
  relays: string[]
  createdAt?: string
  updatedAt?: string
}

export interface AccountInput {
  active: boolean
  mailEnabled: boolean
  plan: string | null
  relays: string[]
}

// An identity is a human-readable alias pointing at a pubkey. It only carries
// what is specific to the name itself.
export interface UserIdentity {
  domain: string
  localPart: string
  pubkey: string
  visibility: IdentityVisibility
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
  visibility: IdentityVisibility
}

export interface IdentityRepository {
  findIdentity(domain: string, localPart: string): Promise<UserIdentity | null>
  findPublicIdentity(domain: string, localPart: string): Promise<UserIdentity | null>
  listIdentitiesByPubkey(pubkey: string): Promise<UserIdentity[]>
  listIdentities?(search?: string): Promise<AdminIdentity[]>
  createIdentity?(identity: IdentityInput): Promise<AdminIdentity>
  updateIdentity?(id: string, identity: IdentityInput): Promise<AdminIdentity | null>
  deleteIdentity?(id: string): Promise<boolean>
  setIdentityVisibility?(domain: string, localPart: string, pubkey: string, visibility: IdentityVisibility): Promise<UserIdentity | null>
  deleteIdentityByName?(domain: string, localPart: string): Promise<boolean>
  close?(): Promise<void>
}

export interface DomainRepository {
  listDomains(): Promise<string[]>
  addDomain?(domain: string): Promise<string>
  deleteDomain?(domain: string): Promise<boolean>
}

export interface AccountRepository {
  getAccount(pubkey: string): Promise<Account | null>
  getOrCreateAccount(pubkey: string): Promise<Account>
  listAccounts?(search?: string): Promise<Account[]>
  upsertAccount?(pubkey: string, input: AccountInput): Promise<Account>
  deleteAccount?(pubkey: string): Promise<boolean>
}

export interface PlanLimits {
  perMinute: number
  perHour: number
  perDay: number
  maxMessageBytes: number
  maxRecipients: number
  maxAliases: number
  allowedDomains: string[]
}

export interface Plan extends PlanLimits {
  name: string
  isDefault: boolean
  createdAt?: string
  updatedAt?: string
}

export interface OutboundSendCounts {
  minute: number
  hour: number
  day: number
}

export interface PolicyRepository {
  getPlan(name: string | null): Promise<Plan>
  countOutboundSends(pubkey: string): Promise<OutboundSendCounts>
  recordOutboundSend(pubkey: string, giftWrapId?: string): Promise<void>
  hasOutboundSend(giftWrapId: string): Promise<boolean>
  listPlans?(): Promise<Plan[]>
  upsertPlan?(name: string, limits: PlanLimits, isDefault: boolean): Promise<Plan>
  deletePlan?(name: string): Promise<boolean>
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

export interface OutboundDecisionPayload {
  protocol?: string
  mode?: 'minimal' | 'summary' | 'full'
  giftWrapId?: string
  nostrSender: string
  rumor?: unknown
  headers?: Array<[string, string]>
  rawMime?: string
}

export type OutboundDecisionResponse =
  | { decision: 'allow' }
  | { decision: 'deny'; reason: string; message: string }

export interface Nip05Response {
  names: Record<string, string>
  relays: Record<string, string[]>
}

// Mail addressed to a role mailbox (abuse@, postmaster@, ...) received from the
// haraka-webhook role webhook and stored for the operator to read in /admin.
export interface RoleMessageInput {
  recipient: string
  sender: string
  from: string
  subject: string
  headers: unknown
  bodyMime: string
  contentHash: string
}

export interface RoleMessageSummary {
  id: string
  recipient: string
  sender: string
  from: string
  subject: string
  receivedAt: string
}

export interface RoleMessage extends RoleMessageSummary {
  headers: unknown
  bodyMime: string
}

export interface RoleMessageRepository {
  recordRoleMessage(input: RoleMessageInput): Promise<void>
  listRoleMessages?(search?: string): Promise<RoleMessageSummary[]>
  getRoleMessage?(id: string): Promise<RoleMessage | null>
  deleteRoleMessage?(id: string): Promise<boolean>
}
