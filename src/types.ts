export interface AppConfig {
  port: number
  databaseUrl: string
  protectedEmailDomains: Set<string>
  inboundDecisionToken: string
  outboundDecisionToken?: string
  outboundMaxBodyBytes: number
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

export interface PlanLimits {
  perMinute: number
  perHour: number
  perDay: number
  maxMessageBytes: number
  maxRecipients: number
}

export interface Plan extends PlanLimits {
  name: string
  isDefault: boolean
  createdAt?: string
  updatedAt?: string
}

export interface PubkeyPlan {
  pubkey: string
  plan: string
  updatedAt?: string
}

export interface OutboundSendCounts {
  minute: number
  hour: number
  day: number
}

export interface PolicyRepository {
  getPlanForPubkey(pubkey: string): Promise<Plan>
  countOutboundSends(pubkey: string): Promise<OutboundSendCounts>
  recordOutboundSend(pubkey: string, giftWrapId?: string): Promise<void>
  hasOutboundSend(giftWrapId: string): Promise<boolean>
  listPlans?(): Promise<Plan[]>
  upsertPlan?(name: string, limits: PlanLimits, isDefault: boolean): Promise<Plan>
  deletePlan?(name: string): Promise<boolean>
  getPubkeyPlan?(pubkey: string): Promise<string | null>
  setPubkeyPlan?(pubkey: string, planName: string): Promise<PubkeyPlan | null>
  clearPubkeyPlan?(pubkey: string): Promise<boolean>
  listPubkeyPlans?(search?: string): Promise<PubkeyPlan[]>
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
