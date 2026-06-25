import cors from '@fastify/cors'
import formbody from '@fastify/formbody'
import Fastify from 'fastify'
import { registerAdminRoutes } from './handlers/admin.js'
import { createClaimAliasHandler } from './handlers/claimAlias.js'
import { createInboundDecisionHandler } from './handlers/inboundDecision.js'
import { createNip05Handler } from './handlers/nip05.js'
import { createOutboundDecisionHandler } from './handlers/outboundDecision.js'
import { createRoleWebhookHandler } from './handlers/roleWebhook.js'
import type {
  AccountRepository,
  AppConfig,
  DomainRepository,
  IdentityRepository,
  PolicyRepository,
  RoleMessageRepository,
} from './types.js'

const DEFAULT_MAX_BODY_BYTES = 32 * 1024 * 1024

export async function buildApp(
  repo: IdentityRepository & AccountRepository & PolicyRepository & DomainRepository & RoleMessageRepository,
  config: Pick<AppConfig, 'inboundDecisionToken' | 'outboundDecisionToken' | 'adminPassword' | 'roleWebhookSigningKey'> & {
    outboundMaxBodyBytes?: number
    roleWebhookMaxBodyBytes?: number
  },
) {
  const app = Fastify({ logger: true })

  await app.register(cors, {
    origin: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  })

  await app.register(formbody, { bodyLimit: config.roleWebhookMaxBodyBytes ?? DEFAULT_MAX_BODY_BYTES })

  app.get('/healthz', async () => 'ok')
  app.get('/.well-known/nostr.json', createNip05Handler(repo))
  app.post('/inbound/decision', createInboundDecisionHandler(repo, config))
  app.post('/aliases/claim', { bodyLimit: 64 * 1024 }, createClaimAliasHandler(repo))
  if (config.outboundDecisionToken) {
    app.post(
      '/outbound/decision',
      { bodyLimit: config.outboundMaxBodyBytes ?? DEFAULT_MAX_BODY_BYTES },
      createOutboundDecisionHandler(repo, { ...config, outboundDecisionToken: config.outboundDecisionToken }),
    )
  }
  if (config.roleWebhookSigningKey) {
    app.post(
      '/inbound/role',
      { bodyLimit: config.roleWebhookMaxBodyBytes ?? DEFAULT_MAX_BODY_BYTES },
      createRoleWebhookHandler(repo, { roleWebhookSigningKey: config.roleWebhookSigningKey }),
    )
  }
  if (config.adminPassword) registerAdminRoutes(app, repo, config.adminPassword)

  return app
}
