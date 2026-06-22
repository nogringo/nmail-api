import cors from '@fastify/cors'
import Fastify from 'fastify'
import { registerAdminRoutes } from './handlers/admin.js'
import { createInboundDecisionHandler } from './handlers/inboundDecision.js'
import { createNip05Handler } from './handlers/nip05.js'
import { createOutboundDecisionHandler } from './handlers/outboundDecision.js'
import type { AppConfig, IdentityRepository, PolicyRepository } from './types.js'

export async function buildApp(
  repo: IdentityRepository & PolicyRepository,
  config: Pick<
    AppConfig,
    'protectedEmailDomains' | 'inboundDecisionToken' | 'outboundDecisionToken' | 'adminPassword'
  > & { outboundMaxBodyBytes?: number },
) {
  const app = Fastify({ logger: true })

  await app.register(cors, {
    origin: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  })

  app.get('/healthz', async () => 'ok')
  app.get('/.well-known/nostr.json', createNip05Handler(repo))
  app.post('/inbound/decision', createInboundDecisionHandler(repo, config))
  if (config.outboundDecisionToken) {
    app.post(
      '/outbound/decision',
      { bodyLimit: config.outboundMaxBodyBytes ?? 32 * 1024 * 1024 },
      createOutboundDecisionHandler(repo, { ...config, outboundDecisionToken: config.outboundDecisionToken }),
    )
  }
  if (config.adminPassword) registerAdminRoutes(app, repo, config.adminPassword)

  return app
}
