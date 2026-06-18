import { buildApp } from './app.js'
import { loadConfig } from './config.js'
import { PgIdentityRepository } from './repository.js'

const config = loadConfig()
const repo = new PgIdentityRepository(config.databaseUrl)
const app = await buildApp(repo, config)

const shutdown = async () => {
  await app.close()
  await repo.close()
}

process.on('SIGINT', () => {
  shutdown().finally(() => process.exit(0))
})

process.on('SIGTERM', () => {
  shutdown().finally(() => process.exit(0))
})

await app.listen({ host: '0.0.0.0', port: config.port })
