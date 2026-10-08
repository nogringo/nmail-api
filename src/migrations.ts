import { readdir, readFile } from 'node:fs/promises'
import pg from 'pg'

const MIGRATIONS_DIR = new URL('../migrations/', import.meta.url)

// Last migration applied by hand before schema_migrations existed.
const BASELINE = '011_index_push_subscriptions_destination.sql'
const BASELINE_MARKER = 'push_subscriptions_destination_idx'

export async function migrate(databaseUrl: string, dir: URL = MIGRATIONS_DIR): Promise<string[]> {
  const files = (await readdir(dir)).filter((file) => file.endsWith('.sql')).sort()
  const client = new pg.Client({ connectionString: databaseUrl })
  await client.connect()

  try {
    await client.query(`select pg_advisory_lock(hashtext('nmail-api migrations'))`)
    await ensureMigrationsTable(client, files)

    const result = await client.query<{ name: string }>('select name from schema_migrations')
    const applied = new Set(result.rows.map((row) => row.name))
    const pending = files.filter((file) => !applied.has(file))

    for (const file of pending) {
      const sql = await readFile(new URL(file, dir), 'utf8')
      try {
        await inTransaction(client, async () => {
          await client.query(sql)
          await client.query('insert into schema_migrations (name) values ($1)', [file])
        })
      } catch (error) {
        throw new Error(`Migration ${file} failed: ${(error as Error).message}`, { cause: error })
      }
    }

    return pending
  } finally {
    await client.end()
  }
}

async function ensureMigrationsTable(client: pg.Client, files: string[]): Promise<void> {
  const result = await client.query<{ tracked: boolean; existing: boolean; baseline: boolean }>(
    `
      select
        to_regclass('schema_migrations') is not null as tracked,
        to_regclass('identities') is not null as existing,
        to_regclass($1) is not null as baseline
    `,
    [BASELINE_MARKER],
  )
  const { tracked, existing, baseline } = result.rows[0]
  if (tracked) return

  if (existing && !baseline) {
    throw new Error(`Database predates schema_migrations: apply migrations up to ${BASELINE} manually, then restart`)
  }

  await inTransaction(client, async () => {
    await client.query(`
      create table schema_migrations (
        name text primary key,
        applied_at timestamptz not null default now()
      )
    `)
    if (existing) {
      await client.query('insert into schema_migrations (name) select unnest($1::text[])', [
        files.filter((file) => file <= BASELINE),
      ])
    }
  })
}

async function inTransaction(client: pg.Client, run: () => Promise<void>): Promise<void> {
  await client.query('begin')
  try {
    await run()
    await client.query('commit')
  } catch (error) {
    await client.query('rollback')
    throw error
  }
}
