import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Pool } from 'pg';
import { loadConfig } from '../config.js';

/**
 * Minimal forward-only migration runner. Files in ./migrations run in
 * lexicographic order, each in a transaction, tracked in _migrations.
 */
export async function runMigrations(databaseUrl?: string, migrationsDir?: string): Promise<string[]> {
  const url = databaseUrl ?? loadConfig().DATABASE_URL;
  const dir = migrationsDir ?? join(__dirname, '..', '..', 'migrations');
  const pool = new Pool({ connectionString: url });
  const applied: string[] = [];
  try {
    await pool.query(
      'CREATE TABLE IF NOT EXISTS _migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())',
    );
    const files = readdirSync(dir)
      .filter((f) => f.endsWith('.sql'))
      .sort();
    for (const file of files) {
      const { rowCount } = await pool.query('SELECT 1 FROM _migrations WHERE name = $1', [file]);
      if (rowCount) continue;
      const sql = readFileSync(join(dir, file), 'utf8');
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        await client.query(sql);
        await client.query('INSERT INTO _migrations (name) VALUES ($1)', [file]);
        await client.query('COMMIT');
        applied.push(file);
      } catch (err) {
        await client.query('ROLLBACK');
        throw err;
      } finally {
        client.release();
      }
    }
  } finally {
    await pool.end();
  }
  return applied;
}

if (require.main === module) {
  runMigrations()
    .then((applied) => {
      console.log(applied.length ? `Applied: ${applied.join(', ')}` : 'Already up to date');
    })
    .catch((err) => {
      console.error('Migration failed:', err);
      process.exit(1);
    });
}
