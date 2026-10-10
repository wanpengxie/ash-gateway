/** Storage schema of the gateway hub, and the lost-phone reset that rebuilds it. */
export interface SchemaSql { exec(query: string, ...bindings: (string | number)[]): { toArray(): unknown[] } }

export const TABLES: readonly { name: string; create: string }[] = [
  { name: "meta", create: "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)" },
  { name: "device_tunnels", create: "CREATE TABLE IF NOT EXISTS device_tunnels (sid TEXT PRIMARY KEY, device TEXT NOT NULL, kind TEXT NOT NULL, expires INTEGER NOT NULL)" },
  { name: "devices", create: `CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY, role TEXT NOT NULL, pubkey TEXT NOT NULL, name TEXT NOT NULL,
    permissions TEXT NOT NULL, grant_version INTEGER NOT NULL, created_at INTEGER NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0)` },
  { name: "challenges", create: `CREATE TABLE IF NOT EXISTS challenges (
    nonce TEXT PRIMARY KEY, purpose TEXT NOT NULL, subject TEXT NOT NULL, expires_at INTEGER NOT NULL)` },
  { name: "sessions", create: `CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY, device_id TEXT NOT NULL, expires_at INTEGER NOT NULL)` },
  { name: "pair_tickets", create: `CREATE TABLE IF NOT EXISTS pair_tickets (
    ticket_hash TEXT PRIMARY KEY, expires_at INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0)` },
  { name: "pair_requests", create: `CREATE TABLE IF NOT EXISTS pair_requests (
    id TEXT PRIMARY KEY, client_id TEXT NOT NULL, pubkey TEXT NOT NULL, name TEXT NOT NULL,
    status TEXT NOT NULL, approval TEXT, expires_at INTEGER NOT NULL, ticket_hash TEXT NOT NULL DEFAULT '')` },
];

/**
 * Creates the tables and applies the lost-phone reset: when the stored RESET_EPOCH differs from the
 * deployed one, every table is dropped and created again, so the stored shape is the current one
 * too (not only empty). Returns true when a reset happened.
 */
export function ensureSchema(sql: SchemaSql, epoch: string): boolean {
  for (const t of TABLES) sql.exec(t.create);
  const row = sql.exec("SELECT value FROM meta WHERE key = ?", "reset_epoch").toArray()[0] as { value: string } | undefined;
  const reset = row !== undefined && row.value !== epoch;
  if (reset) {
    for (const t of TABLES) sql.exec(`DROP TABLE IF EXISTS ${t.name}`);
    for (const t of TABLES) sql.exec(t.create);
  }
  sql.exec("INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", "reset_epoch", epoch);
  return reset;
}
