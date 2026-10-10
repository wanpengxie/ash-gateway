import { test } from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { ensureSchema, TABLES, type SchemaSql } from "../src/schema";

function open() {
  const db = new DatabaseSync(":memory:");
  const sql: SchemaSql = { exec(q, ...args) {
    const stmt = db.prepare(q);
    if (/^SELECT/.test(q)) return { toArray: () => stmt.all(...args) };
    stmt.run(...args); return { toArray: () => [] };
  } };
  return { db, sql };
}
const insertRequest = (db: DatabaseSync) =>
  db.prepare("INSERT INTO pair_requests (id, client_id, pubkey, name, status, expires_at, ticket_hash) VALUES ('r','c','k','n','pending',1,'h')").run();

test("a reset drops every table, so an old shape gains ticket_hash", () => {
  const { db, sql } = open();
  // The store as an earlier version left it: no ticket_hash column, an old epoch, some rows.
  db.exec(`CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    INSERT INTO meta VALUES ('reset_epoch', '1');
    CREATE TABLE pair_requests (id TEXT PRIMARY KEY, client_id TEXT NOT NULL, pubkey TEXT NOT NULL, name TEXT NOT NULL,
      status TEXT NOT NULL, approval TEXT, expires_at INTEGER NOT NULL);
    INSERT INTO pair_requests VALUES ('old','c','k','n','pending',NULL,1);`);
  assert.throws(() => insertRequest(db), /ticket_hash/);
  assert.equal(ensureSchema(sql, "2"), true);
  insertRequest(db);
  assert.equal(db.prepare("SELECT count(*) AS n FROM pair_requests").get()?.n, 1, "old rows are gone");
  assert.equal(db.prepare("SELECT value FROM meta WHERE key='reset_epoch'").get()?.value, "2");
  for (const t of TABLES) assert.ok(db.prepare("SELECT 1 FROM sqlite_master WHERE name = ?").get(t.name), t.name);
  db.close();
});

test("an unchanged epoch keeps the data; a first run is not a reset", () => {
  const { db, sql } = open();
  assert.equal(ensureSchema(sql, "0"), false);
  insertRequest(db);
  assert.equal(ensureSchema(sql, "0"), false);
  assert.equal(db.prepare("SELECT count(*) AS n FROM pair_requests").get()?.n, 1);
  assert.equal(ensureSchema(sql, "1"), true);
  assert.equal(db.prepare("SELECT count(*) AS n FROM pair_requests").get()?.n, 0);
  db.close();
});
