import { Database } from "bun:sqlite";
import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";

export interface BannedScammer {
  server_id: string;
  user_id: string;
  banned_by: string;
  banned_at: string;
}

const DEFAULT_DATABASE_PATH = join(
  import.meta.dir,
  "..",
  "discord-scam-killer.db",
);

export class BotDatabase {
  readonly #db: Database;
  readonly #upsertBannedScammer;
  readonly #getBannedScammer;

  constructor(path = DEFAULT_DATABASE_PATH) {
    if (path !== ":memory:") {
      mkdirSync(dirname(path), { recursive: true });
    }

    this.#db = new Database(path, { create: true, strict: true });
    this.#db.run("PRAGMA journal_mode = WAL;");
    this.#db.run("PRAGMA synchronous = NORMAL;");
    this.#db.run("PRAGMA busy_timeout = 5000;");
    this.#db.run(`
      CREATE TABLE IF NOT EXISTS banned_scammers (
        server_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        banned_by TEXT NOT NULL,
        banned_at TEXT NOT NULL,
        PRIMARY KEY (server_id, user_id)
      ) WITHOUT ROWID;
    `);
    this.#upsertBannedScammer = this.#db.query<
      unknown,
      [string, string, string, string]
    >(`
      INSERT INTO banned_scammers (server_id, user_id, banned_by, banned_at)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(server_id, user_id) DO UPDATE SET
        banned_by = excluded.banned_by,
        banned_at = excluded.banned_at
    `);
    this.#getBannedScammer = this.#db.query<BannedScammer, [string, string]>(`
      SELECT server_id, user_id, banned_by, banned_at
      FROM banned_scammers
      WHERE server_id = ? AND user_id = ?
    `);

    this.#db.run("DROP TABLE IF EXISTS server_settings;");
  }

  recordBan(serverId: string, userId: string, moderatorId: string): void {
    this.#upsertBannedScammer.run(
      serverId,
      userId,
      moderatorId,
      new Date().toISOString(),
    );
  }

  getBan(serverId: string, userId: string): BannedScammer | null {
    return this.#getBannedScammer.get(serverId, userId);
  }

  close(): void {
    this.#db.close(false);
  }
}
