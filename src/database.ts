import { Database } from "bun:sqlite";
import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";

export const SENSITIVITIES = ["strict", "balanced", "aggressive"] as const;

export type Sensitivity = (typeof SENSITIVITIES)[number];

export interface GuildSettings {
  moderationChannelId: string;
  pingRoleId: string | null;
  sensitivity: Sensitivity;
  configuredBy: string;
  configuredAt: string;
}

export interface BannedScammer {
  server_id: string;
  user_id: string;
  banned_by: string;
  banned_at: string;
}

interface SettingsRow {
  value: string;
}

const DEFAULT_DATABASE_PATH = join(
  import.meta.dir,
  "..",
  "discord-scam-killer.db",
);

function isSensitivity(value: unknown): value is Sensitivity {
  return (
    typeof value === "string" && SENSITIVITIES.includes(value as Sensitivity)
  );
}

function parseSettings(value: string): GuildSettings | null {
  try {
    const parsed: unknown = JSON.parse(value);

    if (
      typeof parsed !== "object" ||
      parsed === null ||
      !("moderationChannelId" in parsed) ||
      !("sensitivity" in parsed) ||
      !("configuredBy" in parsed) ||
      !("configuredAt" in parsed) ||
      typeof parsed.moderationChannelId !== "string" ||
      ("pingRoleId" in parsed &&
        parsed.pingRoleId !== null &&
        typeof parsed.pingRoleId !== "string") ||
      !isSensitivity(parsed.sensitivity) ||
      typeof parsed.configuredBy !== "string" ||
      typeof parsed.configuredAt !== "string"
    ) {
      return null;
    }

    return {
      moderationChannelId: parsed.moderationChannelId,
      // Legacy settings remain valid without a role until /setup runs again.
      pingRoleId:
        "pingRoleId" in parsed && typeof parsed.pingRoleId === "string"
          ? parsed.pingRoleId
          : null,
      sensitivity: parsed.sensitivity,
      configuredBy: parsed.configuredBy,
      configuredAt: parsed.configuredAt,
    };
  } catch {
    return null;
  }
}

export class BotDatabase {
  readonly #db: Database;
  readonly #settingsCache = new Map<string, GuildSettings | null>();
  readonly #getSettings;
  readonly #upsertSettings;
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
      CREATE TABLE IF NOT EXISTS server_settings (
        server_id TEXT PRIMARY KEY,
        value TEXT NOT NULL CHECK (json_valid(value))
      ) WITHOUT ROWID;

      CREATE TABLE IF NOT EXISTS banned_scammers (
        server_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        banned_by TEXT NOT NULL,
        banned_at TEXT NOT NULL,
        PRIMARY KEY (server_id, user_id)
      ) WITHOUT ROWID;
    `);

    this.#getSettings = this.#db.query<SettingsRow, [string]>(
      "SELECT value FROM server_settings WHERE server_id = ?",
    );
    this.#upsertSettings = this.#db.query<unknown, [string, string]>(`
      INSERT INTO server_settings (server_id, value)
      VALUES (?, ?)
      ON CONFLICT(server_id) DO UPDATE SET value = excluded.value
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
  }

  getSettings(serverId: string): GuildSettings | null {
    if (this.#settingsCache.has(serverId)) {
      return this.#settingsCache.get(serverId) ?? null;
    }

    const row = this.#getSettings.get(serverId);
    const settings = row ? parseSettings(row.value) : null;
    this.#settingsCache.set(serverId, settings);
    return settings;
  }

  setSettings(serverId: string, settings: GuildSettings): void {
    this.#upsertSettings.run(serverId, JSON.stringify(settings));
    this.#settingsCache.set(serverId, settings);
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
