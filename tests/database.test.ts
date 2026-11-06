import { describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { BotDatabase } from "../src/database.ts";

describe("BotDatabase", () => {
  test("records the moderator who banned a scammer", () => {
    const database = new BotDatabase(":memory:");
    try {
      database.recordBan(
        "300000000000000001",
        "400000000000000001",
        "500000000000000001",
      );

      const ban = database.getBan("300000000000000001", "400000000000000001");
      expect(ban).toMatchObject({
        server_id: "300000000000000001",
        user_id: "400000000000000001",
        banned_by: "500000000000000001",
      });
      expect(Number.isNaN(Date.parse(ban?.banned_at ?? ""))).toBeFalse();
    } finally {
      database.close();
    }
  });

  test("removes legacy settings and keeps recorded bans", async () => {
    const directory = await mkdtemp(join(tmpdir(), "discord-scam-killer-db-"));
    const path = join(directory, "legacy.db");
    const ban = {
      server_id: "300000000000000003",
      user_id: "400000000000000003",
      banned_by: "500000000000000003",
      banned_at: "2026-07-15T00:02:00.000Z",
    };

    try {
      {
        using legacyDatabase = new Database(path);
        legacyDatabase.exec(`
          CREATE TABLE server_settings (
            server_id TEXT PRIMARY KEY,
            value TEXT NOT NULL CHECK (json_valid(value))
          ) WITHOUT ROWID;

          CREATE TABLE banned_scammers (
            server_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            banned_by TEXT NOT NULL,
            banned_at TEXT NOT NULL,
            PRIMARY KEY (server_id, user_id)
          ) WITHOUT ROWID;
        `);
        legacyDatabase
          .query("INSERT INTO server_settings VALUES (?, ?)")
          .run(
            ban.server_id,
            JSON.stringify({ moderationChannelId: "100000000000000003" }),
          );
        legacyDatabase
          .query("INSERT INTO banned_scammers VALUES (?, ?, ?, ?)")
          .run(ban.server_id, ban.user_id, ban.banned_by, ban.banned_at);
      }

      const database = new BotDatabase(path);
      try {
        expect(database.getBan(ban.server_id, ban.user_id)).toEqual(ban);
      } finally {
        database.close();
      }

      using migratedDatabase = new Database(path, { readonly: true });
      const tables = migratedDatabase
        .query("SELECT name FROM sqlite_schema WHERE type = 'table'")
        .all();
      expect(tables).toEqual([{ name: "banned_scammers" }]);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
