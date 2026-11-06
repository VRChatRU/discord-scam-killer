import { afterEach, describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { BotDatabase, type GuildSettings } from "../src/database.ts";

describe("BotDatabase", () => {
  let database: BotDatabase | undefined;

  afterEach(() => {
    database?.close();
    database = undefined;
  });

  test("stores independent JSON settings for each server", () => {
    database = new BotDatabase(":memory:");
    const first: GuildSettings = {
      moderationChannelId: "100000000000000001",
      pingRoleId: "600000000000000001",
      sensitivity: "balanced",
      configuredBy: "200000000000000001",
      configuredAt: "2026-07-15T00:00:00.000Z",
    };
    const second: GuildSettings = {
      moderationChannelId: "100000000000000002",
      pingRoleId: "600000000000000002",
      sensitivity: "strict",
      configuredBy: "200000000000000002",
      configuredAt: "2026-07-15T00:01:00.000Z",
    };

    database.setSettings("300000000000000001", first);
    database.setSettings("300000000000000002", second);

    expect(database.getSettings("300000000000000001")).toEqual(first);
    expect(database.getSettings("300000000000000002")).toEqual(second);
    expect(database.getSettings("missing")).toBeNull();
  });

  test("records the moderator who banned a scammer", () => {
    database = new BotDatabase(":memory:");
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
  });

  test("keeps legacy settings valid until /setup adds a ping role", async () => {
    const directory = await mkdtemp(join(tmpdir(), "beastkiller-db-"));
    const path = join(directory, "legacy.sqlite");

    try {
      const legacyDatabase = new Database(path, { create: true });
      legacyDatabase.run(`
        CREATE TABLE server_settings (
          server_id TEXT PRIMARY KEY,
          value TEXT NOT NULL CHECK (json_valid(value))
        ) WITHOUT ROWID
      `);
      legacyDatabase
        .query("INSERT INTO server_settings (server_id, value) VALUES (?, ?)")
        .run(
          "300000000000000003",
          JSON.stringify({
            moderationChannelId: "100000000000000003",
            sensitivity: "balanced",
            configuredBy: "200000000000000003",
            configuredAt: "2026-07-15T00:02:00.000Z",
          }),
        );
      legacyDatabase.close();

      database = new BotDatabase(path);
      expect(database.getSettings("300000000000000003")).toMatchObject({
        moderationChannelId: "100000000000000003",
        pingRoleId: null,
        sensitivity: "balanced",
      });
      database.close();
      database = undefined;
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
