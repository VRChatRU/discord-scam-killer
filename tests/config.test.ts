import { expect, test } from "bun:test";
import { loadConfig } from "../src/config.ts";

const env = {
  DISCORD_TOKEN: "test-token",
  UPTIME_KUMA_URL: "https://example.invalid/api/push/test",
};

const server = {
  guildId: "123456789012345678",
  moderationChannelId: "234567890123456789",
};

test("loads multiple guilds from the environment with optional settings", () => {
  const second = {
    guildId: "345678901234567890",
    moderationChannelId: "456789012345678901",
    pingRoleId: "567890123456789012",
    sensitivity: "strict" as const,
  };
  const config = loadConfig({
    ...env,
    DISCORD_GUILDS: JSON.stringify([server, second]),
  });

  expect(config.guilds.size).toBe(2);
  expect(config.guilds.get(server.guildId)).toEqual({
    ...server,
    pingRoleId: null,
    sensitivity: "balanced",
  });
  expect(config.guilds.get(second.guildId)).toEqual(second);
});

test("rejects missing, duplicate, or invalid guild settings", () => {
  expect(() => loadConfig(env)).toThrow("Set at least one Discord server");
  expect(() => loadConfig({ ...env, DISCORD_GUILDS: "{" })).toThrow(
    "must be a JSON array",
  );
  expect(() =>
    loadConfig({ ...env, DISCORD_GUILDS: JSON.stringify([server, server]) }),
  ).toThrow("already configured");
  expect(() =>
    loadConfig({
      ...env,
      DISCORD_GUILDS: JSON.stringify([{ ...server, moderationChannelId: 123 }]),
    }),
  ).toThrow("moderationChannelId must be a Discord ID string");
});
