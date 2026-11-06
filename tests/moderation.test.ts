import { describe, expect, mock, test } from "bun:test";
import {
  Collection,
  PermissionFlagsBits,
  PermissionsBitField,
  type ButtonInteraction,
  type Message,
} from "discord.js";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { BotDatabase } from "../src/database.ts";
import { fingerprintImage } from "../src/detector.ts";
import {
  canModerate,
  handleModerationButton,
  inspectMessage,
} from "../src/moderation.ts";

function configuredDatabase(): BotDatabase {
  const database = new BotDatabase(":memory:");
  database.setSettings("guild", {
    moderationChannelId: "report-channel",
    pingRoleId: null,
    sensitivity: "balanced",
    configuredBy: "moderator",
    configuredAt: new Date().toISOString(),
  });
  return database;
}

describe("moderation button authorization", () => {
  test("rejects ordinary report-channel viewers even when no role is configured", () => {
    const permissions = new PermissionsBitField(
      PermissionFlagsBits.ViewChannel,
    );
    expect(canModerate("ban", permissions, null, [])).toBeFalse();
    expect(canModerate("clear", permissions, null, [])).toBeFalse();
  });

  test("accepts the configured role for both decisions", () => {
    const permissions = new PermissionsBitField();
    expect(
      canModerate("ban", permissions, "moderator-role", ["moderator-role"]),
    ).toBeTrue();
    expect(
      canModerate("clear", permissions, "moderator-role", ["moderator-role"]),
    ).toBeTrue();
    expect(
      canModerate("ban", permissions, "moderator-role", ["another-role"]),
    ).toBeFalse();
  });

  test("accepts the corresponding native permission or Administrator", () => {
    const ban = new PermissionsBitField(PermissionFlagsBits.BanMembers);
    const timeout = new PermissionsBitField(
      PermissionFlagsBits.ModerateMembers,
    );
    const admin = new PermissionsBitField(PermissionFlagsBits.Administrator);
    expect(canModerate("ban", ban, null, [])).toBeTrue();
    expect(canModerate("clear", ban, null, [])).toBeFalse();
    expect(canModerate("ban", timeout, null, [])).toBeFalse();
    expect(canModerate("clear", timeout, null, [])).toBeTrue();
    expect(canModerate("ban", admin, "moderator-role", [])).toBeTrue();
    expect(canModerate("clear", admin, "moderator-role", [])).toBeTrue();
  });
});

describe("false positive reports", () => {
  const userId = "123456789012345678";
  const reportTimeout = Date.now() + 60_000;

  test.each([
    [
      `discord-scam-killer:clear:${userId}:${reportTimeout}`,
      reportTimeout,
      true,
    ],
    [
      `discord-scam-killer:clear:${userId}:${reportTimeout}`,
      reportTimeout + 10_000,
      false,
    ],
    [`beastkiller:clear:${userId}`, reportTimeout, false],
  ] as const)(
    "handles %s safely with timeout %s",
    async (customId, currentTimeout, remove) => {
      const timeout = mock(async () => {});
      const editReply = mock(async () => {});
      const interaction = {
        customId,
        guildId: "guild",
        channelId: "report-channel",
        user: { id: "moderator", tag: "moderator" },
        member: { roles: { cache: new Map() } },
        memberPermissions: new PermissionsBitField(
          PermissionFlagsBits.ModerateMembers,
        ),
        message: { id: "report", fetch: async () => ({ embeds: [] }) },
        guild: {
          members: {
            fetch: async () => ({
              communicationDisabledUntilTimestamp: currentTimeout,
              isCommunicationDisabled: () => true,
              timeout,
            }),
          },
        },
        inCachedGuild: () => true,
        deferUpdate: async () => {},
        editReply,
      } as unknown as ButtonInteraction;
      const database = configuredDatabase();
      try {
        expect(await handleModerationButton(interaction, database)).toBeTrue();
        expect(timeout).toHaveBeenCalledTimes(remove ? 1 : 0);
        expect(editReply).toHaveBeenCalledTimes(1);
      } finally {
        database.close();
      }
    },
  );
});

test("preserves the original message and member if its report cannot be posted", async () => {
  const samplePath = join(import.meta.dir, "..", "samples", "1.jpg");
  const sampleFile = Bun.file(samplePath);
  const reference = await fingerprintImage(await sampleFile.bytes());
  const attachment = {
    id: "attachment",
    name: "1.jpg",
    url: pathToFileURL(samplePath).href,
    contentType: "image/jpeg",
    size: sampleFile.size,
    width: 256,
    height: 256,
  };
  const send = mock(async () => {
    throw new Error("Report channel is unavailable");
  });
  const fetchMember = mock(async () => {});
  const deleteMessage = mock(async () => {});
  const message = {
    id: "message",
    guildId: "guild",
    channelId: "source-channel",
    author: {
      id: "123456789012345678",
      tag: "author",
      displayAvatarURL: () => "https://example.com/avatar.png",
    },
    attachments: new Collection([[attachment.id, attachment]]),
    guild: {
      channels: { fetch: async () => ({ isSendable: () => true, send }) },
      members: { fetch: fetchMember },
    },
    inGuild: () => true,
    delete: deleteMessage,
  } as unknown as Message;

  const database = configuredDatabase();
  try {
    await inspectMessage(message, database, [
      { ...reference, sourcePath: samplePath },
    ]);
    expect(send).toHaveBeenCalledTimes(1);
    expect(fetchMember).not.toHaveBeenCalled();
    expect(deleteMessage).not.toHaveBeenCalled();
  } finally {
    database.close();
  }
});
