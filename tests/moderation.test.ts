import { describe, expect, mock, test } from "bun:test";
import {
  Collection,
  PermissionFlagsBits,
  PermissionsBitField,
  type ButtonInteraction,
  type Message,
} from "discord.js";
import sharp from "sharp";
import type { GuildSettings } from "../src/config.ts";
import { BotDatabase } from "../src/database.ts";
import { fingerprintImage } from "../src/detector.ts";
import {
  canModerate,
  handleModerationButton,
  inspectMessage,
} from "../src/moderation.ts";

const settings: GuildSettings = {
  guildId: "guild",
  moderationChannelId: "report-channel",
  pingRoleId: null,
  sensitivity: "balanced",
};

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

  test.each([
    ["unconfigured-guild", "report-channel", undefined],
    ["other-guild", "report-channel", settings],
    ["guild", "other-channel", settings],
  ] as const)(
    "rejects report buttons from %s/%s",
    async (guildId, channelId, guildSettings) => {
      const reply = mock(async () => {});
      const deferUpdate = mock(async () => {});
      const interaction = {
        customId: "discord-scam-killer:ban:123456789012345678",
        guildId,
        channelId,
        inCachedGuild: () => true,
        reply,
        deferUpdate,
      } as unknown as ButtonInteraction;
      const database = new BotDatabase(":memory:");
      try {
        expect(
          await handleModerationButton(interaction, database, guildSettings),
        ).toBeTrue();
        expect(reply).toHaveBeenCalledTimes(1);
        expect(deferUpdate).not.toHaveBeenCalled();
      } finally {
        database.close();
      }
    },
  );
});

describe("false positive reports", () => {
  const userId = "123456789012345678";
  const reportTimeout = Date.now() + 60_000;
  const clearId = `discord-scam-killer:clear:${userId}:${reportTimeout}`;

  test.each([
    ["removes a matching timeout", clearId, reportTimeout, true],
    ["keeps a newer timeout", clearId, reportTimeout + 10_000, false],
    [
      "keeps the timeout for a legacy report",
      `beastkiller:clear:${userId}`,
      reportTimeout,
      false,
    ],
  ] as const)("%s", async (_name, customId, currentTimeout, remove) => {
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
    const database = new BotDatabase(":memory:");
    try {
      expect(
        await handleModerationButton(interaction, database, settings),
      ).toBeTrue();
      expect(timeout).toHaveBeenCalledTimes(remove ? 1 : 0);
      expect(editReply).toHaveBeenCalledTimes(1);
    } finally {
      database.close();
    }
  });
});

test.each([
  ["guild", 1],
  ["other-guild", 0],
] as const)(
  "preserves the original message and member when no report can be posted in %s",
  async (guildId, reportAttempts) => {
    const sample = await sharp({
      create: { width: 32, height: 32, channels: 3, background: "#984a31" },
    })
      .jpeg()
      .toBuffer();
    const reference = await fingerprintImage(sample);
    const attachment = {
      id: "attachment",
      name: "sample.jpg",
      url: `data:image/jpeg;base64,${sample.toString("base64")}`,
      contentType: "image/jpeg",
      size: sample.length,
      width: 32,
      height: 32,
    };
    const send = mock(async () => {
      throw new Error("Report channel is unavailable");
    });
    const fetchMember = mock(async () => {});
    const deleteMessage = mock(async () => {});
    const message = {
      id: "message",
      guildId,
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

    await inspectMessage(message, settings, [
      { ...reference, sourcePath: "sample.jpg" },
    ]);
    expect(send).toHaveBeenCalledTimes(reportAttempts);
    expect(fetchMember).not.toHaveBeenCalled();
    expect(deleteMessage).not.toHaveBeenCalled();
  },
);
