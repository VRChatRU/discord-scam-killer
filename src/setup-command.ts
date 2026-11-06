import {
  ChannelType,
  ChatInputCommandInteraction,
  InteractionContextType,
  MessageFlags,
  PermissionFlagsBits,
  SlashCommandBuilder,
} from "discord.js";
import type { BotDatabase, Sensitivity } from "./database.ts";
import { logger } from "./logger.ts";

export const setupCommand = new SlashCommandBuilder()
  .setName("setup")
  .setDescription("Configure image scam protection for this server")
  .setContexts(InteractionContextType.Guild)
  .setDefaultMemberPermissions(PermissionFlagsBits.Administrator)
  .addChannelOption((option) =>
    option
      .setName("channel")
      .setDescription("Private text channel for moderation reports")
      .addChannelTypes(ChannelType.GuildText)
      .setRequired(true),
  )
  .addRoleOption((option) =>
    option
      .setName("ping_role")
      .setDescription(
        "Optional role to ping and authorize for moderation decisions",
      ),
  )
  .addStringOption((option) =>
    option
      .setName("sensitivity")
      .setDescription("Detector sensitivity (balanced by default)")
      .addChoices(
        { name: "Strict — fewer false positives", value: "strict" },
        { name: "Balanced — recommended", value: "balanced" },
        { name: "Aggressive — catches more variants", value: "aggressive" },
      ),
  );

export async function handleSetupCommand(
  interaction: ChatInputCommandInteraction<"cached">,
  database: BotDatabase,
): Promise<void> {
  if (!interaction.memberPermissions.has(PermissionFlagsBits.Administrator)) {
    await interaction.reply({
      content: "Only server administrators can use this command.",
      flags: MessageFlags.Ephemeral,
    });
    return;
  }

  const channel = interaction.options.getChannel("channel", true, [
    ChannelType.GuildText,
  ]);
  const pingRole = interaction.options.getRole("ping_role");
  const sensitivity =
    (interaction.options.getString("sensitivity") as Sensitivity | null) ??
    "balanced";
  const botMember = interaction.guild.members.me;

  if (!botMember) {
    await interaction.reply({
      content: "Could not resolve the bot guild member. Try again in a minute.",
      flags: MessageFlags.Ephemeral,
    });
    return;
  }

  const channelPermissions = channel.permissionsFor(botMember);
  const missingChannelPermissions = [
    PermissionFlagsBits.ViewChannel,
    PermissionFlagsBits.ReadMessageHistory,
    PermissionFlagsBits.SendMessages,
    PermissionFlagsBits.EmbedLinks,
    PermissionFlagsBits.AttachFiles,
  ].filter((permission) => !channelPermissions?.has(permission));

  if (missingChannelPermissions.length > 0) {
    await interaction.reply({
      content:
        `I cannot use ${channel}. Grant the bot View Channel, Read Message History, ` +
        "Send Messages, Embed Links, and Attach Files in that channel.",
      flags: MessageFlags.Ephemeral,
    });
    return;
  }

  if (pingRole?.id === interaction.guildId || pingRole?.managed) {
    await interaction.reply({
      content:
        "Choose a regular moderation role. @everyone and integration-managed " +
        "roles cannot be used.",
      flags: MessageFlags.Ephemeral,
    });
    return;
  }

  if (
    pingRole &&
    !pingRole.mentionable &&
    !channelPermissions?.has(PermissionFlagsBits.MentionEveryone)
  ) {
    await interaction.reply({
      content:
        `${pingRole} cannot be pinged. Make it mentionable or grant the bot ` +
        "Mention @everyone, @here, and All Roles in the report channel.",
      flags: MessageFlags.Ephemeral,
    });
    return;
  }

  database.setSettings(interaction.guildId, {
    moderationChannelId: channel.id,
    pingRoleId: pingRole?.id ?? null,
    sensitivity,
    configuredBy: interaction.user.id,
    configuredAt: new Date().toISOString(),
  });
  logger.info("Guild scam protection configured", {
    guildId: interaction.guildId,
    moderationChannelId: channel.id,
    pingRoleId: pingRole?.id ?? null,
    sensitivity,
    configuredBy: interaction.user.id,
  });

  const missingGuildPermissions: string[] = [];
  if (!botMember.permissions.has(PermissionFlagsBits.ManageMessages)) {
    missingGuildPermissions.push("Manage Messages");
  }
  if (!botMember.permissions.has(PermissionFlagsBits.ModerateMembers)) {
    missingGuildPermissions.push("Moderate Members");
  }
  if (!botMember.permissions.has(PermissionFlagsBits.BanMembers)) {
    missingGuildPermissions.push("Ban Members");
  }

  const warning =
    missingGuildPermissions.length > 0
      ? `\n\n⚠️ Missing bot permissions: **${missingGuildPermissions.join(", ")}**.`
      : "";
  const roleSummary = pingRole
    ? `${pingRole} (can use both report buttons)`
    : "none (report buttons require Discord moderation permissions)";

  await interaction.reply({
    content:
      `Configured ${channel} for reports. Moderation role: ${roleSummary}. ` +
      `Sensitivity: **${sensitivity}**.` +
      warning,
    flags: MessageFlags.Ephemeral,
  });
}
