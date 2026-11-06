import {
  ActionRowBuilder,
  Attachment,
  AttachmentBuilder,
  ButtonBuilder,
  ButtonInteraction,
  ButtonStyle,
  EmbedBuilder,
  Message,
  MessageFlags,
  PermissionFlagsBits,
  type PermissionsBitField,
  time,
  TimestampStyles,
} from "discord.js";
import type { BotDatabase, GuildSettings } from "./database.ts";
import { logger, type LogContext } from "./logger.ts";
import {
  createEvidenceImage,
  evaluateFingerprints,
  fingerprintImage,
  MAXIMUM_IMAGE_BYTES,
  MAXIMUM_IMAGE_COUNT,
  MINIMUM_IMAGE_COUNT,
  type DetectionResult,
  type ImageFingerprint,
  type ReferenceProfile,
} from "./detector.ts";

const TIMEOUT_DURATION_MS = 24 * 60 * 60 * 1000;
const DOWNLOAD_TIMEOUT_MS = 10_000;
const ANALYSIS_PREVIEW_SIZE = 256;
const ANALYSIS_PREVIEW_MAX_BYTES = 2 * 1024 * 1024;
const MAX_PENDING_INSPECTIONS = 16;
const BUTTON_PATTERN =
  /^(?:discord-scam-killer|beastkiller):(ban|clear):(\d{17,20})(?::(\d{1,13}))?$/;
const SUPPORTED_IMAGE_EXTENSION = /\.(?:avif|gif|jpe?g|png|tiff?|webp)$/i;
const DECISION_FIELD_NAME = "Moderator decision";

type ModerationAction = "ban" | "clear";

interface ScannedImage {
  attachment: Attachment;
  previewBytes: Uint8Array;
  fingerprint: ImageFingerprint;
}

interface ModerationActions {
  timeoutStatus: "applied" | "already active" | "failed";
  timeoutUntil: number;
  deleted: boolean;
}

class Semaphore {
  #available: number;
  readonly #waiting: Array<() => void> = [];

  constructor(limit: number) {
    this.#available = limit;
  }

  async run<T>(task: () => Promise<T>): Promise<T> {
    if (this.#available === 0) {
      await new Promise<void>((resolve) => this.#waiting.push(resolve));
    } else {
      this.#available -= 1;
    }

    try {
      return await task();
    } finally {
      const next = this.#waiting.shift();
      if (next) {
        next();
      } else {
        this.#available += 1;
      }
    }
  }
}

const imageWorkers = new Semaphore(8);
const activeInspections = new Set<string>();
const pendingDecisions = new Set<string>();
let overloadLogged = false;

function errorCode(error: unknown): string | number {
  if (error && typeof error === "object" && "code" in error) {
    const code = error.code;
    if (
      typeof code === "number" ||
      (typeof code === "string" && /^\w+$/.test(code))
    ) {
      return code;
    }
  }
  return error instanceof Error ? error.name : "UnknownError";
}

function isSupportedImage(attachment: Attachment): boolean {
  return (
    attachment.contentType?.toLowerCase().startsWith("image/") === true ||
    SUPPORTED_IMAGE_EXTENSION.test(attachment.name ?? "")
  );
}

function mediaProxyPreviewUrl(
  attachment: Attachment,
  maximumSide: number,
): string {
  const url = new URL(attachment.proxyURL);
  url.searchParams.set("width", String(maximumSide));
  url.searchParams.set("height", String(maximumSide));
  return url.toString();
}

function isSmallImage(attachment: Attachment): boolean {
  return (
    attachment.width !== null &&
    attachment.height !== null &&
    attachment.width <= ANALYSIS_PREVIEW_SIZE &&
    attachment.height <= ANALYSIS_PREVIEW_SIZE &&
    attachment.size <= ANALYSIS_PREVIEW_MAX_BYTES
  );
}

function analysisImageUrl(attachment: Attachment): string {
  return isSmallImage(attachment)
    ? attachment.url
    : mediaProxyPreviewUrl(attachment, ANALYSIS_PREVIEW_SIZE);
}

async function readResponseBytes(
  response: Response,
  maximumBytes: number,
): Promise<Uint8Array> {
  const contentLength = Number(response.headers.get("content-length") ?? 0);
  if (Number.isFinite(contentLength) && contentLength > maximumBytes) {
    await response.body?.cancel();
    throw new Error(`CDN response exceeds ${maximumBytes} bytes`);
  }

  if (!response.body) {
    throw new Error("CDN returned an empty response");
  }

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      totalBytes += value.byteLength;
      if (totalBytes > maximumBytes) {
        await reader.cancel();
        throw new Error(`CDN stream exceeds ${maximumBytes} bytes`);
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  return Buffer.concat(
    chunks.map((chunk) =>
      Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength),
    ),
    totalBytes,
  );
}

async function downloadImage(
  url: string,
  maximumBytes: number,
): Promise<Uint8Array> {
  const response = await fetch(url, {
    headers: { accept: "image/avif,image/webp,image/*" },
    signal: AbortSignal.timeout(DOWNLOAD_TIMEOUT_MS),
  });
  if (!response.ok) {
    await response.body?.cancel();
    throw Object.assign(new Error("Discord CDN request failed"), {
      code: response.status,
    });
  }
  return readResponseBytes(response, maximumBytes);
}

async function scanAttachment(attachment: Attachment): Promise<ScannedImage> {
  try {
    const previewBytes = await downloadImage(
      analysisImageUrl(attachment),
      ANALYSIS_PREVIEW_MAX_BYTES,
    );
    return {
      attachment,
      previewBytes,
      fingerprint: await fingerprintImage(previewBytes),
    };
  } catch (previewError) {
    if (isSmallImage(attachment) || attachment.size > MAXIMUM_IMAGE_BYTES) {
      throw previewError;
    }
  }

  // Safe fallback if Discord's media proxy is temporarily unavailable.
  const previewBytes = await downloadImage(attachment.url, MAXIMUM_IMAGE_BYTES);
  return {
    attachment,
    previewBytes,
    fingerprint: await fingerprintImage(previewBytes),
  };
}

async function scanImages(
  attachments: Attachment[],
  messageId: string,
): Promise<ScannedImage[]> {
  const results = await Promise.allSettled(
    attachments.map((attachment) =>
      imageWorkers.run(() => scanAttachment(attachment)),
    ),
  );

  const images: ScannedImage[] = [];
  for (const [index, result] of results.entries()) {
    if (result.status === "fulfilled") {
      images.push(result.value);
    } else {
      logger.warn("Could not analyze an image", {
        messageId,
        attachmentId: attachments[index]?.id,
        code: errorCode(result.reason),
      });
    }
  }
  return images;
}

async function createEvidenceFiles(
  images: ScannedImage[],
  messageId: string,
): Promise<AttachmentBuilder[]> {
  const results = await Promise.allSettled(
    images.map((image) =>
      imageWorkers.run(() => createEvidenceImage(image.previewBytes)),
    ),
  );

  const files: AttachmentBuilder[] = [];
  for (const [index, result] of results.entries()) {
    if (result.status === "fulfilled") {
      files.push(
        new AttachmentBuilder(result.value, {
          name: `scam-evidence-${index + 1}.jpg`,
          description:
            images[index]?.attachment.name ?? "Suspicious image preview",
        }),
      );
    } else {
      logger.warn("Could not prepare an evidence image", {
        messageId,
        attachmentId: images[index]?.attachment.id,
        code: errorCode(result.reason),
      });
    }
  }
  return files;
}

async function applyAutomaticModeration(
  message: Message<true>,
  detection: DetectionResult,
): Promise<ModerationActions> {
  const result: ModerationActions = {
    timeoutStatus: "failed",
    timeoutUntil: 0,
    deleted: false,
  };
  const reason =
    `Discord Scam Killer: suspected image scam, confidence ` +
    `${detection.confidence}% (message ${message.id})`;

  try {
    const member = await message.guild.members.fetch({
      user: message.author.id,
      force: true,
    });
    if (member.isCommunicationDisabled()) {
      result.timeoutStatus = "already active";
    } else if (member.moderatable) {
      const updated = await member.timeout(TIMEOUT_DURATION_MS, reason);
      result.timeoutStatus = "applied";
      result.timeoutUntil = updated.communicationDisabledUntilTimestamp ?? 0;
    } else {
      logger.warn("Bot cannot time out the member", {
        guildId: message.guildId,
        messageId: message.id,
        userId: message.author.id,
      });
    }
  } catch (error) {
    logger.warn("Could not apply the automatic timeout", {
      guildId: message.guildId,
      messageId: message.id,
      code: errorCode(error),
    });
  }

  try {
    await message.delete();
    result.deleted = true;
  } catch (error) {
    if (errorCode(error) === 10008) {
      result.deleted = true;
    } else {
      logger.warn("Could not delete the suspicious message", {
        guildId: message.guildId,
        messageId: message.id,
        code: errorCode(error),
      });
    }
  }

  return result;
}

function moderationButtons(
  userId: string,
  timeoutUntil: number,
  disabled = false,
): ActionRowBuilder<ButtonBuilder> {
  return new ActionRowBuilder<ButtonBuilder>().addComponents(
    new ButtonBuilder()
      .setCustomId(`discord-scam-killer:ban:${userId}`)
      .setLabel("Ban")
      .setStyle(ButtonStyle.Danger)
      .setDisabled(disabled),
    new ButtonBuilder()
      .setCustomId(`discord-scam-killer:clear:${userId}:${timeoutUntil}`)
      .setLabel("Not a scammer")
      .setStyle(ButtonStyle.Success)
      .setDisabled(disabled),
  );
}

function colorList(detection: DetectionResult): string {
  return detection.colors
    .map(
      (color, index) =>
        `${index + 1}. rgb(${Math.round(color.red)}, ` +
        `${Math.round(color.green)}, ${Math.round(color.blue)})`,
    )
    .join("\n");
}

function actionSummary(actions: ModerationActions): string {
  const timeoutSummary = {
    applied: "✅ 24-hour timeout",
    "already active": "↪️ Existing timeout kept",
    failed: "❌ 24-hour timeout",
  }[actions.timeoutStatus];
  return [
    timeoutSummary,
    `${actions.deleted ? "✅" : "❌"} Message deletion`,
  ].join("\n");
}

async function sendEvidenceReport(
  message: Message<true>,
  settings: GuildSettings,
  files: AttachmentBuilder[],
  detection: DetectionResult,
): Promise<{ report: Message; embed: EmbedBuilder }> {
  const channel = await message.guild.channels.fetch(
    settings.moderationChannelId,
  );
  if (!channel?.isSendable()) {
    throw new Error("The report channel is missing or is not sendable");
  }

  const embed = new EmbedBuilder()
    .setColor(0xed4245)
    .setTitle("Suspected image scam")
    .setDescription(
      `User **${message.author.tag}** (${message.author}) sent a suspicious ` +
        "set of images.",
    )
    .setThumbnail(message.author.displayAvatarURL())
    .addFields(
      {
        name: "Detector",
        value:
          `Confidence: **${detection.confidence}%** ` +
          `(${detection.imageCountPoints} image count + ` +
          `${detection.colorPoints} AVG color + ` +
          `${detection.pHashPoints} pHash)\n` +
          `Average RGB distance: **${detection.averageReferenceDistance}**\n` +
          `pHash: **${detection.pHashMatches}** close matches, ` +
          `average distance **${detection.averagePHashDistance}**`,
      },
      { name: "Average RGB", value: colorList(detection) },
      {
        name: "Original message",
        value: `ID: \`${message.id}\`\nChannel: <#${message.channelId}>`,
      },
      { name: "Automatic actions", value: "⏳ Pending" },
    )
    .setFooter({ text: `User ID: ${message.author.id}` })
    .setTimestamp();

  const report = await channel.send({
    nonce: message.id,
    enforceNonce: true,
    content: settings.pingRoleId ? `<@&${settings.pingRoleId}>` : undefined,
    embeds: [embed],
    files,
    allowedMentions: settings.pingRoleId
      ? { parse: [], roles: [settings.pingRoleId] }
      : { parse: [] },
  });
  return { report, embed };
}

export async function inspectMessage(
  message: Message,
  database: BotDatabase,
  referenceProfiles: readonly ReferenceProfile[],
): Promise<void> {
  if (!message.inGuild() || message.author.bot || message.webhookId) {
    return;
  }

  // The most common path exits before a settings lookup or any allocation.
  if (message.attachments.size === 0) {
    return;
  }

  const baseLogContext = {
    guildId: message.guildId,
    channelId: message.channelId,
    messageId: message.id,
    authorId: message.author.id,
    attachmentCount: message.attachments.size,
  };
  logger.debug("Attachment message received", baseLogContext);

  const settings = database.getSettings(message.guildId);
  if (!settings) {
    logger.debug("Attachment message skipped", {
      ...baseLogContext,
      reason: "guild is not configured",
    });
    return;
  }

  const supportedImages = message.attachments.filter(isSupportedImage);
  const attachments = supportedImages.first(MAXIMUM_IMAGE_COUNT);
  if (attachments.length < MINIMUM_IMAGE_COUNT) {
    logger.debug("Attachment message skipped", {
      ...baseLogContext,
      supportedImageCount: supportedImages.size,
      reason: "no supported images",
    });
    return;
  }

  if (activeInspections.has(message.id)) {
    return;
  }
  if (activeInspections.size >= MAX_PENDING_INSPECTIONS) {
    if (!overloadLogged) {
      logger.warn("Image inspection capacity reached. Skipping new messages.", {
        limit: MAX_PENDING_INSPECTIONS,
      });
      overloadLogged = true;
    }
    return;
  }

  activeInspections.add(message.id);
  try {
    await inspectImageSet(message, settings, attachments, referenceProfiles, {
      ...baseLogContext,
      supportedImageCount: supportedImages.size,
    });
  } finally {
    activeInspections.delete(message.id);
    if (activeInspections.size < MAX_PENDING_INSPECTIONS / 2) {
      overloadLogged = false;
    }
  }
}

async function inspectImageSet(
  message: Message<true>,
  settings: GuildSettings,
  attachments: Attachment[],
  referenceProfiles: readonly ReferenceProfile[],
  baseLogContext: LogContext,
): Promise<void> {
  const images = await scanImages(attachments, message.id);
  if (images.length < MINIMUM_IMAGE_COUNT) {
    logger.debug("Attachment message skipped", {
      ...baseLogContext,
      analyzedImageCount: images.length,
      reason: "no images decoded successfully",
    });
    return;
  }

  const detection = evaluateFingerprints(
    images.map((image) => image.fingerprint),
    settings.sensitivity,
    referenceProfiles,
  );
  logger.debug("Attachment message evaluated", {
    ...baseLogContext,
    analyzedImageCount: images.length,
    sensitivity: settings.sensitivity,
    confidence: detection.confidence,
    imageCountPoints: detection.imageCountPoints,
    averageColorPoints: detection.colorPoints,
    pHashPoints: detection.pHashPoints,
    averageColorDistance: detection.averageReferenceDistance,
    averagePHashDistance: detection.averagePHashDistance,
    pHashMatches: detection.pHashMatches,
    averageColors: detection.colors.map((color) => [
      Math.round(color.red),
      Math.round(color.green),
      Math.round(color.blue),
    ]),
    detected: detection.suspicious,
  });
  if (!detection.suspicious) {
    return;
  }

  logger.info("Suspicious image set detected", {
    ...baseLogContext,
    sensitivity: settings.sensitivity,
    confidence: detection.confidence,
  });

  const evidenceFiles = await createEvidenceFiles(images, message.id);
  let evidence: Awaited<ReturnType<typeof sendEvidenceReport>>;

  try {
    evidence = await sendEvidenceReport(
      message,
      settings,
      evidenceFiles,
      detection,
    );
  } catch (error) {
    logger.error(
      "Automatic moderation skipped because the report could not be sent",
      {
        ...baseLogContext,
        moderationChannelId: settings.moderationChannelId,
        code: errorCode(error),
      },
    );
    return;
  }

  const { report, embed } = evidence;
  if (report.components.length > 0) {
    return;
  }
  const actions = await applyAutomaticModeration(message, detection);
  logger.info("Automatic moderation finished", {
    ...baseLogContext,
    reportId: report.id,
    timeoutStatus: actions.timeoutStatus,
    deleted: actions.deleted,
  });

  try {
    embed.spliceFields(-1, 1, {
      name: "Automatic actions",
      value: actionSummary(actions),
    });
    await report.edit({
      embeds: [embed],
      components: [moderationButtons(message.author.id, actions.timeoutUntil)],
    });
  } catch (error) {
    logger.error(
      "Could not update the report with automatic moderation results",
      {
        ...baseLogContext,
        reportId: report.id,
        code: errorCode(error),
      },
    );
  }
}

async function finishButton(
  interaction: ButtonInteraction<"cached">,
  report: Message,
  userId: string,
  resultText: string,
): Promise<void> {
  const originalEmbed = report.embeds[0];
  const embed = originalEmbed
    ? EmbedBuilder.from(originalEmbed)
    : new EmbedBuilder().setTitle("Scam moderation decision");

  embed.addFields({
    name: DECISION_FIELD_NAME,
    value:
      `${resultText}\nModerator: ${interaction.user}\n` +
      `Time: ${time(new Date(), TimestampStyles.ShortDateTime)}`,
  });

  await interaction.editReply({
    embeds: [embed],
    components: [moderationButtons(userId, 0, true)],
  });
}

export function canModerate(
  action: ModerationAction,
  permissions: Pick<PermissionsBitField, "has">,
  moderationRoleId: string | null,
  memberRoleIds: Iterable<string>,
): boolean {
  const requiredPermission =
    action === "ban"
      ? PermissionFlagsBits.BanMembers
      : PermissionFlagsBits.ModerateMembers;
  if (permissions.has(requiredPermission)) {
    return true;
  }
  for (const roleId of memberRoleIds) {
    if (roleId === moderationRoleId) {
      return true;
    }
  }
  return false;
}

export async function handleModerationButton(
  interaction: ButtonInteraction,
  database: BotDatabase,
): Promise<boolean> {
  const match = BUTTON_PATTERN.exec(interaction.customId);
  if (!match) {
    return false;
  }

  if (!interaction.inCachedGuild()) {
    await interaction.reply({
      content: "This button only works inside a guild.",
      flags: MessageFlags.Ephemeral,
    });
    return true;
  }

  const [, action, userId] = match;
  if ((action !== "ban" && action !== "clear") || !userId) {
    return false;
  }

  const settings = database.getSettings(interaction.guildId);
  if (!settings || interaction.channelId !== settings.moderationChannelId) {
    await interaction.reply({
      content:
        "This moderation report is no longer linked to the active setup.",
      flags: MessageFlags.Ephemeral,
    });
    return true;
  }

  if (
    !canModerate(
      action,
      interaction.memberPermissions,
      settings.pingRoleId,
      interaction.member.roles.cache.keys(),
    )
  ) {
    await interaction.reply({
      content: `This action requires the configured moderation role or the ${
        action === "ban" ? "Ban Members" : "Moderate Members"
      } permission.`,
      flags: MessageFlags.Ephemeral,
    });
    return true;
  }

  const decisionKey = `${interaction.guildId}:${userId}`;
  if (pendingDecisions.has(decisionKey)) {
    await interaction.reply({
      content: "A moderation decision for this member is already in progress.",
      flags: MessageFlags.Ephemeral,
    });
    return true;
  }

  pendingDecisions.add(decisionKey);
  const decisionContext = {
    guildId: interaction.guildId,
    reportId: interaction.message.id,
    userId,
    moderatorId: interaction.user.id,
    action,
  };
  try {
    await interaction.deferUpdate();
    const report = await interaction.message.fetch();
    if (
      report.embeds.some((embed) =>
        embed.fields.some((field) => field.name === DECISION_FIELD_NAME),
      )
    ) {
      await interaction.followUp({
        content:
          "A moderation decision has already been recorded on this report.",
        flags: MessageFlags.Ephemeral,
      });
      return true;
    }

    let decision: string;
    if (action === "ban") {
      await interaction.guild.members.ban(userId, {
        reason:
          `Discord Scam Killer: confirmed by ${interaction.user.tag} ` +
          `(${interaction.user.id})`,
      });
      database.recordBan(interaction.guildId, userId, interaction.user.id);
      decision = `🔨 <@${userId}> was banned.`;
    } else {
      const member = await interaction.guild.members.fetch({
        user: userId,
        force: true,
      });
      const active = member.isCommunicationDisabled();
      const expectedTimeoutUntil = Number(match[3] ?? 0);
      let timeoutSummary = active
        ? "The active timeout was kept."
        : "There was no active timeout.";
      if (
        active &&
        member.communicationDisabledUntilTimestamp === expectedTimeoutUntil
      ) {
        await member.timeout(
          null,
          `Discord Scam Killer: false positive confirmed by ${interaction.user.tag}`,
        );
        timeoutSummary = "The timeout for this report was removed.";
      }
      decision = `✅ <@${userId}> was marked as not a scammer. ${timeoutSummary}`;
    }
    logger.info("Moderator decision applied", decisionContext);
    await finishButton(interaction, report, userId, decision);
  } catch (error) {
    logger.error("Could not complete the moderation request", {
      ...decisionContext,
      code: errorCode(error),
    });
    if (interaction.deferred) {
      await interaction.followUp({
        content:
          "Could not complete the moderation request. Check the bot log for details.",
        flags: MessageFlags.Ephemeral,
      });
    }
  } finally {
    pendingDecisions.delete(decisionKey);
  }

  return true;
}
