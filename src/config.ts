const SENSITIVITIES = ["strict", "balanced", "aggressive"] as const;
const DISCORD_ID = /^[1-9]\d{16,19}$/;

export type Sensitivity = (typeof SENSITIVITIES)[number];

export interface GuildSettings {
  guildId: string;
  moderationChannelId: string;
  pingRoleId: string | null;
  sensitivity: Sensitivity;
}

function isDiscordId(value: unknown): value is string {
  return typeof value === "string" && DISCORD_ID.test(value);
}

function isSensitivity(value: unknown): value is Sensitivity {
  return SENSITIVITIES.some((mode) => mode === value);
}

function parseGuilds(
  value: string | undefined,
): ReadonlyMap<string, GuildSettings> {
  let entries: unknown;
  try {
    entries = JSON.parse(value ?? "[]");
  } catch {
    throw new Error("DISCORD_GUILDS must be a JSON array");
  }
  if (!Array.isArray(entries) || entries.length === 0) {
    throw new Error("Set at least one Discord server in DISCORD_GUILDS");
  }

  const guilds = new Map<string, GuildSettings>();
  for (const [index, entry] of entries.entries()) {
    const field = `DISCORD_GUILDS[${index}]`;
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      throw new Error(`${field} must be an object`);
    }
    const {
      guildId,
      moderationChannelId,
      pingRoleId = null,
      sensitivity = "balanced",
    } = entry as Record<string, unknown>;
    if (!isDiscordId(guildId)) {
      throw new Error(`${field}.guildId must be a Discord ID string`);
    }
    if (!isDiscordId(moderationChannelId)) {
      throw new Error(
        `${field}.moderationChannelId must be a Discord ID string`,
      );
    }
    if (
      pingRoleId !== null &&
      (!isDiscordId(pingRoleId) || pingRoleId === guildId)
    ) {
      throw new Error(
        `${field}.pingRoleId must be a regular Discord role ID or null`,
      );
    }
    if (!isSensitivity(sensitivity)) {
      throw new Error(
        `${field}.sensitivity must be strict, balanced, or aggressive`,
      );
    }
    if (guilds.has(guildId)) {
      throw new Error(`${field}.guildId is already configured`);
    }
    guilds.set(guildId, {
      guildId,
      moderationChannelId,
      pingRoleId,
      sensitivity,
    });
  }
  return guilds;
}

export function loadConfig(
  env: Readonly<Record<string, string | undefined>> = Bun.env,
) {
  const token = env.DISCORD_TOKEN?.trim();
  if (!token) throw new Error("Set DISCORD_TOKEN in .env");

  const kumaUrl = URL.parse(env.UPTIME_KUMA_URL?.trim() ?? "");
  if (!kumaUrl || !["http:", "https:"].includes(kumaUrl.protocol)) {
    throw new Error("Set UPTIME_KUMA_URL to an HTTP(S) Push URL in .env");
  }

  return { token, kumaUrl, guilds: parseGuilds(env.DISCORD_GUILDS?.trim()) };
}
