import { setTimeout as sleep } from "node:timers/promises";
import {
  ApplicationCommandType,
  Client,
  DefaultRestOptions,
  DiscordAPIError,
  DiscordjsError,
  DiscordjsErrorCodes,
  Events,
  GatewayCloseCodes,
  GatewayIntentBits,
  HTTPError,
  Partials,
  type RESTGetAPIApplicationCommandsResult,
  RESTJSONErrorCodes,
  Routes,
  Status,
} from "discord.js";
import type { GuildSettings } from "./config.ts";
import type { BotDatabase } from "./database.ts";
import { loadReferenceProfiles, type ReferenceProfile } from "./detector.ts";
import { logger } from "./logger.ts";
import { handleModerationButton, inspectMessage } from "./moderation.ts";

const INITIAL_RETRY_MS = 5_000;
const MAX_RETRY_MS = 60_000;

const FATAL_GATEWAY_ERRORS = new Set([
  "Authentication failed",
  "Invalid shard",
  "Sharding is required",
  "Used an invalid API version",
  "Used invalid intents",
  "Used disallowed intents",
]);

function isPermanentDiscordError(error: unknown): boolean {
  if (
    error instanceof DiscordjsError &&
    error.code === DiscordjsErrorCodes.TokenInvalid
  ) {
    return true;
  }
  if (error instanceof DiscordAPIError || error instanceof HTTPError) {
    return (
      error.status >= 400 &&
      error.status < 500 &&
      ![408, 425, 429].includes(error.status)
    );
  }
  return error instanceof Error && FATAL_GATEWAY_ERRORS.has(error.message);
}

async function retryDiscordRequest(
  operation: () => Promise<unknown>,
  action: string,
  signal: AbortSignal,
): Promise<void> {
  let delay = INITIAL_RETRY_MS;
  while (!signal.aborted) {
    try {
      await operation();
      return;
    } catch (error) {
      if (signal.aborted) return;
      if (isPermanentDiscordError(error)) throw error;
      logger.warn(`Discord ${action} failed, retrying`, { delay, error });
      try {
        await sleep(delay, undefined, { signal });
      } catch (sleepError) {
        if (signal.aborted) return;
        throw sleepError;
      }
      delay = Math.min(delay * 2, MAX_RETRY_MS);
    }
  }
}

async function login(
  client: Client,
  token: string,
  signal: AbortSignal,
): Promise<void> {
  const { promise, resolve } = Promise.withResolvers<void>();
  const onAbort = () => resolve();
  signal.addEventListener("abort", onAbort, { once: true });
  try {
    await Promise.race([client.login(token), promise]);
  } finally {
    signal.removeEventListener("abort", onAbort);
  }
}

async function removeLegacySetup(
  client: Client<true>,
  signal: AbortSignal,
): Promise<void> {
  const applicationId = client.application.id;
  const commands = (await client.rest.get(
    Routes.applicationCommands(applicationId),
    { signal },
  )) as RESTGetAPIApplicationCommandsResult;
  const setup = commands.find(
    (command) =>
      command.type === ApplicationCommandType.ChatInput &&
      command.name === "setup",
  );
  if (!setup) return;

  try {
    await client.rest.delete(
      Routes.applicationCommand(applicationId, setup.id),
      {
        signal,
      },
    );
  } catch (error) {
    if (
      error instanceof DiscordAPIError &&
      error.code === RESTJSONErrorCodes.UnknownApplicationCommand
    ) {
      return;
    }
    throw error;
  }
  logger.info("Removed legacy /setup command");
}

export function createBot(
  database: BotDatabase,
  guilds: ReadonlyMap<string, GuildSettings>,
) {
  const shutdown = new AbortController();
  const inFlight = new Set<Promise<unknown>>();
  let client: Client | undefined;

  function track(
    task: Promise<unknown>,
    failure: string,
    context: Record<string, unknown> = {},
  ): void {
    const tracked = task.catch((error) =>
      logger.error(failure, { ...context, error }),
    );
    inFlight.add(tracked);
    void tracked.finally(() => inFlight.delete(tracked));
  }

  function makeClient(
    profiles: readonly ReferenceProfile[],
    signal: AbortSignal,
  ): Client {
    const connection = new Client({
      intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMessages,
        GatewayIntentBits.MessageContent,
      ],
      partials: [Partials.Channel],
      rest: {
        makeRequest(url, init) {
          // Discord.js does not expose a signal for its initial Gateway lookup.
          if (!url.endsWith(Routes.gatewayBot())) {
            return DefaultRestOptions.makeRequest(url, init);
          }
          const requestSignal = init.signal
            ? AbortSignal.any([init.signal, signal])
            : signal;
          return DefaultRestOptions.makeRequest(url, {
            ...init,
            signal: requestSignal,
          });
        },
      },
    });
    const reconnecting = new Set<number>();

    connection.once(Events.ClientReady, (readyClient) => {
      if (signal.aborted) return;
      logger.info("Discord Scam Killer is online", {
        userId: readyClient.user.id,
        guilds: readyClient.guilds.cache.size,
      });

      track(
        retryDiscordRequest(
          () => removeLegacySetup(readyClient, signal),
          "legacy /setup removal",
          signal,
        ),
        "Could not remove legacy /setup command",
      );
    });

    connection.on(Events.MessageCreate, (message) => {
      if (signal.aborted || !message.inGuild()) return;
      const settings = guilds.get(message.guildId);
      if (!settings) return;
      track(
        inspectMessage(message, settings, profiles),
        "Could not inspect message",
        { messageId: message.id },
      );
    });

    connection.on(Events.InteractionCreate, (interaction) => {
      if (signal.aborted || !interaction.isButton()) return;
      const settings = interaction.guildId
        ? guilds.get(interaction.guildId)
        : undefined;
      track(
        handleModerationButton(interaction, database, settings),
        "Could not handle moderation button",
        { interactionId: interaction.id },
      );
    });

    connection.on(Events.Error, (error) => {
      if (!signal.aborted) logger.error("Discord client error", { error });
    });

    connection.on(Events.ShardReconnecting, (shardId) => {
      if (signal.aborted || reconnecting.has(shardId)) return;
      reconnecting.add(shardId);
      logger.warn("Discord Gateway shard reconnecting", { shardId });
    });

    const logReconnected = (shardId: number) => {
      if (reconnecting.delete(shardId) && !signal.aborted) {
        logger.info("Discord Gateway shard reconnected", { shardId });
      }
    };
    connection.on(Events.ShardReady, logReconnected);
    connection.on(Events.ShardResume, logReconnected);

    connection.on(Events.ShardDisconnect, (event, shardId) => {
      if (signal.aborted) return;
      if (event.code === GatewayCloseCodes.DisallowedIntents) {
        logger.error(
          "Enable Message Content Intent in the Discord Developer Portal and restart",
          { shardId },
        );
        return;
      }
      logger.error("Discord Gateway shard stopped", {
        shardId,
        code: event.code,
      });
    });

    return connection;
  }

  return {
    async start(token: string, signal: AbortSignal): Promise<void> {
      const running = AbortSignal.any([signal, shutdown.signal]);
      if (running.aborted) return;
      const profiles = await loadReferenceProfiles();
      logger.info("Loaded reference image profiles", {
        profiles: profiles.length,
      });

      await retryDiscordRequest(
        async () => {
          client = makeClient(profiles, running);
          await login(client, token, running);
        },
        "login",
        running,
      );
    },

    async stop(): Promise<void> {
      shutdown.abort();
      await Promise.allSettled(inFlight);
      await client?.destroy();
    },

    isReady(): boolean {
      return (
        !shutdown.signal.aborted &&
        client?.isReady() === true &&
        client.ws.shards.every((shard) => shard.status === Status.Ready)
      );
    },
  };
}
