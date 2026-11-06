import { once } from "node:events";
import { createBot } from "./src/bot.ts";
import { loadConfig } from "./src/config.ts";
import { BotDatabase } from "./src/database.ts";
import { startHeartbeat } from "./src/heartbeat.ts";
import { logger } from "./src/logger.ts";

async function run(): Promise<void> {
  const { token, kumaUrl, guilds } = loadConfig();
  const database = new BotDatabase();
  const shutdown = new AbortController();
  const stop = (signal: NodeJS.Signals) => {
    logger.info("Shutdown requested", { signal });
    shutdown.abort();
  };
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);

  try {
    const bot = createBot(database, guilds);
    try {
      logger.info("Starting discord-scam-killer", {
        bun: Bun.version,
        configuredGuilds: guilds.size,
      });
      startHeartbeat(kumaUrl, bot.isReady, shutdown.signal);
      await bot.start(token, shutdown.signal);
      if (!shutdown.signal.aborted) await once(shutdown.signal, "abort");
    } finally {
      shutdown.abort();
      await bot.stop();
    }
  } finally {
    process.off("SIGINT", stop);
    process.off("SIGTERM", stop);
    database.close();
  }
}

try {
  await run();
} catch (error) {
  logger.error("Bot stopped", { error });
  process.exitCode = 1;
}
