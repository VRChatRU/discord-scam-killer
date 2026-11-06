import { once } from "node:events";
import { createBot } from "./src/bot.ts";
import { BotDatabase } from "./src/database.ts";
import { startHeartbeat } from "./src/heartbeat.ts";
import { logger } from "./src/logger.ts";

async function run(): Promise<void> {
  const token = Bun.env.DISCORD_TOKEN?.trim();
  if (!token) throw new Error("Set DISCORD_TOKEN in .env");

  const kumaUrl = URL.parse(Bun.env.UPTIME_KUMA_URL?.trim() ?? "");
  if (!kumaUrl || !["http:", "https:"].includes(kumaUrl.protocol)) {
    throw new Error("Set UPTIME_KUMA_URL to an HTTP(S) Push URL in .env");
  }

  const database = new BotDatabase();
  const shutdown = new AbortController();
  const stop = (signal: NodeJS.Signals) => {
    logger.info("Shutdown requested", { signal });
    shutdown.abort();
  };
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);

  try {
    const bot = createBot(database);
    try {
      logger.info("Starting discord-scam-killer", { bun: Bun.version });
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
