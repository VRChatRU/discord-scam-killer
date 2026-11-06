import { appendFileSync } from "node:fs";
import { join } from "node:path";

export const LOG_LEVELS = ["debug", "info", "warn", "error", "silent"] as const;

export type LogLevel = (typeof LOG_LEVELS)[number];
export type LogContext = Readonly<Record<string, unknown>>;

const PRIORITY: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
  silent: 50,
};

export function parseLogLevel(value: string | undefined): LogLevel {
  const normalized = value?.trim().toLowerCase();
  return LOG_LEVELS.includes(normalized as LogLevel)
    ? (normalized as LogLevel)
    : "info";
}

const activeLevel = parseLogLevel(Bun.env.LOG_LEVEL);
const logPath = join(import.meta.dir, "..", "discord-scam-killer.log");
const secrets = [Bun.env.DISCORD_TOKEN, Bun.env.UPTIME_KUMA_URL]
  .map((value) => value?.trim())
  .filter((value): value is string => Boolean(value));
let fileUnavailable = false;

function redact(text: string): string {
  for (const secret of secrets) {
    text = text.replaceAll(secret, "[redacted]");
  }
  return text.replace(/https?:\/\/[^\s"'<>]+/gi, "[url]");
}

function logValue(_key: string, value: unknown): unknown {
  if (value instanceof Error) {
    // SDK errors may hold entire HTTP requests and message bodies.
    return {
      name: value.name,
      message: value.message,
      code: "code" in value ? value.code : undefined,
      status: "status" in value ? value.status : undefined,
    };
  }
  return typeof value === "string" ? redact(value) : value;
}

function emit(
  level: Exclude<LogLevel, "silent">,
  message: string,
  context?: LogContext,
): void {
  if (PRIORITY[level] < PRIORITY[activeLevel]) {
    return;
  }

  const timestamp = new Date().toISOString();
  const line = JSON.stringify(
    { timestamp, level, message, ...context },
    logValue,
  );
  console[level](line);

  try {
    appendFileSync(logPath, `${line}\n`);
    fileUnavailable = false;
  } catch {
    if (!fileUnavailable) {
      console.warn(`[${timestamp}] Could not write discord-scam-killer.log`);
      fileUnavailable = true;
    }
  }
}

export const logger = {
  debug(message: string, context?: LogContext): void {
    emit("debug", message, context);
  },
  info(message: string, context?: LogContext): void {
    emit("info", message, context);
  },
  warn(message: string, context?: LogContext): void {
    emit("warn", message, context);
  },
  error(message: string, context?: LogContext): void {
    emit("error", message, context);
  },
};
