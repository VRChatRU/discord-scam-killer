const INTERVAL_MS = 60_000;
const REQUEST_TIMEOUT_MS = 10_000;

export function startHeartbeat(
  url: URL,
  isReady: () => boolean,
  signal: AbortSignal,
): void {
  if (signal.aborted) return;

  const downUrl = new URL(url);
  downUrl.searchParams.set("status", "down");
  downUrl.searchParams.set("msg", "Discord Gateway unavailable");
  downUrl.searchParams.delete("ping");

  const timer = setInterval(async () => {
    try {
      const response = await fetch(isReady() ? url : downUrl, {
        signal: AbortSignal.any([
          signal,
          AbortSignal.timeout(REQUEST_TIMEOUT_MS),
        ]),
        redirect: "error",
      });
      await response.body?.cancel();
    } catch {
      // Missed pushes are handled by Kuma. The next interval tries again.
    }
  }, INTERVAL_MS);

  signal.addEventListener("abort", () => clearInterval(timer), { once: true });
}
