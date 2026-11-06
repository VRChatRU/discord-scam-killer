import { expect, spyOn, test, vi } from "bun:test";
import { startHeartbeat } from "../src/heartbeat.ts";

test("pushes after one minute, recovers after a network error, and stops on abort", async () => {
  vi.useFakeTimers();
  const requests: URL[] = [];
  const fetchMock = spyOn(globalThis, "fetch").mockImplementation(
    Object.assign(
      async (resource: Parameters<typeof fetch>[0]) => {
        requests.push(new URL(String(resource)));
        if (requests.length === 1) throw new Error("Network unavailable");
        return new Response(null);
      },
      { preconnect: fetch.preconnect },
    ),
  );
  const shutdown = new AbortController();

  try {
    let ready = false;
    const pushUrl = new URL(
      "https://example.invalid/api/push/test?status=up&msg=OK",
    );
    startHeartbeat(pushUrl, () => ready, shutdown.signal);
    vi.advanceTimersByTime(59_999);
    expect(requests).toHaveLength(0);

    vi.advanceTimersByTime(1);
    expect(requests).toHaveLength(1);
    expect(requests[0]?.searchParams.get("status")).toBe("down");
    await Promise.resolve();

    ready = true;
    vi.advanceTimersByTime(60_000);
    expect(requests).toHaveLength(2);
    expect(requests[1]?.href).toBe(pushUrl.href);

    shutdown.abort();
    vi.advanceTimersByTime(60_000);
    expect(requests).toHaveLength(2);
  } finally {
    shutdown.abort();
    fetchMock.mockRestore();
    vi.useRealTimers();
  }
});
