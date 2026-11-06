import { describe, expect, test } from "bun:test";
import { parseLogLevel } from "../src/logger.ts";

describe("logger", () => {
  test("parses supported levels case-insensitively", () => {
    expect(parseLogLevel(" DEBUG ")).toBe("debug");
    expect(parseLogLevel("warn")).toBe("warn");
    expect(parseLogLevel("SILENT")).toBe("silent");
  });

  test("defaults invalid or missing values to info", () => {
    expect(parseLogLevel(undefined)).toBe("info");
    expect(parseLogLevel("verbose")).toBe("info");
  });
});
