import { describe, expect, test } from "bun:test";
import { setupCommand } from "../src/setup-command.ts";

describe("setup command", () => {
  test("keeps the report channel required and moderation role optional", () => {
    const command = setupCommand.toJSON();
    const channel = command.options?.find(
      (option) => option.name === "channel",
    );
    const role = command.options?.find((option) => option.name === "ping_role");

    expect(
      channel && "required" in channel ? channel.required : false,
    ).toBeTrue();
    expect(role && "required" in role ? role.required : false).toBeFalse();
  });
});
