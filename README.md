# discord-scam-killer

Discord bot that matches scam images against local samples and reports detections to moderators.

1. Install [Bun 1.4.4 or newer](https://bun.com/) and run `bun install`.
2. Use `example.env` as a template for `.env`. Set `DISCORD_TOKEN`, `UPTIME_KUMA_URL`, and `DISCORD_GUILDS`. Add one entry per server with its server ID and private report channel ID. `pingRoleId` and `sensitivity` are optional.
3. Enable **Message Content Intent** in the Discord Developer Portal. Install the bot with the `bot` scope. Grant it **View Channel**, **Read Message History**, **Send Messages**, **Embed Links**, **Attach Files**, **Manage Messages**, **Moderate Members**, and **Ban Members**. Place its role above the roles it should moderate.
4. Create `samples/`, add reference images, and run `bun start`. Restart after changing settings or samples.

When upgrading, move server settings to `DISCORD_GUILDS` before starting. SQLite keeps confirmed bans.
