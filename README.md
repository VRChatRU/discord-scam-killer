# discord-scam-killer

Discord bot that matches scam images against local samples and reports detections to moderators.

1. Install [Bun 1.4.4 or newer](https://bun.com/) and run `bun install`.
2. Copy `example.env` to `.env` and set `DISCORD_TOKEN` and `UPTIME_KUMA_URL`.
3. Enable **Message Content Intent** in the Discord Developer Portal. Install the bot with `bot` and `applications.commands`. Grant it **View Channel**, **Read Message History**, **Send Messages**, **Embed Links**, **Attach Files**, **Manage Messages**, **Moderate Members**, and **Ban Members**. Place its role above the roles it should moderate.
4. Run `bun start`. An administrator can configure a private report channel with `/setup channel:#mod-log sensitivity:balanced` and optionally set `ping_role`.

Update reference images in `samples/` and restart. To migrate from BeastKiller, stop the old bot and copy `data/beastkiller.sqlite` to `discord-scam-killer.db` before starting the new one.
