# Alert Notifier

This utility polls Kibana alerts and posts state changes to Microsoft Teams and/or Webex. It can run locally for experimentation or inside Kubernetes (via the Helm charts in this repository).

## Local development

1. Set up a virtual environment and install dependencies:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

2. Provide credentials and execute the notifier:
   ```bash
   export ES_URL=https://elastic.example:9200
   export ES_USER=elastic
   export ES_PASS=supersecret
   export TEAMS_WEBHOOK_URL="https://outlook.office.com/webhook/..."        # optional
   export WEBEX_BOT_TOKEN="<bot-token>"                                     # optional
   export WEBEX_ROOM_ID="Y2lzY29zcGFyazovL3VzL1JPT00v..."                  # or WEBEX_PERSON_EMAIL=user@example.com

   python eck_notifier.py --state /var/lib/eck-notifier/state.json \
     --enable-teams --enable-webex
   ```

   Drop `--enable-teams`/`--enable-webex` (or set the matching `ENABLE_*` env vars) if you only want one destination. Append `--dry-run` to preview the diff without sending messages.

The script accepts either a JSON file containing current alerts or, if no file path is provided, it will query Elasticsearch directly using the credentials above.

### Helper utilities

- `teams_send.py` – send a test message to the configured Teams webhook.
- `webex_send.py` – send a test message to a Webex room or direct recipient. The helper understands `webexteams://` links or UI “space IDs” and converts them to the API `roomId` automatically. Pass `--token` or set `WEBEX_BOT_TOKEN` to supply the bot credential.
- `notifier.py` – one-off Teams poke that reads the webhook from `TEAMS_WEBHOOK_URL`. Use it for quick smoke tests without touching the full notifier.
