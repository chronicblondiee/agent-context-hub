# Agent Context Hub

Self-hosted shared context, memory and task coordination for humans and coding agents.
Includes authenticated REST/MCP, project grants, hybrid search, troubleshooting,
an optional web UI and federation, and a Python CLI with Claude Code/Codex plugins.
MIT licensed; see LICENSE.

## Build and start locally

Use Linux, Docker Engine with Compose v2 and BuildKit, Git, Bash, and a non-root
account with Docker access. The CLI requires Python 3.11+. Server dependencies run
inside containers. The first build downloads pinned base images, SQLite and the
embedding model; the resulting core can run offline. No registry account is needed.

```sh
scripts/hub.sh build
scripts/hub.sh bootstrap local
scripts/hub.sh up local
scripts/hub.sh status local
curl --fail http://127.0.0.1:8097/health/live
```

Bootstrap creates only the service administrator and saves its key with mode 600
at `.local/stacks/local/admin/admin.key`. It refuses an already bootstrapped database.
The default listener is `127.0.0.1:8097`. Set `HUB_PORT` to use another port. State
and backups live in ignored `.local/stacks/STACK/` directories. `down` stops containers
without deleting data. Do not run two checkouts with the same stack name.

## Create your project and client credentials

The administrator provisions access but cannot read project content. These examples
create a project named `pilot`, a human owner, and an agent acting for that human.
Choose your own identifiers. Keep generated keys private; do not commit them.

```sh
scripts/hub.sh admin local POST /v2/admin/projects <<<'{"id":"pilot","name":"Pilot"}'
scripts/hub.sh admin local POST /v2/admin/principals <<<'{"id":"owner","kind":"human"}'
scripts/hub.sh admin local POST /v2/admin/grants <<<'{"principal":"owner","project":"pilot","role":"contributor"}'
scripts/hub.sh admin local POST /v2/admin/grants <<<'{"principal":"owner","project":"pilot","role":"maintainer"}'
scripts/hub.sh admin local POST /v2/admin/principals <<<'{"id":"assistant","kind":"agent","acts_for":"owner"}'
scripts/hub.sh admin local POST /v2/admin/grants <<<'{"principal":"assistant","project":"pilot","role":"contributor"}'
umask 077
scripts/hub.sh admin local POST /v2/admin/keys <<<'{"principal":"owner"}' > .local/owner-key.json
scripts/hub.sh admin local POST /v2/admin/keys <<<'{"principal":"assistant"}' > .local/agent-key.json
```

## CLI and agent clients

The standalone client is `plugins/hub/bin/hub`; copy it to a directory on your PATH
as `hub`, or invoke it by that path. It uses only Python's standard library.

For human terminal use, load the human key and configure a personal route:

```sh
export HUB_MCP_KEY=$(python3 -c 'import json; print(json.load(open(".local/owner-key.json"))["key"])')
plugins/hub/bin/hub --human setup --endpoint http://127.0.0.1:8097 --project pilot
plugins/hub/bin/hub --human status
plugins/hub/bin/hub --human --session pilot-check tshoot service:example
plugins/hub/bin/hub --human --session pilot-check show
```

For agents, load the agent key into `HUB_MCP_KEY` before launching the client.
The MCP endpoint is `http://127.0.0.1:8097/mcp`, authenticated with
`Authorization: Bearer <key>`. Configure each agent with its own key.
Install the plugin from this local checkout's marketplace (`agent-context-hub`)
through your client's plugin manager. The plugin lives in `plugins/hub`; local
marketplace manifests are included for both supported clients.
Then, inside the repository you want the agent to work on, run:

```sh
hub setup --client claude --endpoint http://127.0.0.1:8097 --project pilot
# Or: hub setup --client codex --endpoint http://127.0.0.1:8097 --project pilot
hub status
```

Setup writes non-secret `.hub.json` routing and merges MCP configuration. Review
your client's MCP/plugin hook permissions and restart it. Automatic context reads
are opt-in during setup; `HUB_DISABLED=1` or `HUB_NO_MEMORY=1` disables helper memory
activity. Use a distinct `--session SESSION` for each terminal investigation.
`hub --help` lists commands.

Troubleshooting is kept apart from the general task and memory workflow. `hub setup
--client claude|codex` also installs a personal, explicit-only skill: `/tshoot <problem>`
in Claude Code, `$tshoot <problem>` in Codex. Neither client loads it, or the
troubleshooting operations, into the model's context until you invoke it; `hub status`
reports whether the installed copy is current. It retrieves project context plus an
optional curated general library, coordinates shared investigations and reserved
actions, and records sourced outcomes.

The general library is a dedicated project that the administrator designates with
`POST /v2/admin/tshoot-library {"project": "ID"}` after granting readers explicitly.
Entries reach it only when a human maintainer of both the source project and the
library publishes a sanitized proposal (`/ui/p/PROJECT/proposals`); revising or
revoking the source withdraws the entry.

For portable archives, run `scripts/hub.sh package-cli` or
`scripts/hub.sh package-plugin`; outputs and checksums are under `.local/`.

## Local verification

```sh
scripts/hub.sh lint
scripts/hub.sh test
```

Tests use isolated temporary storage and Compose projects. They cover server and
client behaviour, REST/MCP access, crash recovery, backup/restore, offline startup,
and optional federation against an ephemeral NATS broker. Run `unit` or `integration`
instead of `test` to run those groups separately. No hosted CI is required.

## Maintenance and optional services

```sh
scripts/hub.sh backup local
scripts/hub.sh down local
# After updating source:
scripts/hub.sh build
scripts/hub.sh migrate local
scripts/hub.sh up local
```

Take a backup before updating. Migrations and offline administration require the
core to be stopped. Restore a backup into a new stack with
`scripts/hub.sh restore restored /absolute/path/to/backup`, then run
`scripts/hub.sh admin-key restored` and `scripts/hub.sh up restored`.
Restoring revokes all old keys: issue new human/agent credentials through the
recovered administrator. A second stack uses an ephemeral loopback port by default;
`up` prints it. Never replace an existing database with a restore.

The web UI is disabled by default. `HUB_UI=1 scripts/hub.sh up local` enables a
local-only view at `/ui`. For a shared deployment, provide your own HTTPS reverse
proxy and use `HUB_UI=auth` (its login cookie requires HTTPS). Set `HUB_BIND` only
when intentionally exposing the service, and restrict access at your network boundary.
Default core limits are one CPU and 512 MiB; assess capacity for your own workload.

Federation is optional: configure a project-granted transport key in
`.local/stacks/STACK/federation-secrets/hub.key` and a NATS configuration in
`nats.json`, then run `scripts/hub.sh federation-up STACK PROJECT`.
See `hub/federation_transport.py` for the configuration contract and
`tests/integration_hub_federation.py` for a complete isolated example.
The optional `broker-up STACK` command requires your own `nats.conf` in the same
directory. Neither service is started with the default core deployment.
