#!/usr/bin/env bash
# Local Docker build, verification and operation.
# Usage: scripts/hub.sh build|lint|unit|integration|test|package-cli|package-plugin
#        scripts/hub.sh bootstrap|up|down|status|migrate|backup|admin-key [STACK]
#        scripts/hub.sh admin STACK METHOD PATH | restore STACK BACKUP_DIR
#        scripts/hub.sh federation-up STACK PROJECT | federation-down STACK
#        scripts/hub.sh broker-up|broker-down STACK
#        scripts/hub.sh checker-up STACK PROJECT | checker-down STACK
set -euo pipefail
umask 077
source_root=$(cd -- "$(dirname -- "$0")/.." && pwd)
runtime=${HUB_IMAGE:-hub-public-runtime}
verification=${HUB_VERIFY_IMAGE:-hub-public-verification}
operator=${HUB_OPERATOR_IMAGE:-hub-public-operator}
federation=${HUB_FEDERATION_IMAGE:-hub-public-federation}
checker=${HUB_CHECKER_IMAGE:-hub-public-checker}
export HUB_VERIFY_IMAGE=$verification
export HUB_IMAGE=$runtime HUB_UID=$(id -u) HUB_GID=$(id -g) HUB_PORT=${HUB_PORT:-}

stack() {
  [[ "$1" =~ ^[a-z0-9][a-z0-9-]*$ ]] || { echo "invalid stack name: $1" >&2; exit 2; }
  project="hub-public-$1"
  [[ "$1" != local ]] || export HUB_PORT=${HUB_PORT:-8097}
  export HUB_STATE="$source_root/.local/stacks/$1"
  compose=(docker compose -p "$project" -f "$source_root/compose.hub.yaml")
  # secrets: the core's read-only mount. admin: the operator's key, never mounted into the core.
  mkdir -p "$HUB_STATE/data" "$HUB_STATE/secrets" "$HUB_STATE/admin" "$HUB_STATE/backups" \
    "$HUB_STATE/federation-secrets" "$HUB_STATE/nats-data" "$HUB_STATE/checker-secrets"
  chmod 700 "$HUB_STATE/secrets" "$HUB_STATE/admin" "$HUB_STATE/federation-secrets" \
    "$HUB_STATE/checker-secrets"
  exec 9>"$HUB_STATE/.lock"
  flock -x 9
  # The "hub-public-" prefix keeps other Compose projects out of reach; also refuse a hub project another checkout owns.
  while IFS= read -r container; do
    [[ -n "$container" ]] || continue
    owner=$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project.config_files"}}' "$container")
    if [[ "$owner" != "$source_root/compose.hub.yaml" ]]; then
      echo "Compose project $project is owned by $owner; choose another name." >&2
      exit 1
    fi
  done < <("${compose[@]}" ps --all -q)
}

# --init reaps orphans, which tests that kill process groups need to see a group settle.
verify() { docker run --rm --init --network none --user "$HUB_UID:$HUB_GID" "$verification" "$@"; }
operate() {
  # SQLite needs a writable temp dir for statement journals (e.g. a migration's UPDATE).
  docker run --rm --user "$HUB_UID:$HUB_GID" --read-only --tmpfs /tmp:size=64m --cap-drop ALL \
    --security-opt no-new-privileges:true "$@"
}
offline() {
  if [[ -n "$("${compose[@]}" ps --status running -q core)" ]]; then
    echo "Stop the core ($project) before $1." >&2
    exit 1
  fi
}

# Offline schema migration: operator image, core stopped, only the data directory mounted.
migrate() {
  offline "migrating its database"
  operate --network none -v "$HUB_STATE/data:/data:z" "$operator" python -m hub migrate
}

bootstrap() {
  offline "bootstrapping"
  [[ -f "$HUB_STATE/data/hub.sqlite3" ]] || migrate >&2
  operate --network none -v "$HUB_STATE/data:/data:z" "$operator" \
    python -m hub bootstrap "${HUB_ADMIN:-admin}"
}

admin() {
  [[ -s "$HUB_STATE/admin/admin.key" ]] \
    || { echo "Run bootstrap for this stack first." >&2; exit 1; }
  local stdin=()
  [[ -t 0 ]] || stdin=(-i)
  operate "${stdin[@]}" --network "${project}_default" -v "$HUB_STATE/admin:/admin:ro,z" \
    "$operator" python -m hub admin "$1" "$2"
}

# Backup: through the live core's admin API, or the same code offline when the core is stopped
# (optionally labelled, which exempts it from retention); then daily/weekly retention. Restore fills an empty, stopped stack and revokes every key.
backup() {
  local previous_code=() previous_revision=()
  [[ -z "${3:-}" ]] || previous_code=(-v "$3:/app/hub:ro,z")
  [[ -z "${4:-}" ]] || previous_revision=(-e "HUB_SOURCE_REVISION=$4")
  if [[ -n "$("${compose[@]}" ps --status running -q core)" ]]; then
    admin POST /v2/admin/backups </dev/null
  else
    operate --network none -v "$HUB_STATE/data:/data:z" -v "$HUB_STATE/backups:/backups:z" \
      "${previous_code[@]}" "${previous_revision[@]}" "${2:-$operator}" python -m hub backup /backups ${1:+"$1"}
  fi
  operate --network none -v "$HUB_STATE/backups:/backups:z" "$operator" python -m hub prune /backups
}
restore() {
  offline "restoring"
  [[ ! -e "$HUB_STATE/data/hub.sqlite3" ]] || { echo "$project already has data" >&2; exit 1; }
  operate --network none -v "$HUB_STATE/data:/data:z" -v "$(realpath -e "$1"):/restore:ro,z" \
    "$operator" python -m hub restore /restore
}

# A new stack gets its schema here; an existing database is upgraded only by an explicit migrate.
start() {
  [[ -f "$HUB_STATE/data/hub.sqlite3" ]] || migrate
  "${compose[@]}" up -d --no-build --wait
}

harness() {
  local run="test-$(date -u +%Y%m%d%H%M%S)-$$" container
  stack "$run"
  trap '"${compose[@]}" down --volumes --remove-orphans; rm -rf "$HUB_STATE"' EXIT
  bootstrap >"$HUB_STATE/admin/admin.key"
  if (bootstrap) >/dev/null 2>&1; then echo 'second bootstrap succeeded' >&2; exit 1; fi
  start
  if (migrate) 2>/dev/null; then echo 'migrate ran against a live core' >&2; exit 1; fi
  container=$("${compose[@]}" ps -q core)
  [[ "$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}} {{.HostConfig.CapDrop}} {{.HostConfig.SecurityOpt}} {{.Config.User}}' "$container")" \
    == "true [ALL] [no-new-privileges:true] $HUB_UID:$HUB_GID" ]] || { echo 'core hardening missing' >&2; exit 1; }
  ! docker inspect --format '{{range .Mounts}}{{.Source}} {{end}}' "$container" | grep -q docker.sock \
    || { echo 'Docker socket mounted' >&2; exit 1; }
  docker exec "$container" sh -ec '[ "$(id -u)" != 0 ]; if touch /probe 2>/dev/null; then exit 1; fi
    touch /tmp/probe; [ ! -e /var/run/docker.sock ]; grep -q "^CapEff:[[:space:]]*0*$" /proc/self/status'
  [[ "$("${compose[@]}" port core 8097)" == 127.0.0.1:* ]] || { echo 'port not loopback-only' >&2; exit 1; }
  docker run --rm --network "${project}_default" "$verification" python -c '
import urllib.error, urllib.request
assert urllib.request.urlopen("http://core:8097/health/live").status == 200
for path in ("/docs", "/openapi.json"):
    try:
        urllib.request.urlopen("http://core:8097" + path)
        raise SystemExit(path + " is anonymously reachable")
    except urllib.error.HTTPError as error:
        assert error.code == 404, path'
  # SIGKILL the core mid-write: every acknowledged commit survives and the database stays intact.
  : >"$HUB_STATE/acked"
  docker exec "$container" python -c '
from hub.store import Store
s = Store("/data/hub.sqlite3")
s.create_project("crash", "crash", "harness")
i = 0
while True:
    i += 1
    def fn(tx, ident=f"k{i}"):
        tx.execute("INSERT INTO objects VALUES (?, ?, ?, ?)", ["crash", "task", ident, "{}"])
        tx.audit("task.create", ident, {})
        return ident
    print(s.mutate("crash", "harness", fn), flush=True)' >"$HUB_STATE/acked" &
  local writer=$!
  until [[ $(wc -l <"$HUB_STATE/acked") -ge 200 ]]; do
    kill -0 "$writer" 2>/dev/null || { echo 'crash writer exited early' >&2; exit 1; }
    sleep 0.1
  done
  docker kill -s KILL "$container" >/dev/null
  wait "$writer" || true
  "${compose[@]}" up -d --no-build --wait
  docker exec -i "$("${compose[@]}" ps -q core)" python -c '
import sys
from hub import store
con = store.connect("/data/hub.sqlite3")
assert con.execute("PRAGMA integrity_check").fetchone()[0] == "ok", "integrity check failed"
stored = {r[0] for r in con.execute("SELECT id FROM objects WHERE project_id = ?", ["crash"])}
acked = {line.strip() for line in sys.stdin if line.endswith("\n")}  # a cut-off last line was never acked
assert acked and acked <= stored, f"lost acknowledged writes: {sorted(acked - stored)[:5]}"
print(f"{len(acked)} acknowledged writes survived SIGKILL")' <"$HUB_STATE/acked"
  # Disk pressure: on a full 4 MiB data volume writes fail without acking, the writer survives,
  # and once space returns writes succeed again with every acknowledged one intact.
  docker run --rm --network none --read-only --user "$HUB_UID:$HUB_GID" \
    --mount type=tmpfs,destination=/data,tmpfs-size=4194304,tmpfs-mode=1777 "$HUB_IMAGE" \
    timeout 120 python -c '
import json, os, sqlite3
from hub.store import Store, connect, migrate
migrate("/data/hub.sqlite3")
s = Store("/data/hub.sqlite3")
s.create_project("full", "full", "harness")
with open("/data/ballast", "wb") as f:
    f.write(b"\0" * 1048576)
def put(ident):
    def fn(tx):
        tx.execute("INSERT INTO objects VALUES (?, ?, ?, ?)", ["full", "task", ident, json.dumps("x" * 4000)])
        tx.audit("task.create", ident, {})
        return ident
    return s.mutate("full", "harness", fn)
acked, i = [], 0
while True:
    i += 1
    try:
        acked.append(put(f"k{i}"))
    except sqlite3.OperationalError as error:
        assert "full" in str(error), error
        break
os.remove("/data/ballast")
acked.append(put("after"))
s.close()
con = connect("/data/hub.sqlite3")
assert con.execute("PRAGMA integrity_check").fetchone()[0] == "ok", "integrity check failed"
stored = {r[0] for r in con.execute("SELECT id FROM objects WHERE project_id = ?", ["full"])}
assert set(acked) <= stored and f"k{i}" not in stored, "disk-full write lost or half-applied"
print(f"disk full ok: {len(acked) - 1} acked before full, writer recovered after space returned")'
  # Identity flow: the admin provisions an agent, which works over REST and MCP until revoked.
  admin POST /v2/admin/projects <<<'{"id": "harness", "name": "harness"}' >/dev/null
  admin POST /v2/admin/principals <<<'{"id": "agent", "kind": "agent"}' >/dev/null
  admin POST /v2/admin/grants <<<'{"principal": "agent", "project": "harness", "role": "contributor"}' >/dev/null
  admin POST /v2/admin/keys <<<'{"principal": "agent"}' >"$HUB_STATE/admin/agent.json"
  admin POST /v2/admin/principals <<<'{"id": "verifier", "kind": "verifier"}' >/dev/null
  admin POST /v2/admin/grants <<<'{"principal": "verifier", "project": "harness", "role": "verifier"}' >/dev/null
  admin POST /v2/admin/keys <<<'{"principal": "verifier"}' >"$HUB_STATE/admin/verifier.json"
  admin POST /v2/admin/principals <<<'{"id": "maintainer", "kind": "human"}' >/dev/null
  admin POST /v2/admin/grants <<<'{"principal": "maintainer", "project": "harness", "role": "maintainer"}' >/dev/null
  admin POST /v2/admin/keys <<<'{"principal": "maintainer"}' >"$HUB_STATE/admin/maintainer.json"
  docker run --rm --network "${project}_default" --user "$HUB_UID:$HUB_GID" \
    -v "$HUB_STATE/admin:/admin:ro,z" "$verification" python tests/integration_hub_knowledge.py
  docker run --rm --network "${project}_default" --user "$HUB_UID:$HUB_GID" \
    -v "$HUB_STATE/admin:/admin:ro,z" "$verification" python tests/integration_hub_identity.py
  container=$("${compose[@]}" ps -q core)
  echo "loaded-core memory: $(docker stats --no-stream --format '{{.MemUsage}}' "$container")"
  # Captured first: grep exiting early under pipefail would otherwise hide a match.
  local surfaces
  surfaces=$("${compose[@]}" logs 2>&1; docker inspect "$("${compose[@]}" ps -q core)")
  if grep -E 'hub_[0-9a-f]{16}_[A-Za-z0-9_-]{43}' <<<"$surfaces" >/dev/null; then
    echo 'a key secret appears in container logs or configuration' >&2
    exit 1
  fi
  # Online backup under the live core, restored into a fresh stack: data and artifacts return,
  # every key is revoked there, and only an offline-recovered admin key works.
  backup >/dev/null
  local saved old_keys="$HUB_STATE/admin"
  saved=$(find "$HUB_STATE/backups" -mindepth 1 -maxdepth 1 -name '2*' | sort | tail -1)
  (
    stack "$run-restore"
    trap '"${compose[@]}" down --volumes --remove-orphans; rm -rf "$HUB_STATE"' EXIT
    restore "$saved" >/dev/null
    operate --network none -v "$HUB_STATE/data:/data:z" "$operator" \
      python -m hub admin-key "${HUB_ADMIN:-admin}" >"$HUB_STATE/admin/admin.key"
    # Offline startup: the restored core starts healthy and embeds with no network at all.
    local offline_core
    offline_core=$(docker run -d --network none --read-only --tmpfs /tmp:size=64m \
      --cap-drop ALL --security-opt no-new-privileges:true --user "$HUB_UID:$HUB_GID" \
      -v "$HUB_STATE/data:/data:z" -v "$HUB_STATE/secrets:/secrets:ro,z" "$HUB_IMAGE")
    while [[ "$(docker inspect --format '{{.State.Running}} {{.State.Health.Status}}' "$offline_core")" \
      == "true starting" ]]; do sleep 1; done
    [[ "$(docker inspect --format '{{.State.Health.Status}}' "$offline_core")" == healthy ]] \
      && docker exec "$offline_core" python -c 'from hub.embed import Embedder
assert Embedder().embed(["docker restart"]), "model did not load offline"
print("offline startup ok: healthy and embedding with no network")' \
      || { docker logs "$offline_core" >&2; docker rm -f "$offline_core" >/dev/null; exit 1; }
    docker rm -f "$offline_core" >/dev/null
    start >/dev/null
    docker exec "$("${compose[@]}" ps -q core)" python -c '
from hub import store
con = store.connect("/data/hub.sqlite3")
assert con.execute("SELECT count(*) FROM objects WHERE project_id = ?", ["crash"]).fetchone()[0] >= 200'
    docker run --rm --network "${project}_default" --user "$HUB_UID:$HUB_GID" \
      -v "$old_keys:/old:ro,z" -v "$HUB_STATE/admin:/admin:ro,z" "$verification" python -c '
import json, urllib.error, urllib.request
def post(key, path, body):
    req = urllib.request.Request("http://core:8097" + path, data=json.dumps(body).encode(),
        headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"})
    try:
        return urllib.request.urlopen(req).status
    except urllib.error.HTTPError as error:
        return error.code
old = json.load(open("/old/agent.json"))["key"]
assert post(old, "/v2/projects/harness/work/work_read", {"kind": "task"}) == 401, "restored key works"
assert post(open("/old/admin.key").read().strip(), "/v2/admin/principals", {}) == 401
assert post(open("/admin/admin.key").read().strip(), "/v2/admin/principals",
            {"id": "restored", "kind": "agent"}) == 200, "recovered admin key refused"
print("restore ok: data back, every old key revoked, recovered admin key works")'
  )
  echo "harness ok: $project"
}

case "${1:-}" in
  build)
    revision=$(git -C "$source_root" rev-parse HEAD)
    [[ -z "$(git -C "$source_root" status --porcelain)" ]] || revision+=-dirty
    lock=$(sha256sum "$source_root/uv.lock" | cut -d' ' -f1)
    schema=$(find "$source_root/hub/migrations" -name '*.sql' | wc -l)
    docker build --target hub-runtime -t "$runtime" --build-arg SOURCE_REVISION="$revision" \
      --build-arg LOCK_SHA256="$lock" --build-arg SCHEMA_VERSION="$schema" "$source_root"
    docker build --target hub-operator -t "$operator" --build-arg SOURCE_REVISION="$revision" \
      "$source_root"
    docker build --target hub-federation -t "$federation" "$source_root"
    docker build --target hub-checker -t "$checker" "$source_root"
    docker build --target hub-verification -t "$verification" "$source_root"
    docker build --target hub-cli-smoke "$source_root" ;;
  lock)
    docker build --target toolchain -t hub-toolchain "$source_root"
    docker run --rm --user "$HUB_UID:$HUB_GID" -e UV_CACHE_DIR=/src/.local/uv-cache \
      -v "$source_root:/src:z" -w /src hub-toolchain uv lock ;;
  package-cli)
    mkdir -p "$source_root/.local/cli"
    docker run --rm --network none --user "$HUB_UID:$HUB_GID" \
      -v "$source_root:/source:ro,z" -v "$source_root/.local/cli:/output:z" \
      "$verification" sh /source/scripts/package_hub_cli.sh /output \
      "$(git -C "$source_root" rev-parse HEAD)" ;;
  package-plugin)
    mkdir -p "$source_root/.local/plugins"
    docker run --rm --network none --user "$HUB_UID:$HUB_GID" \
      -v "$source_root:/source:ro,z" -v "$source_root/.local/plugins:/output:z" \
      "$verification" python /source/scripts/package_hub_plugin.py /output ;;
  lint) verify sh -ec 'export RUFF_NO_CACHE=true; cd /source; ruff check .; ruff format --check .' ;;
  test)
    verify python -m unittest
    (harness)
    bash "$source_root/tests/run_hub_federation.sh" ;;
  unit) verify python -m unittest ;;
  integration) (harness); bash "$source_root/tests/run_hub_federation.sh" ;;
  up)
    stack "${2:-local}"
    start
    "${compose[@]}" port core 8097 ;;
  down) stack "${2:-local}"; "${compose[@]}" down ;;
  checker-up)
    [[ $# -eq 3 ]] || { echo 'usage: scripts/hub.sh checker-up STACK PROJECT' >&2; exit 2; }
    stack "$2"
    [[ "$3" =~ ^[a-z0-9][a-z0-9-]*$ ]] || { echo 'invalid project' >&2; exit 2; }
    export HUB_CHECK_PROJECT=$3 HUB_CHECKER_IMAGE=$checker
    [[ -s "$HUB_STATE/checker-secrets/hub.key" && -s "$HUB_STATE/checker-secrets/sources.json" ]] \
      || { echo 'provision checker-secrets/hub.key and sources.json first' >&2; exit 1; }
    "${compose[@]}" --profile checker up -d --no-build --wait checker ;;
  checker-down)
    stack "$2"
    "${compose[@]}" --profile checker stop checker ;;
  federation-up)
    [[ $# -eq 3 ]] || { echo 'usage: scripts/hub.sh federation-up STACK PROJECT' >&2; exit 2; }
    stack "$2"
    [[ "$3" =~ ^[a-z0-9][a-z0-9-]*$ ]] || { echo 'invalid project' >&2; exit 2; }
    export HUB_FEDERATION_PROJECT=$3 HUB_FEDERATION_IMAGE=$federation
    [[ -s "$HUB_STATE/federation-secrets/hub.key" \
      && -s "$HUB_STATE/federation-secrets/nats.json" ]] \
      || { echo 'provision federation-secrets/hub.key and nats.json first' >&2; exit 1; }
    "${compose[@]}" --profile federation up -d --no-build --wait federation ;;
  federation-down)
    stack "${2:-local}"
    export HUB_FEDERATION_IMAGE=$federation
    "${compose[@]}" --profile federation stop federation ;;
  broker-up)
    stack "${2:-local}"
    [[ -s "$HUB_STATE/federation-secrets/nats.conf" ]] \
      || { echo 'provision federation-secrets/nats.conf first' >&2; exit 1; }
    "${compose[@]}" --profile broker up -d --no-build broker ;;
  broker-down)
    stack "${2:-local}"
    "${compose[@]}" --profile broker stop broker ;;
  backup) stack "${2:-local}"; backup ;;
  restore)
    [[ $# -eq 3 ]] || { echo 'usage: scripts/hub.sh restore STACK BACKUP_DIR' >&2; exit 2; }
    stack "$2"
    restore "$3" ;;
  admin-key)
    [[ $# -eq 2 || $# -eq 3 ]] || { echo 'usage: scripts/hub.sh admin-key STACK [ADMIN]' >&2; exit 2; }
    stack "$2"
    offline "recovering an admin key"
    operate --network none -v "$HUB_STATE/data:/data:z" "$operator" \
      python -m hub admin-key "${3:-${HUB_ADMIN:-admin}}" >"$HUB_STATE/admin/.recovered.key"
    chmod 600 "$HUB_STATE/admin/.recovered.key"
    mv "$HUB_STATE/admin/.recovered.key" "$HUB_STATE/admin/admin.key" ;;
  status) stack "${2:-local}"; "${compose[@]}" ps --all ;;
  migrate) stack "${2:-local}"; migrate ;;
  bootstrap)
    stack "${2:-local}"
    [[ ! -e "$HUB_STATE/admin/admin.key" ]] || { echo 'admin key already exists' >&2; exit 1; }
    key_tmp=$(mktemp "$HUB_STATE/admin/.bootstrap.XXXXXX")
    trap 'rm -f -- "$key_tmp"' EXIT
    bootstrap >"$key_tmp"
    chmod 600 "$key_tmp"
    mv "$key_tmp" "$HUB_STATE/admin/admin.key"
    echo "Administrator key saved in $HUB_STATE/admin/admin.key" ;;
  admin)
    [[ $# -eq 4 ]] || { sed -n '7p' "$0" >&2; exit 2; }
    stack "$2"
    admin "$3" "$4" ;;
  *) sed -n '3,7p' "$0" >&2; exit 2 ;;
esac
