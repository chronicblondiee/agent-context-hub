"""python -m hub [serve] | migrate | bootstrap NAME | admin METHOD PATH |
    backup ROOT [LABEL] | prune ROOT | restore BACKUP | admin-key NAME

The database is $HUB_DB (default /data/hub.sqlite3). bootstrap creates the first service
administrator once and writes only its key to stdout.
backup (core stopped) writes the same backup the live core makes through the admin API; prune
applies daily/weekly retention; restore fills an empty data directory from a verified backup and
revokes every key; admin-key then reissues a key for an existing service administrator.
admin sends one request to $HUB_URL (default http://core:8097) with the key in $HUB_ADMIN_KEY
(default /admin/admin.key) and the JSON body read from stdin; the key never appears in arguments.
"""

import os
import sys

from hub import app, store

path = os.environ.get("HUB_DB", "/data/hub.sqlite3")
command = sys.argv[1] if len(sys.argv) > 1 else "serve"
if command == "migrate":
    print(f"schema version {store.migrate(path)}")
elif command == "bootstrap" and len(sys.argv) == 3:
    from hub import identity

    s = store.Store(path)
    try:
        sys.stdout.write(identity.bootstrap(s, sys.argv[2])["key"] + "\n")
    finally:
        s.close()
elif (command, len(sys.argv)) in (
    ("backup", 3),
    ("backup", 4),
    ("prune", 3),
    ("restore", 3),
    ("admin-key", 3),
):
    import json

    from hub import backup, identity

    try:
        if command == "prune":
            print(json.dumps({"kept": backup.prune(sys.argv[2])}))
        elif command == "restore":
            print(json.dumps(backup.restore(sys.argv[2], path)))
        else:
            s = store.Store(path)
            try:
                if command == "backup":
                    print(json.dumps(backup.create(s, *sys.argv[2:])))
                else:
                    sys.stdout.write(identity.recover_admin(s, sys.argv[2])["key"] + "\n")
            finally:
                s.close()
    except (ValueError, OSError, store.SchemaMismatch) as error:
        sys.exit(f"{command} refused: {error}")
elif command == "admin" and len(sys.argv) == 4:
    import urllib.error
    import urllib.request

    with open(os.environ.get("HUB_ADMIN_KEY", "/admin/admin.key")) as f:
        key = f.read().strip()
    body = sys.stdin.buffer.read() if not sys.stdin.isatty() else b""
    request = urllib.request.Request(
        os.environ.get("HUB_URL", "http://core:8097") + sys.argv[3],
        data=body or None,
        method=sys.argv[2],
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request) as response:
            sys.stdout.write(response.read().decode() + "\n")
    except urllib.error.HTTPError as error:
        sys.exit(f"{error.code} {error.read().decode()}")
elif command == "serve":
    import uvicorn

    app.state.store = store.Store(path)  # refuses an unmigrated or mismatched database
    uvicorn.run(app, host="0.0.0.0", port=8097)
else:
    sys.exit(__doc__)
