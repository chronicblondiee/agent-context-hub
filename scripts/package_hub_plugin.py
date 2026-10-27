"""Reproducible plugin archive; invoked by the container-only hub.sh wrapper."""

import hashlib
import json
import sys
import zipfile
from pathlib import Path

source = Path("/source/plugins/hub")
version = json.loads((source / ".claude-plugin/plugin.json").read_text())["version"]
assert version == json.loads((source / ".codex-plugin/plugin.json").read_text())["version"]
output = Path(sys.argv[1]) / f"hub-{version}.zip"
with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
    for path in sorted(source.rglob("*")):
        if not path.is_file() or "__pycache__" in path.parts:
            continue
        if path.is_symlink():
            raise ValueError("plugin packages cannot contain symlinks")
        info = zipfile.ZipInfo(path.relative_to(source).as_posix(), (1980, 1, 1, 0, 0, 0))
        info.external_attr = (0o100755 if path.name == "hub" else 0o100644) << 16
        info.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(info, path.read_bytes())
digest = hashlib.sha256(output.read_bytes()).hexdigest()
output.with_suffix(".zip.sha256").write_text(f"{digest}  {output.name}\n")
print(f"{output.name}: sha256:{digest}")
