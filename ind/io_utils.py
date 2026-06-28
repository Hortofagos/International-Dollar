# Small filesystem helpers used by tools and runtime support modules.

import json
import os
from pathlib import Path


def atomic_write_text(path, text, *, encoding="utf-8", newline=None):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("w", encoding=encoding, newline=newline) as handle:
        handle.write(text)
    os.replace(tmp, path)


def atomic_write_json(path, data, *, sort_keys=True, indent=2, ensure_ascii=True):
    atomic_write_text(
        path,
        json.dumps(data, sort_keys=sort_keys, indent=indent, ensure_ascii=ensure_ascii) + "\n",
        encoding="utf-8",
    )
