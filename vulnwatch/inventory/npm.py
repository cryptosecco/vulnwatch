"""Globally installed npm packages under one prefix. Symlinked (npm link) packages are not registry installs: skipped."""
import json
import os
from typing import List, Optional

from ..model import InventoryItem


def _read(path: str, expected: str, prefix: str) -> Optional[InventoryItem]:
    if os.path.islink(path) or not os.path.isdir(path):
        return None
    try:
        with open(os.path.join(path, "package.json"), encoding="utf-8") as f:
            pj = json.load(f)
    except (OSError, ValueError):
        return None
    if not isinstance(pj, dict) or pj.get("name") != expected or not isinstance(pj.get("version"), str):
        return None
    return InventoryItem("npm_global", expected, pj["version"], "npm", "npm_global", prefix)


def npm_globals(prefix: str) -> List[InventoryItem]:
    root = os.path.join(prefix, "lib", "node_modules")
    if not os.path.isdir(root):
        return []
    out = []
    for entry in sorted(os.listdir(root)):
        if entry.startswith("."):
            continue
        path = os.path.join(root, entry)
        if entry.startswith("@"):
            if os.path.islink(path) or not os.path.isdir(path):
                continue
            for sub in sorted(os.listdir(path)):
                item = _read(os.path.join(path, sub), "%s/%s" % (entry, sub), prefix)
                if item:
                    out.append(item)
        else:
            item = _read(path, entry, prefix)
            if item:
                out.append(item)
    return out
