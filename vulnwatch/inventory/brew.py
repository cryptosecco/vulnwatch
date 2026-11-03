"""Homebrew formulae and casks from `brew info --json=v2 --installed`."""
from typing import List

from ..model import InventoryItem

BREW_ENV = {
    "HOMEBREW_NO_AUTO_UPDATE": "1",
    "HOMEBREW_NO_ANALYTICS": "1",
    "HOMEBREW_NO_ENV_HINTS": "1",
    "HOMEBREW_NO_INSTALL_CLEANUP": "1",
    "HOMEBREW_NO_AUTOREMOVE": "1",
}


def brew_items(info: dict) -> List[InventoryItem]:
    out = []
    for f in info.get("formulae") or []:
        name, tap = f.get("name"), f.get("tap")
        versions = [i.get("version") for i in (f.get("installed") or []) if isinstance(i, dict)]
        versions = [v for v in versions if isinstance(v, str) and v]
        if not versions or not isinstance(name, str):
            continue
        # Old kegs are kept on purpose (no cleanup): the version in use is the linked one, else the newest.
        linked = f.get("linked_keg")
        version = linked if linked in versions else versions[-1]
        out.append(InventoryItem("brew_formula", name, version, None, tap if isinstance(tap, str) else None, "/opt/homebrew"))
    for c in info.get("casks") or []:
        token, ver, tap = c.get("token"), c.get("installed"), c.get("tap")
        if not isinstance(token, str) or not isinstance(ver, str):
            continue
        out.append(InventoryItem("brew_cask", token, ver, None, tap if isinstance(tap, str) else None, "/opt/homebrew"))
    return out
