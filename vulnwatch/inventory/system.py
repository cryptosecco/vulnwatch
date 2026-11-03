"""macOS version, application bundles and loose Node/Bun runtimes."""
import glob
import os
import plistlib
import re
from typing import List, Sequence

from ..config import RuntimeSpec
from ..i18n import t
from ..model import InventoryItem

_TEAM_RE = re.compile(r"^TeamIdentifier=(\S+)$", re.MULTILINE)
_VERSION_RE = re.compile(r"^v?(\d+(?:\.\d+)*)")
_RUNTIME_ENV = {"PATH": "/usr/bin:/bin"}
CHROME_ID = "com.google.Chrome"


def macos_item(run) -> InventoryItem:
    argv = ["/usr/bin/sw_vers", "-productVersion"]
    r = run(argv, timeout=10)
    version = r.stdout.strip() if r.returncode == 0 else ""
    if not version:
        raise RuntimeError(t("cannot read the macOS version", "impossibile leggere la versione di macOS"))
    return InventoryItem("macos", "macos", version, None, None, "/System")


def team_id(path: str, run):
    r = run(["/usr/bin/codesign", "-dv", "--verbose=2", path], timeout=30)
    m = _TEAM_RE.search((r.stderr or "") + (r.stdout or ""))
    if not m or m.group(1) == "not":
        return None
    return m.group(1)


def apps(app_dirs: Sequence[str], run) -> List[InventoryItem]:
    out = []
    for d in app_dirs:
        if not os.path.isdir(d):
            continue
        for name in sorted(os.listdir(d)):
            path = os.path.join(d, name)
            if not name.endswith(".app") or os.path.islink(path):
                continue
            try:
                with open(os.path.join(path, "Contents", "Info.plist"), "rb") as f:
                    info = plistlib.load(f)
            except Exception:  # noqa: BLE001 - any unreadable plist means "skip this app"
                continue
            if not isinstance(info, dict):
                continue
            bid = info.get("CFBundleIdentifier")
            ver = info.get("CFBundleShortVersionString") or info.get("CFBundleVersion")
            if not isinstance(bid, str) or not isinstance(ver, str) or not bid or not ver:
                continue
            disp = info.get("CFBundleName")
            out.append(InventoryItem(
                kind="app",
                name=bid,
                version=ver,
                ecosystem=None,
                channel="google_updater" if bid == CHROME_ID else None,
                location=path,
                team_id=team_id(path, run),
                display_name=disp if isinstance(disp, str) else None,
            ))
    return out


def runtimes(specs: Sequence[RuntimeSpec], run) -> List[InventoryItem]:
    out = []
    for spec in specs:
        for p in sorted(glob.glob(spec.path)):
            real = os.path.realpath(p)
            if not os.path.isfile(real) or not os.access(real, os.X_OK):
                continue
            r = run([p, "--version"], timeout=10, env=dict(_RUNTIME_ENV))
            if r.returncode != 0:
                continue
            first = (r.stdout or "").strip().splitlines()[:1]
            m = _VERSION_RE.match(first[0]) if first else None
            if not m:
                continue
            out.append(InventoryItem("runtime", spec.product, m.group(1), None, None, real, display_name=spec.label))
    return out
