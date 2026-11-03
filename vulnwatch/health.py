"""Post-upgrade health checks: broken venvs, services still running an old keg, Node in PATH."""
import os
import re
from typing import List, Optional, Sequence, Tuple

from .i18n import t

_SKIP = {"node_modules", ".git", "__pycache__"}
_HOME_RE = re.compile(r"^\s*home\s*=\s*(.+?)\s*$", re.MULTILINE)
_VERSION_RE = re.compile(r"^v?(\d+(?:\.\d+)*)")


def _venv_broken(cfg_path: str) -> bool:
    try:
        with open(cfg_path, encoding="utf-8", errors="replace") as f:
            m = _HOME_RE.search(f.read())
    except OSError:
        return False
    return bool(m) and not os.path.isdir(m.group(1))


def broken_venvs(roots: Sequence[str], max_depth: int = 4) -> List[str]:
    out: List[str] = []

    def walk(d: str, depth: int) -> None:
        cfg = os.path.join(d, "pyvenv.cfg")
        if os.path.isfile(cfg) and _venv_broken(cfg):
            out.append(d)
        if depth >= max_depth:
            return
        try:
            entries = sorted(os.scandir(d), key=lambda e: e.name)
        except OSError:
            return
        for e in entries:
            if e.is_dir(follow_symlinks=False) and not e.is_symlink() and e.name not in _SKIP:
                walk(e.path, depth + 1)

    for root in roots:
        if os.path.isdir(root) and not os.path.islink(root):
            walk(root, 0)
    return out


def services_on_old_keg(run, cellar: str, services: List[dict]) -> List[str]:
    out = []
    opt_dir = os.path.join(os.path.dirname(cellar.rstrip("/")), "opt")
    for s in services:
        name, pid = s.get("name"), s.get("pid")
        if s.get("status") != "started" or not isinstance(name, str) or not isinstance(pid, int):
            continue
        current = os.path.basename(os.path.realpath(os.path.join(opt_dir, name)))
        prefix = os.path.join(cellar, name) + "/"
        r = run(["/usr/sbin/lsof", "-p", str(pid), "-Fn"], timeout=30)
        for line in (r.stdout or "").splitlines():
            if line.startswith("n") and line[1:].startswith(prefix):
                running = line[1 + len(prefix):].split("/", 1)[0]
                if running and running != current:
                    out.append(t("%s: running from version %s, installed %s",
                                 "%s: in esecuzione dalla versione %s, installata %s") % (name, running, current))
                    break
    return out


def keg_users(run, cellar: str, services: List[dict], target: str) -> List[Tuple[str, str]]:
    """Running brew services that have files of `target`'s kegs open: (service, keg version in use)."""
    out = []
    prefix = os.path.join(cellar, target) + "/"
    for s in services:
        name, pid = s.get("name"), s.get("pid")
        if s.get("status") != "started" or not isinstance(name, str) or not isinstance(pid, int):
            continue
        r = run(["/usr/sbin/lsof", "-p", str(pid), "-Fn"], timeout=30)
        for line in (r.stdout or "").splitlines():
            if line.startswith("n") and line[1:].startswith(prefix):
                version = line[1 + len(prefix):].split("/", 1)[0]
                if version:
                    out.append((name, version))
                    break
    return out


def path_node_version(run, path_node: Optional[str]) -> Optional[str]:
    if not path_node:
        return None
    r = run([path_node, "--version"], timeout=10, env={"PATH": "/usr/bin:/bin"})
    if r.returncode != 0:
        return None
    m = _VERSION_RE.match((r.stdout or "").strip())
    return m.group(1) if m else None
