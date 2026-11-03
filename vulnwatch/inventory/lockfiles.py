"""Project lockfiles (report only). Never follows symlinks, never enters protected folders."""
import json
import os
import re
from typing import Callable, Dict, List, Sequence, Tuple

from ..model import InventoryItem

SKIP_DIRS = {"node_modules", ".git", ".claude", ".venv", "venv", "__pycache__", "dist", "build", ".next"}
MAX_FILE_BYTES = 20_000_000
_PNPM_RE = re.compile(r"^\s{2}'?/?(@?[^@\s'/]+(?:/[^@\s']+)?)@([^:(\s']+)")
_YARN_VERSION_RE = re.compile(r'^\s+version:?\s+"?([^"\s]+)"?\s*$')
_BUN_RE = re.compile(r'"(@?[^"@/]+(?:/[^"@]+)?)@([^"@]+)"')
_REQ_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;#]+)")
_VERSION_OK = re.compile(r"^\d")

Pairs = List[Tuple[str, str]]


def _dedup(pairs: Pairs) -> Pairs:
    seen, out = set(), []
    for p in pairs:
        if p not in seen and p[0] and _VERSION_OK.match(p[1]):
            seen.add(p)
            out.append(p)
    return out


def parse_package_lock(text: str) -> Pairs:
    try:
        d = json.loads(text)
    except ValueError:
        return []
    if not isinstance(d, dict):
        return []
    out: Pairs = []
    pk = d.get("packages")
    if isinstance(pk, dict):
        for key, v in pk.items():
            if not key or not isinstance(v, dict) or v.get("link"):
                continue
            idx = key.rfind("node_modules/")
            if idx < 0:
                continue
            ver = v.get("version")
            if isinstance(ver, str):
                out.append((key[idx + len("node_modules/"):], ver))
    elif isinstance(d.get("dependencies"), dict):
        stack = [d["dependencies"]]
        while stack:
            deps = stack.pop(0)
            for name, v in deps.items():
                if isinstance(v, dict):
                    if isinstance(v.get("version"), str):
                        out.append((name, v["version"]))
                    if isinstance(v.get("dependencies"), dict):
                        stack.append(v["dependencies"])
    return _dedup(out)


def parse_pnpm_lock(text: str) -> Pairs:
    out: Pairs = []
    section = None
    for line in text.splitlines():
        if line and not line[0].isspace():
            section = line.split(":", 1)[0].strip()
            continue
        if section in ("packages", "snapshots"):
            m = _PNPM_RE.match(line)
            if m:
                out.append((m.group(1), m.group(2)))
    return _dedup(out)


def _descriptor_name(desc: str):
    idx = desc.find("@", 1) if desc.startswith("@") else desc.find("@")
    if idx <= 0:
        return None
    rest = desc[idx + 1:]
    if rest.startswith(("workspace:", "link:", "file:", "portal:")):
        return None
    return desc[:idx]


def parse_yarn_lock(text: str) -> Pairs:
    out: Pairs = []
    current = None
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace():
            header = line.rstrip().rstrip(":").strip()
            current = None
            if header == "__metadata":
                continue
            for desc in header.split(","):
                name = _descriptor_name(desc.strip().strip('"'))
                if name:
                    current = name
                    break
            continue
        if current:
            m = _YARN_VERSION_RE.match(line)
            if m:
                out.append((current, m.group(1)))
                current = None
    return _dedup(out)


def parse_bun_lock(text: str) -> Pairs:
    idx = text.find('"packages"')
    if idx < 0:
        return []
    return _dedup([(m.group(1), m.group(2)) for m in _BUN_RE.finditer(text[idx:])])


def parse_requirements(text: str) -> Pairs:
    out: Pairs = []
    for line in text.splitlines():
        m = _REQ_RE.match(line.strip())
        if m:
            out.append((re.sub(r"[-_.]+", "-", m.group(1)).lower(), m.group(2)))
    return _dedup(out)


_PARSERS: Dict[str, Tuple[str, Callable[[str], Pairs]]] = {
    "package-lock.json": ("npm", parse_package_lock),
    "npm-shrinkwrap.json": ("npm", parse_package_lock),
    "pnpm-lock.yaml": ("npm", parse_pnpm_lock),
    "yarn.lock": ("npm", parse_yarn_lock),
    "bun.lock": ("npm", parse_bun_lock),
    "requirements.txt": ("PyPI", parse_requirements),
}


def _is_protected(path: str, protected: Sequence[str]) -> bool:
    real = os.path.realpath(path)
    for p in protected:
        rp = os.path.realpath(p)
        if real == rp or real.startswith(rp.rstrip("/") + "/"):
            return True
    return False


def _walk(d: str, depth: int, max_depth: int, protected: Sequence[str], out: List[InventoryItem]) -> None:
    if _is_protected(d, protected):
        return
    try:
        entries = sorted(os.scandir(d), key=lambda e: e.name)
    except OSError:
        return
    for e in entries:
        if e.is_symlink():
            continue
        if e.is_dir(follow_symlinks=False):
            if e.name in SKIP_DIRS or e.name.startswith(".") or depth + 1 > max_depth:
                continue
            _walk(e.path, depth + 1, max_depth, protected, out)
        elif e.is_file(follow_symlinks=False) and e.name in _PARSERS:
            try:
                if e.stat(follow_symlinks=False).st_size > MAX_FILE_BYTES:
                    continue
                with open(e.path, encoding="utf-8", errors="replace") as f:
                    text = f.read()
            except OSError:
                continue
            eco, parser = _PARSERS[e.name]
            for name, version in parser(text):
                out.append(InventoryItem("lockfile_pkg", name, version, eco, None, e.path))


def scan(roots: Sequence[str], max_depth: int, protected: Sequence[str]) -> List[InventoryItem]:
    out: List[InventoryItem] = []
    for root in roots:
        if os.path.isdir(root) and not os.path.islink(root):
            _walk(root, 0, max_depth, protected, out)
    return out
