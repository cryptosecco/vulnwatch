"""Tamper check of the installed copy: ownership, permissions, no symlinks/bytecode, hashes vs manifest."""
import hashlib
import json
import os
import stat as st
from typing import Callable, Dict, List

from .i18n import t

MANIFEST_NAME = "manifest.json"


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _files(root: str) -> Dict[str, str]:
    out = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            if rel == MANIFEST_NAME or os.path.islink(full):
                continue
            out[rel] = full
    return out


def write_manifest(root: str) -> Dict[str, str]:
    manifest = {rel: _sha256(full) for rel, full in sorted(_files(root).items())}
    with open(os.path.join(root, MANIFEST_NAME), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=1, sort_keys=True)
    return manifest


def _owner_mode(path: str, label: str, expect_uid: int, stat: Callable, problems: List[str]) -> None:
    try:
        s = stat(path)
    except OSError:
        problems.append(t("%s missing", "%s mancante") % label)
        return
    if st.S_ISLNK(s.st_mode):
        problems.append(t("symbolic link: %s", "collegamento simbolico: %s") % label)
    if s.st_uid != expect_uid:
        problems.append(t("invalid owner: %s", "proprietario non valido: %s") % label)
    if s.st_mode & 0o022:
        problems.append(t("writable by group or others: %s", "scrivibile da gruppo o altri: %s") % label)


def verify(root: str, plist_path: str, expect_uid: int = 0, stat: Callable = os.lstat) -> List[str]:
    problems: List[str] = []
    _owner_mode(root, t("install folder", "cartella di installazione"), expect_uid, stat, problems)
    _owner_mode(plist_path, "plist", expect_uid, stat, problems)
    manifest_path = os.path.join(root, MANIFEST_NAME)
    _owner_mode(manifest_path, "manifest", expect_uid, stat, problems)
    try:
        with open(manifest_path, encoding="utf-8") as f:
            manifest = json.load(f)
        if not isinstance(manifest, dict):
            raise ValueError
    except (OSError, ValueError):
        problems.append(t("manifest unreadable", "manifest illeggibile"))
        manifest = None

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in dirnames + filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            if name == "__pycache__":
                problems.append(t("unexpected bytecode cache: %s", "cache bytecode inattesa: %s") % rel)
            _owner_mode(full, rel, expect_uid, stat, problems)

    if manifest is not None:
        present = _files(root)
        for rel in sorted(set(manifest) - set(present)):
            problems.append(t("missing file: %s", "file mancante: %s") % rel)
        for rel in sorted(set(present) - set(manifest)):
            problems.append(t("extra file: %s", "file in più: %s") % rel)
        for rel in sorted(set(present) & set(manifest)):
            try:
                if _sha256(present[rel]) != manifest[rel]:
                    problems.append(t("hash mismatch: %s", "hash diverso: %s") % rel)
            except OSError:
                problems.append(t("unreadable file: %s", "file illeggibile: %s") % rel)
    return problems
