"""Thin wrapper around the brew CLI. Always argv lists, always BREW_ENV, never cleanup or autoremove."""
import json
import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .i18n import t
from .inventory.brew import BREW_ENV

_UP_RE = re.compile(r"^(\S+)\s+(\S+)\s+->\s+(\S+)")
_IN_RE = re.compile(r"^(\S+)\s+(\S+)$")
_SAFE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+_.@-]*$")
_PATH = "/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"


@dataclass
class DryRun:
    installs: List[str] = field(default_factory=list)
    upgrades: List[Tuple[str, str, str]] = field(default_factory=list)


def parse_dry_run(text: str) -> DryRun:
    dr = DryRun()
    section = None
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("==> "):
            head = s[4:]
            if head.startswith("Would upgrade"):
                section = "up"
            elif head.startswith("Would install"):
                section = "in"
            elif head.startswith("Would "):
                raise ValueError(t("unknown dry-run section", "sezione del dry-run sconosciuta"))
            else:
                section = None
            continue
        if not s or section is None:
            continue
        up, plain = _UP_RE.match(s), _IN_RE.match(s)
        if section == "up" and up:
            dr.upgrades.append((up.group(1), up.group(2), up.group(3)))
        elif section == "up" and plain:
            dr.upgrades.append((plain.group(1), "", plain.group(2)))
        elif section == "in" and plain:
            dr.installs.append(plain.group(1))
        else:
            raise ValueError(t("unrecognized dry-run line", "riga del dry-run non riconosciuta"))
    return dr


def brew_env(auto_update: bool = False) -> Dict[str, str]:
    env = {"PATH": _PATH, "HOME": os.path.expanduser("~")}
    env.update(BREW_ENV)
    if auto_update:
        env.pop("HOMEBREW_NO_AUTO_UPDATE", None)
    return env


class BrewClient:
    def __init__(self, run, brew: str = "/opt/homebrew/bin/brew"):
        self.run = run
        self.brew = brew
        self._cellar: Optional[str] = None

    def _call(self, args: List[str], timeout: float = 120, auto_update: bool = False):
        if not self.brew:
            # Every caller handles ValueError; brew=null in the config means "no Homebrew on this Mac".
            raise ValueError(t("Homebrew is not configured", "Homebrew non è configurato"))
        return self.run([self.brew] + args, timeout=timeout, env=brew_env(auto_update))

    def info(self, name: str, cask: bool = False) -> dict:
        r = self._call(["info", "--json=v2", "--cask" if cask else "--formula", name])
        if r.returncode != 0:
            raise ValueError(t("brew info failed", "brew info non riuscito"))
        try:
            doc = json.loads(r.stdout)
            return doc["casks" if cask else "formulae"][0]
        except (ValueError, KeyError, IndexError, TypeError) as e:
            raise ValueError(t("brew info unreadable", "brew info illeggibile")) from e

    def dry_run(self, name: str, cask: bool = False) -> DryRun:
        r = self._call(["upgrade", "--dry-run", "--cask" if cask else "--formula", name], timeout=300)
        if r.returncode != 0:
            raise ValueError(t("brew dry-run failed", "dry-run di brew non riuscito"))
        return parse_dry_run((r.stdout or "") + "\n" + (r.stderr or ""))

    def services(self) -> List[dict]:
        r = self._call(["services", "info", "--all", "--json"])
        if r.returncode != 0:
            raise ValueError(t("brew services failed", "brew services non riuscito"))
        try:
            data = json.loads(r.stdout or "[]")
        except ValueError as e:
            raise ValueError(t("brew services unreadable", "brew services illeggibile")) from e
        if not isinstance(data, list):
            raise ValueError(t("brew services unreadable", "brew services illeggibile"))
        return [s for s in data if isinstance(s, dict)]

    def bottle_tag(self) -> str:
        r = self._call(["ruby", "-e", "puts Utils::Bottles.tag.to_s"])
        lines = (r.stdout or "").strip().splitlines()
        if r.returncode != 0 or not lines:
            raise ValueError(t("bottle tag not available", "bottle tag non disponibile"))
        return lines[-1].strip()

    def cellar(self) -> str:
        if self._cellar is None:
            r = self._call(["--cellar"])
            path = (r.stdout or "").strip()
            if r.returncode != 0 or not path.startswith("/"):
                raise ValueError(t("cellar not available", "cellar non disponibile"))
            self._cellar = path
        return self._cellar

    def keg_source(self, name: str, version: str) -> Optional[str]:
        if not _SAFE_RE.match(name) or not _SAFE_RE.match(version):
            return None
        path = os.path.join(self.cellar(), name, version, ".brew", name + ".rb")
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                return f.read()
        except OSError:
            return None

    def update(self) -> None:
        r = self._call(["update"], timeout=600, auto_update=True)
        if r.returncode != 0:
            raise ValueError(t("brew update failed", "brew update non riuscito"))
