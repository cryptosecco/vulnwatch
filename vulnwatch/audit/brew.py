"""Audit of a Homebrew formula or cask upgrade. Fails closed on any missing or unreadable data."""
import re
from datetime import datetime
from typing import Optional, Tuple
from urllib.parse import quote

from ..brew_client import BrewClient
from ..health import keg_users
from ..i18n import t
from ..model import AuditResult, Check, InventoryItem
from ..net import Fetcher, FetchError
from ..sanitize import clean_text
from ..versions import VersionError, compare, major
from . import cooldown_check, parse_time

RUBY_PATH_RE = re.compile(r"^(Formula|Casks)/[0-9a-z_+.@/-]+\.rb$")
_REPOS = {"Homebrew/homebrew-core", "Homebrew/homebrew-cask"}
_INSTALLER_KEYS = {"pkg", "installer", "preflight", "postflight", "script"}


def _last_change_raw(fetcher: Fetcher, repo: str, path: str) -> Optional[str]:
    if repo not in _REPOS:
        raise ValueError(t("repository not allowed", "repository non ammesso"))
    if not isinstance(path, str) or not RUBY_PATH_RE.match(path) or ".." in path:
        raise ValueError(t("invalid formula path", "percorso della formula non valido"))
    url = "https://api.github.com/repos/%s/commits?path=%s&per_page=1" % (repo, quote(path, safe="/"))
    data = fetcher.get_json(url, headers={"Accept": "application/vnd.github+json"})
    if not isinstance(data, list) or not data:
        return None
    try:
        return data[0]["commit"]["committer"]["date"]
    except (KeyError, TypeError):
        return None


def last_change(fetcher: Fetcher, repo: str, path: str) -> Optional[datetime]:
    return parse_time(_last_change_raw(fetcher, repo, path))


def _cooldown(fetcher, repo, info, now, hours, accept_fresh) -> Check:
    try:
        raw = _last_change_raw(fetcher, repo, info.get("ruby_source_path"))
    except (FetchError, ValueError) as e:
        return Check("cooldown", "unknown", t("last change date not available (%s)",
                                              "data dell'ultima modifica non disponibile (%s)")
                     % clean_text(str(e), 120))
    return cooldown_check(raw, now, hours, accept_fresh)


def _candidate(cand: str, installed: str, fixed: str) -> Check:
    try:
        ok = compare(cand, fixed, "generic") >= 0 and compare(cand, installed, "generic") > 0
    except VersionError:
        return Check("candidate", "unknown", t("version unreadable", "versione illeggibile"))
    return Check("candidate", "pass" if ok else "fail", clean_text(cand, 60) if ok else
                 t("the offered version (%s) does not fix (%s)",
                   "la versione offerta (%s) non corregge (%s)") % (clean_text(cand, 60), clean_text(fixed, 60)))


def _dry_run(brew: BrewClient, name: str, cask: bool) -> Check:
    try:
        dr = brew.dry_run(name, cask=cask)
    except ValueError as e:
        return Check("dry_run_only_target", "unknown", clean_text(str(e), 120))
    names = [u[0] for u in dr.upgrades]
    if dr.installs or names != [name]:
        others = sorted(set(names + dr.installs) - {name})
        return Check("dry_run_only_target", "fail",
                     t("also touches: %s", "tocca anche: %s") % ", ".join(clean_text(n, 40) for n in others[:10]))
    return Check("dry_run_only_target", "pass", "")


def _source_check(name: str, defined: bool, src: Optional[str], marker: str) -> Check:
    if not defined:
        return Check(name, "pass", "")
    if src is None:
        return Check(name, "unknown", t("source of the installed version not available",
                                        "sorgente della versione installata non disponibile"))
    return Check(name, "pass" if marker in src else "fail",
                 "" if marker in src else t("new compared to the installed version",
                                            "nuovo rispetto alla versione installata"))


def _error(finding_id: str, what: str, e: Exception) -> AuditResult:
    return AuditResult(finding_id, None, [Check(what, "error", clean_text(str(e), 120))], {})


def audit_formula(item: InventoryItem, fixed_version: str, brew: BrewClient, fetcher: Fetcher, now: datetime,
                  cooldown_hours: int, finding_id: str, accept_fresh: bool = False) -> AuditResult:
    try:
        info = brew.info(item.name)
    except ValueError as e:
        return _error(finding_id, "brew_info", e)
    checks = [Check("tap_core", "pass" if info.get("tap") == "homebrew/core" else "fail", "")]
    stable = (info.get("versions") or {}).get("stable")
    rev = info.get("revision") or 0
    if not isinstance(stable, str):
        return _error(finding_id, "brew_info", ValueError(t("stable version missing", "versione stabile assente")))
    cand = stable + ("_%d" % rev if isinstance(rev, int) and rev > 0 else "")
    checks.append(_candidate(cand, item.version, fixed_version))
    try:
        checks.append(Check("same_major", "pass" if major(cand, "generic") == major(item.version, "generic") else "fail", ""))
    except VersionError:
        checks.append(Check("same_major", "unknown", t("version unreadable", "versione illeggibile")))
    try:
        files = ((info.get("bottle") or {}).get("stable") or {}).get("files") or {}
        tag = brew.bottle_tag()
        ok = tag in files or "all" in files
        checks.append(Check("bottle_available", "pass" if ok else "fail",
                            "" if ok else t("no bottle for %s", "nessun bottle per %s") % clean_text(tag, 40)))
    except ValueError as e:
        checks.append(Check("bottle_available", "unknown", clean_text(str(e), 120)))
    checks.append(_dry_run(brew, item.name, cask=False))
    try:
        src = brew.keg_source(item.name, item.version) if (info.get("post_install_defined") or info.get("caveats")) else None
    except ValueError:
        src = None
    checks.append(_source_check("post_install_unchanged", bool(info.get("post_install_defined")), src, "def post_install"))
    checks.append(_source_check("caveats_unchanged", bool(info.get("caveats")), src, "def caveats"))
    try:
        services = brew.services()
        users = [s.get("name") for s in services if s.get("name") == item.name and s.get("status") == "started"]
        users += [svc for svc, _ in keg_users(brew.run, brew.cellar(), services, item.name) if svc not in users]
        detail = (t("used by active services: %s", "usato da servizi attivi: %s")
                  % ", ".join(clean_text(u, 60) for u in users) if users else "")
        checks.append(Check("not_running_service", "fail" if users else "pass", detail))
    except ValueError as e:
        checks.append(Check("not_running_service", "unknown", clean_text(str(e), 120)))
    dep = bool(info.get("deprecated") or info.get("disabled"))
    checks.append(Check("not_deprecated", "fail" if dep else "pass", ""))
    checks.append(_cooldown(fetcher, "Homebrew/homebrew-core", info, now, cooldown_hours, accept_fresh))
    evidence = {
        "candidate": cand,
        "ruby_source_sha256": str((info.get("ruby_source_checksum") or {}).get("sha256", "")),
        "tap_git_head": str(info.get("tap_git_head", "")),
    }
    return AuditResult(finding_id, cand, checks, evidence)


def audit_cask(item: InventoryItem, fixed_version: str, brew: BrewClient, fetcher: Fetcher, now: datetime,
               cooldown_hours: int, finding_id: str, accept_fresh: bool = False) -> AuditResult:
    try:
        info = brew.info(item.name, cask=True)
    except ValueError as e:
        return _error(finding_id, "brew_info", e)
    cand = info.get("version")
    if not isinstance(cand, str):
        return _error(finding_id, "brew_info", ValueError(t("cask version missing", "versione del cask assente")))
    checks = [Check("tap_cask", "pass" if info.get("tap") == "homebrew/cask" else "fail", "")]
    checks.append(_candidate(cand, item.version, fixed_version))
    checks.append(_dry_run(brew, item.name, cask=True))
    keys = set()
    for a in info.get("artifacts") or []:
        if isinstance(a, dict):
            keys |= set(a)
    bad = sorted(keys & _INSTALLER_KEYS)
    checks.append(Check("no_installer_scripts", "fail" if bad else "pass",
                        t("contains: %s", "contiene: %s") % ", ".join(bad) if bad else ""))
    dep = bool(info.get("deprecated") or info.get("disabled"))
    checks.append(Check("not_deprecated", "fail" if dep else "pass", ""))
    checks.append(_cooldown(fetcher, "Homebrew/homebrew-cask", info, now, cooldown_hours, accept_fresh))
    evidence = {"candidate": cand, "ruby_source_sha256": str((info.get("ruby_source_checksum") or {}).get("sha256", "")),
                "tap_git_head": str(info.get("tap_git_head", "")), "app_path": _app_path(info)}
    return AuditResult(finding_id, cand, checks, evidence)


def _app_path(info: dict) -> str:
    for a in info.get("artifacts") or []:
        if isinstance(a, dict) and isinstance(a.get("app"), list) and a["app"]:
            target = a.get("target")
            if isinstance(target, str) and target.startswith("/Applications/") and target.endswith(".app"):
                return target
            name = a["app"][0]
            if isinstance(name, str) and name.endswith(".app") and "/" not in name:
                return "/Applications/" + name
    return ""
