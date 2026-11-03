"""Audit of a global npm package update, against the official registry metadata."""
import re
from datetime import datetime
from typing import Callable, Dict, Optional

from ..i18n import t
from ..model import AuditResult, Check, InventoryItem
from ..net import Fetcher, FetchError
from ..sanitize import clean_text
from ..versions import VersionError, compare, major, npm_satisfies
from . import cooldown_check, parse_time

REGISTRY = "https://registry.npmjs.org"
NPM_NAME_RE = re.compile(r"^(@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$")
_STABLE_RE = re.compile(r"^\d+\.\d+\.\d+(\+[0-9A-Za-z.-]+)?$")
_SCRIPTS = ("preinstall", "install", "postinstall")
_MAX_BYTES = 60_000_000


def packument_url(name: str) -> str:
    if not isinstance(name, str) or not NPM_NAME_RE.match(name) or ".." in name:
        raise ValueError(t("invalid npm name: %r", "nome npm non valido: %r") % (name,))
    return REGISTRY + "/" + name.replace("/", "%2f")


def _eligible(pk, v, installed, fixed, now, hours, accept_fresh) -> bool:
    meta = (pk.get("versions") or {}).get(v)
    if not isinstance(meta, dict) or meta.get("deprecated") or not _STABLE_RE.match(v):
        return False
    try:
        if major(v, "semver") != major(installed, "semver"):
            return False
        if compare(v, fixed, "semver") < 0 or compare(v, installed, "semver") <= 0:
            return False
    except VersionError:
        return False
    if accept_fresh:
        return True
    dt = parse_time((pk.get("time") or {}).get(v))
    return dt is not None and (now - dt).total_seconds() >= hours * 3600


def select_candidate(packument: dict, installed: str, fixed: str, now: datetime, cooldown_hours: int,
                     accept_fresh: bool) -> Optional[str]:
    best = None
    for v in (packument.get("versions") or {}):
        if _eligible(packument, v, installed, fixed, now, cooldown_hours, accept_fresh):
            if best is None or compare(v, best, "semver") > 0:
                best = v
    return best


def _names(meta: dict) -> set:
    return {m.get("name") for m in (meta.get("maintainers") or []) if isinstance(m, dict) and m.get("name")}


def _deps(meta: dict) -> set:
    out = set()
    for k in ("dependencies", "optionalDependencies"):
        d = meta.get(k)
        if isinstance(d, dict):
            out |= set(d)
    return out


def _trusted_publisher(meta: dict) -> Optional[tuple]:
    """(provider, oidcConfigId) of an npm trusted-publishing release, or None if absent or malformed."""
    user = meta.get("_npmUser")
    tp = user.get("trustedPublisher") if isinstance(user, dict) else None
    if not isinstance(tp, dict):
        return None
    pid, cfg = tp.get("id"), tp.get("oidcConfigId")
    if not isinstance(pid, str) or not isinstance(cfg, str) or not pid or not cfg:
        return None
    return (pid, cfg)


def _same_trusted_publisher(old: dict, new: dict) -> bool:
    """True only if both versions come from the same trusted-publishing config and the new one has provenance."""
    a, b = _trusted_publisher(old), _trusted_publisher(new)
    dist = new.get("dist")
    has_provenance = isinstance(dist, dict) and isinstance(dist.get("attestations"), dict)
    return a is not None and a == b and has_provenance


def _list(names) -> str:
    return ", ".join(clean_text(n, 60) for n in sorted(names)[:10])


def audit_npm_global(item: InventoryItem, fixed_version: str, fetcher: Fetcher, now: datetime, cooldown_hours: int,
                     owner_node_version: Optional[str], is_malicious: Callable[[str, str], bool], finding_id: str,
                     accept_fresh: bool = False) -> AuditResult:
    try:
        pk = fetcher.get_json(packument_url(item.name), max_bytes=_MAX_BYTES, headers={"Accept": "application/json"})
        if not isinstance(pk, dict) or not isinstance(pk.get("versions"), dict):
            raise ValueError(t("malformed packument", "packument malformato"))
    except (FetchError, ValueError) as e:
        return AuditResult(finding_id, None, [Check("packument", "error", clean_text(str(e), 200))], {})

    cand = select_candidate(pk, item.version, fixed_version, now, cooldown_hours, accept_fresh)
    if cand is None:
        cand = select_candidate(pk, item.version, fixed_version, now, cooldown_hours, True)
    if cand is None:
        return AuditResult(finding_id, None, [Check(
            "candidate", "fail", t("no fixed version (>= %s) with the same major version",
                                   "nessuna versione corretta (>= %s) con la stessa versione maggiore")
            % clean_text(fixed_version, 40))], {})

    new: Dict = pk["versions"][cand]
    old = pk["versions"].get(item.version)
    checks = [Check("candidate", "pass", cand)]
    try:
        same = major(cand, "semver") == major(item.version, "semver")
        checks.append(Check("same_major", "pass" if same else "fail", ""))
    except VersionError:
        checks.append(Check("same_major", "unknown", t("version unreadable", "versione illeggibile")))
    checks.append(cooldown_check((pk.get("time") or {}).get(cand), now, cooldown_hours, accept_fresh))

    if not isinstance(old, dict):
        for name in ("maintainers", "publisher", "install_scripts", "new_dependencies", "provenance"):
            checks.append(Check(name, "unknown", t("the installed version is not in the registry",
                                                   "la versione installata non è nel registro")))
    else:
        on, nn = _names(old), _names(new)
        if on == nn and nn:
            checks.append(Check("maintainers", "pass", ""))
        else:
            checks.append(Check("maintainers", "fail", t("added: %s; removed: %s", "aggiunti: %s; rimossi: %s")
                                % (_list(nn - on), _list(on - nn))))
        user = new.get("_npmUser")
        uname = user.get("name") if isinstance(user, dict) else None
        if not uname:
            checks.append(Check("publisher", "unknown", t("publisher missing", "pubblicatore assente")))
        elif uname in on:
            checks.append(Check("publisher", "pass", ""))
        elif _same_trusted_publisher(old, new):
            checks.append(Check("publisher", "pass", t("same trusted publisher as the installed version, with provenance",
                                                       "stesso trusted publisher della versione installata, con provenance")))
        else:
            checks.append(Check("publisher", "fail", t("published by %s", "pubblicato da %s") % clean_text(uname, 60)))
        os_, ns = old.get("scripts") or {}, new.get("scripts") or {}
        changed = [k for k in _SCRIPTS if (os_.get(k) if isinstance(os_, dict) else None) != (ns.get(k) if isinstance(ns, dict) else None)]
        checks.append(Check("install_scripts", "fail" if changed else "pass",
                            t("changed: %s", "cambiati: %s") % ", ".join(changed) if changed else ""))
        added = _deps(new) - _deps(old)
        checks.append(Check("new_dependencies", "fail" if added else "pass",
                            t("new: %s", "nuove: %s") % _list(added) if added else ""))
        had = isinstance(old.get("dist"), dict) and "attestations" in old["dist"]
        has = isinstance(new.get("dist"), dict) and "attestations" in new["dist"]
        checks.append(Check("provenance", "fail" if had and not has else "pass",
                            t("provenance dropped", "provenance sparita") if had and not has else ""))

    engines = new.get("engines")
    expr = engines.get("node") if isinstance(engines, dict) else None
    if engines is not None and not isinstance(engines, dict):
        checks.append(Check("engines", "unknown", t("engines field unreadable", "campo engines illeggibile")))
    elif not expr:
        checks.append(Check("engines", "pass", ""))
    elif not owner_node_version:
        checks.append(Check("engines", "unknown", t("owner Node version not readable",
                                                    "versione del Node proprietario non leggibile")))
    else:
        try:
            ok = npm_satisfies(owner_node_version, str(expr))
            checks.append(Check("engines", "pass" if ok else "fail",
                                "" if ok else t("requires node %s", "richiede node %s") % clean_text(expr, 60)))
        except VersionError:
            checks.append(Check("engines", "unknown", t("engines requirement not parseable",
                                                    "requisito engines non interpretabile")))

    checks.append(Check("not_malicious", "fail" if is_malicious(item.name, cand) else "pass", ""))
    checks.append(Check("not_deprecated", "fail" if new.get("deprecated") else "pass", ""))
    dist = new.get("dist") if isinstance(new.get("dist"), dict) else {}
    evidence = {
        "integrity": str(dist.get("integrity", "")),
        "tarball": str(dist.get("tarball", "")),
        "published": str((pk.get("time") or {}).get(cand, "")),
    }
    return AuditResult(finding_id, cand, checks, evidence)
