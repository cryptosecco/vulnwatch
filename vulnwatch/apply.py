"""Playbook: the ONLY commands vulnwatch ever runs to change the system. Fixed templates, validated values."""
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, List, Optional, Tuple

from .audit.npm import NPM_NAME_RE
from .brew_client import brew_env
from .config import Config
from .health import broken_venvs, keg_users, path_node_version, services_on_old_keg
from .i18n import t
from .model import AuditResult, Finding, InventoryItem, to_dict
from .sanitize import clean_text
from .versions import VersionError, compare

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9+_.@-]*$")
VERSION_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+_,-]*$")
CHROME_ID = "com.google.Chrome"
NPM_REGISTRY = "https://registry.npmjs.org/"


class ApplyError(Exception):
    pass


def can_apply(f: Finding) -> bool:
    k = f.item.kind
    return k in ("brew_formula", "brew_cask", "npm_global") or (k == "app" and f.item.name == CHROME_ID)


def argv_for(f: Finding, audit: AuditResult, cfg: Config, now: datetime,
             accept_fresh: bool = False) -> Tuple[List[str], Dict[str, str]]:
    it = f.item
    home = os.path.expanduser("~")
    if not can_apply(f):
        raise ApplyError(t("this item has instructions only", "per questo elemento ci sono solo istruzioni"))
    if it.kind in ("brew_formula", "brew_cask"):
        if cfg.brew is None:
            raise ApplyError(t("Homebrew is not configured", "Homebrew non è configurato"))
        if not NAME_RE.match(it.name) or ".." in it.name:
            raise ApplyError(t("invalid brew name", "nome brew non valido"))
        return [cfg.brew, "upgrade", "--formula" if it.kind == "brew_formula" else "--cask", it.name], brew_env()
    if it.kind == "npm_global":
        ver = audit.candidate_version
        if cfg.npm_global is None:
            raise ApplyError(t("npm is not configured", "npm non è configurato"))
        if not NPM_NAME_RE.match(it.name) or ".." in it.name:
            raise ApplyError(t("invalid npm name", "nome npm non valido"))
        if not isinstance(ver, str) or not VERSION_RE.match(ver):
            raise ApplyError(t("invalid version", "versione non valida"))
        npm = cfg.npm_global.npm
        # The audited registry only, and the cooldown for the whole dependency tree, not just the top package.
        argv = [npm, "--prefix", cfg.npm_global.prefix, "--registry=" + NPM_REGISTRY]
        if not accept_fresh:
            before = now.astimezone(timezone.utc) - timedelta(hours=cfg.cooldown_hours)
            argv.append("--before=" + before.strftime("%Y-%m-%dT%H:%M:%SZ"))
        argv += ["--no-audit", "--no-fund", "install", "-g", "%s@%s" % (it.name, ver)]
        return argv, {"PATH": os.path.dirname(npm) + ":/usr/bin:/bin", "HOME": home}
    return [cfg.google_updater, "--wake"], {"PATH": "/usr/bin:/bin", "HOME": home}


def instructions(f: Finding) -> str:
    it = f.item
    loc = clean_text(it.location, 200)
    name = clean_text(it.name, 100)
    fixed = clean_text(f.fixed_version or t("the fixed version", "la versione corretta"), 60)
    if it.kind == "runtime" and it.name == "node":
        return t("Update the Node copy in %s by hand. Standalone copy: download the official tarball from nodejs.org "
                 "and replace the folder, keeping the old one as a backup. /usr/local/bin/node: install the official "
                 ".pkg with your password, from a folder outside ~/Downloads. Copy bundled inside an app: "
                 "update the app that contains it.",
                 "Aggiorna a mano la copia di Node in %s. Copia autonoma: scarica il tarball ufficiale da nodejs.org "
                 "e sostituisci la cartella tenendo la vecchia come backup. /usr/local/bin/node: installa il .pkg "
                 "ufficiale con la password, da una cartella fuori da ~/Downloads. Copia inclusa in un'app: "
                 "aggiorna l'app che la contiene.") % loc
    if it.kind == "runtime":
        return t("Update the copy of %s in %s, or the app that contains it.",
                 "Aggiorna la copia di %s in %s, oppure l'app che la contiene.") % (name, loc)
    if it.kind == "macos":
        return t("Update macOS from System Settings > General > Software Update.",
                 "Aggiorna macOS da Impostazioni di Sistema > Generali > Aggiornamento Software.")
    if it.kind == "app":
        return t("Update %s from its updater or the Mac App Store.",
                 "Aggiorna %s dal suo updater o dal Mac App Store.") % clean_text(it.display_name or it.name, 100)
    if it.kind == "lockfile_pkg":
        return t("Update %s to %s in project %s, on a branch, with your package manager.",
                 "Aggiorna %s a %s nel progetto %s, in un branch, con il tuo package manager.") % (
            name, fixed, clean_text(os.path.dirname(it.location), 200))
    if it.kind == "brew_formula":
        return t("Formula from an external tap (%s): audit it by hand, then brew upgrade %s.",
                 "Formula di un tap esterno (%s): fai un audit manuale, poi brew upgrade %s.") % (
            clean_text(it.channel or "?", 80), name)
    return t("No automatic action available.", "Nessuna azione automatica disponibile.")


@dataclass
class ApplyContext:
    cfg: Config
    run: Callable
    now: datetime
    actions_log: str
    reinventory: Callable[[InventoryItem], Optional[InventoryItem]]
    team_id: Callable[[str], Optional[str]]
    expected_candidate: Optional[str] = None
    cellar: str = "/opt/homebrew/Cellar"
    services: Callable[[], List[dict]] = field(default=lambda: [])
    accept_fresh: bool = False


@dataclass
class ApplyOutcome:
    status: str
    problems: List[str]
    record: dict


def _app_path(f: Finding, audit: AuditResult) -> Optional[str]:
    if f.item.kind == "app":
        return f.item.location
    if f.item.kind == "brew_cask":
        return audit.evidence.get("app_path") or None
    return None


def _rollback(f: Finding, keg: Optional[str]) -> str:
    it = f.item
    if it.kind == "npm_global":
        return "npm install -g %s@%s" % (it.name, it.version)
    if it.kind == "brew_formula":
        return t("old version kept in %s (no cleanup)", "vecchia versione conservata in %s (nessun cleanup)") % keg
    return t("no automatic rollback", "nessun rollback automatico")


def _log(path: str, record: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def apply_finding(f: Finding, audit_fn: Callable[[], AuditResult], ctx: ApplyContext) -> ApplyOutcome:
    it = f.item
    record = {"time": ctx.now.isoformat(), "finding_id": f.id, "canonical_id": f.canonical_id, "item": to_dict(it)}

    def finish(status: str, problems: List[str]) -> ApplyOutcome:
        record["status"] = status
        record["problems"] = problems
        _log(ctx.actions_log, record)
        return ApplyOutcome(status, problems, record)

    fresh = audit_fn()
    record["checks"] = [to_dict(c) for c in fresh.checks]
    record["candidate"] = fresh.candidate_version
    if not fresh.green:
        return finish("red", [t("audit not green", "audit non verde")])
    if ctx.expected_candidate and fresh.candidate_version != ctx.expected_candidate:
        return finish("aborted", [t("the offered version changed after the audit", "la versione offerta è cambiata dopo l'audit")])
    try:
        argv, env = argv_for(f, fresh, ctx.cfg, ctx.now, ctx.accept_fresh)
    except ApplyError as e:
        return finish("aborted", [str(e)])
    record["argv"] = argv
    keg = os.path.join(ctx.cellar, it.name, it.version) if it.kind == "brew_formula" else None
    record["rollback"] = _rollback(f, keg)
    app = _app_path(f, fresh)
    team_before = ctx.team_id(app) if app else None
    venvs_before = set(broken_venvs(ctx.cfg.venv_roots))
    touches_node = it.kind == "brew_formula" and it.name == "node"
    node_before = None if touches_node else path_node_version(ctx.run, ctx.cfg.path_node)
    record["before"] = {"version": it.version, "team_id": team_before, "keg": keg}

    r = ctx.run(argv, timeout=1800, env=env)
    if r.returncode != 0:
        return finish("failed", [t("the command exited with code %d", "il comando è terminato con codice %d") % r.returncode])

    problems: List[str] = []
    after = ctx.reinventory(it)
    record["after"] = {"version": after.version if after else None}
    if after is None:
        problems.append(t("item no longer found after the update", "elemento non più trovato dopo l'aggiornamento"))
    elif it.kind in ("npm_global", "brew_formula"):
        if after.version != fresh.candidate_version:
            problems.append(t("version after the update: %s, expected %s",
                              "versione dopo l'aggiornamento: %s, attesa %s") % (after.version, fresh.candidate_version))
    else:
        target = f.fixed_version or fresh.candidate_version or it.version
        try:
            if compare(after.version, target, "generic") < 0:
                problems.append(t("version after the update still below %s",
                                  "versione dopo l'aggiornamento ancora inferiore a %s") % target)
        except VersionError:
            problems.append(t("version after the update unreadable", "versione dopo l'aggiornamento illeggibile"))
    if app:
        team_after = ctx.team_id(app)
        record["after"]["team_id"] = team_after
        if not team_before or team_after != team_before:
            problems.append(t("Team ID changed or missing (%s -> %s)",
                              "Team ID cambiato o assente (%s -> %s)") % (team_before, team_after))
    for v in sorted(set(broken_venvs(ctx.cfg.venv_roots)) - venvs_before):
        problems.append(t("broken venv: %s", "venv rotto: %s") % v)
    if it.kind == "brew_formula":
        try:
            services = ctx.services()
            problems += services_on_old_keg(ctx.run, ctx.cellar, services)
            for svc, used in keg_users(ctx.run, ctx.cellar, services, it.name):
                if used != fresh.candidate_version:
                    problems.append(t("%s is still using %s %s: it needs a restart",
                                  "%s usa ancora %s %s: va riavviato") % (svc, it.name, used))
        except ValueError as e:
            problems.append(t("service check failed: %s", "controllo dei servizi non riuscito: %s") % e)
    if not touches_node:
        node_after = path_node_version(ctx.run, ctx.cfg.path_node)
        if node_after != node_before:
            problems.append(t("the Node on PATH changed (%s -> %s)",
                              "il Node nel PATH è cambiato (%s -> %s)") % (node_before, node_after))
    return finish("applied_with_problems" if problems else "applied", problems)
