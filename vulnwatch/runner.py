"""Daily orchestration. Order matters: self-check, then ALL source syncs, only then the inventory (I1)."""
import dataclasses
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, List, Optional, Set, Tuple

from .apply import ApplyContext, apply_finding
from .audit.brew import audit_cask, audit_formula
from .audit.npm import audit_npm_global
from .brew_client import BrewClient
from .config import Config
from .grouping import group_by_item, item_key, representative
from .health import path_node_version
from .i18n import t
from .inventory.brew import brew_items
from .inventory.npm import npm_globals
from .inventory.system import CHROME_ID, apps, team_id
from .lanes import classify
from .match import build_findings, load_aliases
from .model import AuditResult, Check, Finding, InventoryItem
from .net import Fetcher
from .report import RunSummary, notification_text, write_report
from .sanitize import clean_text
from .sources import cverecord, cvenow, iso, kev, osv
from .store import Store

_BREW_CHANNELS = {("brew_formula", "homebrew/core"), ("brew_cask", "homebrew/cask")}


@dataclass
class RunContext:
    cfg: Config
    fetcher: Fetcher
    store: Store
    run: Callable
    brew: BrewClient
    now: datetime
    tmp_dir: str
    dev: bool
    selfcheck: Callable[[], List[str]]
    inventory: Callable[[], List[InventoryItem]]
    notify: Callable[[str], None]
    report_dir: str
    actions_log: str


def malicious_index(store: Store) -> Set[Tuple[str, str]]:
    out = set()
    for adv in store.advisories("osv", id_prefix="MAL-"):
        for a in adv.affected:
            if (a.ecosystem or "").lower() == "npm" and a.package:
                out.update((a.package, v) for v in a.versions)
    return out


def _with_note(result: AuditResult, note: Optional[str]) -> AuditResult:
    if note:
        result.checks.insert(0, Check("brew_update", "error", note))
    return result


def make_audit(ctx: RunContext, f: Finding, brew_note: Optional[str], mal: Set[Tuple[str, str]],
               accept_fresh: bool = False, interactive: bool = False) -> Optional[Callable[[], AuditResult]]:
    it, cfg = f.item, ctx.cfg
    if it.kind == "npm_global" and it.channel == "npm_global":
        if cfg.npm_global is None:
            return None
        owner = path_node_version(ctx.run, cfg.npm_global.node)
        return lambda: audit_npm_global(it, f.fixed_version, ctx.fetcher, ctx.now, cfg.cooldown_hours, owner,
                                        lambda n, v: (n, v) in mal, f.id, accept_fresh)
    if (it.kind, it.channel) == ("brew_formula", "homebrew/core"):
        return lambda: _with_note(audit_formula(it, f.fixed_version, ctx.brew, ctx.fetcher, ctx.now, cfg.cooldown_hours,
                                                f.id, accept_fresh), brew_note)
    if (it.kind, it.channel) == ("brew_cask", "homebrew/cask"):
        return lambda: _with_note(audit_cask(it, f.fixed_version, ctx.brew, ctx.fetcher, ctx.now, cfg.cooldown_hours,
                                             f.id, accept_fresh), brew_note)
    if interactive and it.kind == "app" and it.name == CHROME_ID:
        return lambda: AuditResult(f.id, None, [Check(
            "manual_approval", "pass",
            t("Google's updater cannot be verified beforehand: approved by hand, signature and Team ID checked after",
              "l'updater di Google non si può verificare prima: approvato a mano, verifica di firma e Team ID dopo"))], {})
    return None


def reinventory(ctx: RunContext, item: InventoryItem) -> Optional[InventoryItem]:
    if item.kind == "npm_global":
        if ctx.cfg.npm_global is None:
            return None
        return next((x for x in npm_globals(ctx.cfg.npm_global.prefix) if x.name == item.name), None)
    if item.kind in ("brew_formula", "brew_cask"):
        cask = item.kind == "brew_cask"
        try:
            info = ctx.brew.info(item.name, cask=cask)
        except ValueError:
            return None
        found = brew_items({"casks": [info]} if cask else {"formulae": [info]})
        return found[0] if found else None
    if item.kind == "app":
        import os
        return next((x for x in apps([os.path.dirname(item.location)], ctx.run) if x.name == item.name), None)
    return None


def apply_context(ctx: RunContext, expected: Optional[str], accept_fresh: bool = False) -> ApplyContext:
    try:
        cellar = ctx.brew.cellar()
    except ValueError:
        cellar = "/opt/homebrew/Cellar"
    return ApplyContext(ctx.cfg, ctx.run, ctx.now, ctx.actions_log, lambda item: reinventory(ctx, item),
                        lambda path: team_id(path, ctx.run), expected, cellar=cellar, services=ctx.brew.services,
                        accept_fresh=accept_fresh)


def _sync_all(ctx: RunContext, errors: List[str]) -> dict:
    cfg, fx, st, now = ctx.cfg, ctx.fetcher, ctx.store, ctx.now
    steps = [
        ("kev", lambda: kev.sync(fx, st, now)),
        ("cvenow", lambda: cvenow.sync(fx, st, now, cfg.backfill_days, cfg.max_records_per_run)),
        ("cverecord", lambda: cverecord.sync(fx, st, now, cfg.max_records_per_run)),
        ("osv", lambda: osv.sync(fx, st, now, cfg.osv_ecosystems, ctx.tmp_dir, cfg.max_records_per_run, cfg.osv_zip_max_bytes)),
    ]
    ok = {}
    for name, fn in steps:
        try:
            stats = fn()
            ok[name] = not ((stats.failed and stats.fetched == 0) or stats.incomplete)
            if stats.errors:
                errors.append(t("%s: %d entries with errors", "%s: %d voci con errori") % (name, len(stats.errors)))
                errors.extend("%s: %s" % (name, clean_text(e, 200)) for e in stats.errors[:5])
        except Exception as e:  # noqa: BLE001 - one broken source must not stop the others
            ok[name] = False
            errors.append("%s: %s" % (name, clean_text(str(e), 200)))
    return ok


def _stop(ctx: RunContext, date: str, errors: List[str], sources_ok: dict, note: str, code: int) -> Tuple[int, RunSummary]:
    s = RunSummary(date, [], {}, [], [], errors, sources_ok, False)
    write_report(s, ctx.report_dir, ctx.now)
    ctx.notify(note if note else notification_text(s))
    return code, s


def run_daily(ctx: RunContext) -> Tuple[int, RunSummary]:
    cfg, now = ctx.cfg, ctx.now
    date = now.strftime("%Y-%m-%d")
    problems = ctx.selfcheck()
    if problems:
        return _stop(ctx, date, [t("suspected tampering: ", "manomissione sospetta: ") + clean_text(p, 200) for p in problems], {},
                     t("vulnwatch: suspected tampering, job stopped", "vulnwatch: manomissione sospetta, job fermato"), 2)

    run_id = ctx.store.start_run(iso(now))
    errors: List[str] = []
    sources_ok = _sync_all(ctx, errors)
    if not any(sources_ok.values()) and next(ctx.store.advisories(), None) is None:
        ctx.store.finish_run(run_id, "nodata", {})
        return _stop(ctx, date, errors, sources_ok, "", 3)

    try:
        items = ctx.inventory()
    except Exception as e:  # noqa: BLE001 - fail loud, never silently report "nothing found"
        ctx.store.finish_run(run_id, "failed", {})
        return _stop(ctx, date, errors + [t("inventory failed: %s", "inventario non riuscito: %s") % clean_text(str(e), 200)], sources_ok,
                     t("vulnwatch: inventory failed", "vulnwatch: inventario non riuscito"), 3)

    ignores = ctx.store.ignores()
    findings = [classify(f, cfg.hold, ignores)
                for f in build_findings(ctx.store.advisories(), items, load_aliases(cfg.aliases_file), now)]
    mal = malicious_index(ctx.store) if any(f.item.kind == "npm_global" for f in findings) else set()

    # One audit per inventory item, against the highest fixed version among its findings.
    pos = {f.id: i for i, f in enumerate(findings)}
    audits, reps, brew_note, brew_updated = {}, {}, None, False
    for group in group_by_item(findings):
        cands = [f for f in group if f.lane in ("auto", "manual") and f.fixed_version and f.match == "exact"]
        if not cands:
            continue
        rep = representative(cands)
        if (rep.item.kind, rep.item.channel) in _BREW_CHANNELS and not brew_updated:
            brew_updated = True
            try:
                ctx.brew.update()
            except Exception as e:  # noqa: BLE001
                brew_note = t("brew update failed: %s", "brew update non riuscito: %s") % clean_text(str(e), 120)
                errors.append(brew_note)
        fn = make_audit(ctx, rep, brew_note, mal)
        if fn is None:
            continue
        try:
            audit = fn()
        except Exception as e:  # noqa: BLE001 - an audit that crashes is a red audit
            audit = AuditResult(rep.id, None, [Check("audit", "error", clean_text(str(e), 200))], {})
        reps[item_key(rep)] = rep.id
        for f in cands:
            audits[f.id] = audit
            if f.lane == "auto" and not audit.green:
                findings[pos[f.id]] = dataclasses.replace(f, lane="manual", reasons=f.reasons + ("audit_red",))

    # At most one apply per item, with the representative finding.
    auto_enabled = cfg.auto_apply and not ctx.dev and all(sources_ok.values())
    applied, shadow = [], []
    for group in group_by_item(findings):
        autos = [f for f in group if f.lane == "auto" and f.id in audits and audits[f.id].green]
        if not autos:
            continue
        rep = findings[pos[reps[item_key(group[0])]]]
        a = audits[rep.id]
        if auto_enabled and rep.item.kind in ("brew_formula", "npm_global"):
            outcome = apply_finding(rep, make_audit(ctx, rep, brew_note, mal), apply_context(ctx, a.candidate_version))
            applied.append(outcome.record)
        else:
            shadow.extend(f.id for f in autos)

    ctx.store.save_findings(run_id, findings, audits)
    ctx.store.finish_run(run_id, "ok" if all(sources_ok.values()) else "partial", {"findings": len(findings)})
    s = RunSummary(date, findings, audits, applied, shadow, errors, sources_ok, auto_enabled, ignores)
    write_report(s, ctx.report_dir, now)
    ctx.notify(notification_text(s))
    return 0, s
