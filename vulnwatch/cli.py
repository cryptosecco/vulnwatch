"""Command line: run, apply, ignore, report, selfcheck. User-facing text goes through i18n.t()."""
import argparse
import dataclasses
import getpass
import glob
import json
import os
import shutil
import tempfile
import time
from datetime import datetime, timezone
from typing import List, Optional

from . import report as report_mod
from . import setup as setup_mod
from .apply import apply_finding, can_apply, instructions
from .brew_client import BrewClient, brew_env
from .config import Config, ConfigError, load_config
from .i18n import language, set_language, t
from .inventory import collect
from .net import Fetcher, UrllibTransport
from .proc import Runner
from .runner import RunContext, apply_context, make_audit, malicious_index, reinventory, run_daily
from .sanitize import clean_text
from .selfcheck import verify
from .status import status_lines
from .sources import iso
from .store import AlreadyRunning, RunLock, Store

INSTALL_ROOT = "/usr/local/libexec/vulnwatch"
PLIST = "/Library/LaunchAgents/local.vulnwatch.plist"
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_STALE_LOCK_HOURS = 6


def _config(dev: bool, config_path: Optional[str]) -> Config:
    default = os.path.join(REPO_ROOT if dev else INSTALL_ROOT, "config", "config.json")
    cfg = load_config(config_path or default)
    if dev:
        cfg = dataclasses.replace(cfg, state_dir=cfg.state_dir + "-dev", log_dir=cfg.log_dir + "-dev", auto_apply=False)
    return cfg


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="vulnwatch", description=t("Daily vulnerability check for this Mac.",
                                                                "Controllo giornaliero delle vulnerabilità di questo Mac."))
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help=t("run the daily check now", "esegue il controllo giornaliero"))
    a = sub.add_parser("apply", help=t("apply a report entry after a fresh audit",
                                       "applica una voce del report dopo un nuovo audit"))
    a.add_argument("id")
    a.add_argument("--accept-fresh", action="store_true",
                   help=t("accept a version younger than the cooldown", "accetta una versione più giovane del cooldown"))
    i = sub.add_parser("ignore", help=t("ignore an entry, with a reason", "ignora una voce, con un motivo"))
    i.add_argument("id")
    i.add_argument("--reason", required=True)
    rp = sub.add_parser("report", help=t("print the path of the latest report", "mostra il percorso dell'ultimo report"))
    sub.add_parser("selfcheck", help=t("verify the installed copy", "verifica l'installazione"))
    st = sub.add_parser("status", help=t("show installation, schedule and the latest run",
                                         "mostra installazione, pianificazione e ultimo run"))
    sub.add_parser("setup", help=t("detect this Mac and write config/config.json (use ./setup.sh)",
                                   "rileva questo Mac e scrive config/config.json (usa ./setup.sh)"))
    for sp in (r, a, i, rp, st):
        sp.add_argument("--dev", action="store_true", help=t("use the development copy; no automatic applies",
                                                              "usa la copia di sviluppo; niente applicazioni automatiche"))
    return p


def _confirm_prompt() -> str:
    return t("Apply %s %s -> %s? [y/N] ", "Applicare %s %s -> %s? [s/N] ")


def _confirmed(answer: str) -> bool:
    yes = ("s", "si", "sì") if language() == "it" else ("y", "yes")
    return answer.strip().lower() in yes


def _ctx(cfg: Config, dev: bool, problems: List[str], tmp: str, store: Store, run: Runner, fetcher: Fetcher,
         notify=None) -> RunContext:
    brew = BrewClient(run, cfg.brew)

    def inventory():
        if cfg.brew is None:
            return collect(cfg, run, None)
        r = run([cfg.brew, "info", "--json=v2", "--installed"], timeout=300, env=brew_env())
        if r.returncode != 0:
            raise RuntimeError(t("brew info --installed failed", "brew info --installed non riuscito"))
        return collect(cfg, run, json.loads(r.stdout))

    return RunContext(
        cfg=cfg, fetcher=fetcher, store=store, run=run, brew=brew, now=datetime.now(timezone.utc), tmp_dir=tmp,
        dev=dev, selfcheck=lambda: problems, inventory=inventory,
        notify=notify or (lambda t: report_mod.notify(t, run)),
        report_dir=os.path.join(cfg.state_dir, "reports"), actions_log=os.path.join(cfg.log_dir, "actions.jsonl"))


def _run(cfg: Config, dev: bool, problems: List[str], notify) -> int:
    try:
        run, store = Runner(), Store(os.path.join(cfg.state_dir, "state.db"))
        fetcher = Fetcher(UrllibTransport(), cfg.allowed_hosts, min_interval=cfg.min_request_interval,
                          host_intervals=cfg.host_intervals)
        tmp = tempfile.mkdtemp(dir=cfg.state_dir)
    except Exception:
        notify(t("vulnwatch: startup error, see the logs", "vulnwatch: errore in avvio, vedi i log"))
        raise
    ctx = _ctx(cfg, dev, problems, tmp, store, run, fetcher, notify)
    try:
        code, summary = run_daily(ctx)
        print("Report: %s" % os.path.join(ctx.report_dir, summary.date + ".md"))
        return code
    except Exception:
        notify(t("vulnwatch: unexpected error, see the logs", "vulnwatch: errore inatteso, vedi i log"))
        raise
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        _write_request_log(cfg, ctx.now, fetcher)
        store.close()


def _write_request_log(cfg: Config, now: datetime, fetcher: Optional[Fetcher]) -> None:
    """Every HTTP request vulnwatch makes, in run and in apply, goes to requests-<UTC date>.log."""
    if fetcher is None:
        return
    with open(os.path.join(cfg.log_dir, "requests-%s.log" % now.strftime("%Y-%m-%d")), "a", encoding="utf-8") as f:
        f.write("".join(u + "\n" for u in fetcher.request_log))


def _apply(cfg: Config, dev: bool, fid: str, accept_fresh: bool) -> int:
    run, store = Runner(), Store(os.path.join(cfg.state_dir, "state.db"))
    fetcher: Optional[Fetcher] = None
    try:
        f = store.find(fid)
        if f is None:
            print(t("Entry %s not found in the latest report.", "Voce %s non trovata nell'ultimo report.") % clean_text(fid, 40))
            return 1
        if not can_apply(f):
            print(instructions(f))
            return 0
        fetcher = Fetcher(UrllibTransport(), cfg.allowed_hosts, min_interval=cfg.min_request_interval,
                          host_intervals=cfg.host_intervals)
        ctx = _ctx(cfg, dev, [], "", store, run, fetcher)
        live = reinventory(ctx, f.item)
        if live is None or live.version != f.item.version:
            print(t("State changed: %s is now %s, the report said %s. Run vulnwatch run again before applying.",
                    "Lo stato è cambiato: %s ora risulta %s, il report diceva %s. Rilancia vulnwatch run prima di applicare.") % (
                clean_text(f.item.name, 100), clean_text(live.version, 60) if live else t("not installed", "non installato"),
                clean_text(f.item.version, 60)))
            return 1
        note = None
        if f.item.kind in ("brew_formula", "brew_cask"):
            try:
                ctx.brew.update()
            except ValueError as e:
                note = t("brew update failed: %s", "brew update non riuscito: %s") % e
        audit_fn = make_audit(ctx, f, note, malicious_index(store), accept_fresh=accept_fresh, interactive=True)
        if audit_fn is None:
            print(instructions(f))
            return 0
        fresh = audit_fn()
        print(t("Audit of %s %s:", "Audit di %s %s:") % (f.item.kind, clean_text(f.item.name, 100)))
        for c in fresh.checks:
            print("  %-24s %-8s %s" % (c.name, c.status, clean_text(c.detail, 200)))
        if not fresh.green:
            print(t("Audit not green: nothing applied.", "Audit non verde: non applico nulla."))
            return 1
        answer = input(_confirm_prompt() % (clean_text(f.item.name, 100), clean_text(f.item.version, 60),
                                            fresh.candidate_version or t("update", "aggiornamento")))
        if not _confirmed(answer):
            print(t("Cancelled.", "Annullato."))
            return 0
        outcome = apply_finding(f, audit_fn, apply_context(ctx, fresh.candidate_version, accept_fresh))
        print(t("Outcome: %s", "Esito: %s") % outcome.status)
        for p in outcome.problems:
            print("- " + clean_text(p, 300))
        return 0 if outcome.status.startswith("applied") else 1
    finally:
        _write_request_log(cfg, datetime.now(timezone.utc), fetcher)
        store.close()


def _lock_age_hours(path: str) -> float:
    try:
        return (time.time() - os.path.getmtime(path)) / 3600.0
    except OSError:
        return 0.0


def main(argv: List[str], config_path: Optional[str] = None, notifier=None) -> int:
    if argv and argv[0] == "setup":
        if os.path.realpath(REPO_ROOT) == os.path.realpath(INSTALL_ROOT):
            print("Run setup from your clone of the repository: ./setup.sh")
            return 2
        return setup_mod.main(argv[1:], REPO_ROOT)
    args = _parser().parse_args(argv)
    dev = bool(getattr(args, "dev", False))
    is_run = args.cmd == "run"
    notify = notifier or (lambda t: report_mod.notify(t, Runner()))
    try:
        cfg = _config(dev, config_path)
    except ConfigError as e:
        print("Invalid configuration: %s" % e)
        if is_run:
            notify("vulnwatch: invalid configuration, job stopped")
        return 1
    set_language(cfg.language)
    if getpass.getuser() != cfg.user:
        print(t("vulnwatch runs only for the user %s.", "vulnwatch gira solo per l'utente %s.") % cfg.user)
        return 1
    if args.cmd == "status":
        # Read-only: no state folder, database or log is created just to look.
        db = os.path.join(cfg.state_dir, "state.db")
        store = Store(db) if os.path.isfile(db) else None
        try:
            for line in status_lines(cfg, INSTALL_ROOT, PLIST, Runner(), os.getuid(), store):
                print(line)
        finally:
            if store is not None:
                store.close()
        return 0
    if args.cmd == "selfcheck":
        problems = verify(INSTALL_ROOT, PLIST)
        for p in problems:
            print("- " + p)
        print(t("Installation intact.", "Installazione integra.") if not problems else t("Suspected tampering.", "Manomissione sospetta."))
        return 2 if problems else 0
    problems: List[str] = []
    if dev:
        print(t("--dev mode: self-check skipped, automatic lane off.", "Modalità --dev: auto-controllo saltato, corsia automatica spenta."))
    else:
        problems = verify(INSTALL_ROOT, PLIST)
    try:
        os.makedirs(cfg.state_dir, mode=0o700, exist_ok=True)
        os.makedirs(cfg.log_dir, mode=0o700, exist_ok=True)
    except OSError:
        if is_run:
            notify(t("vulnwatch: startup error, see the logs", "vulnwatch: errore in avvio, vedi i log"))
        raise
    if args.cmd == "report":
        files = sorted(glob.glob(os.path.join(cfg.state_dir, "reports", "*.md")))
        print(files[-1] if files else t("No report yet.", "Nessun report ancora."))
        return 0 if files else 1
    if args.cmd == "ignore":
        store = Store(os.path.join(cfg.state_dir, "state.db"))
        try:
            store.add_ignore(args.id, clean_text(args.reason, 300), iso(datetime.now(timezone.utc)))
        finally:
            store.close()
        print(t("Entry %s ignored. It stays visible in the Ignored section of the report.",
                "Voce %s ignorata. Resterà visibile nella sezione Ignorate del report.") % clean_text(args.id, 40))
        return 0
    lock_path = os.path.join(cfg.state_dir, "run.lock")
    lock = RunLock(lock_path)
    try:
        lock.__enter__()
    except AlreadyRunning:
        print(t("already running", "già in esecuzione"))
        if is_run and _lock_age_hours(lock_path) > _STALE_LOCK_HOURS:
            notify(t("vulnwatch: run stuck for more than %d hours", "vulnwatch: esecuzione bloccata da più di %d ore") % _STALE_LOCK_HOURS)
        return 4
    try:
        if is_run:
            return _run(cfg, dev, problems, notify)
        if problems:
            for p in problems:
                print("- " + p)
            print(t("Suspected tampering: nothing applied.", "Manomissione sospetta: non applico nulla."))
            return 2
        return _apply(cfg, dev, args.id, args.accept_fresh)
    finally:
        lock.__exit__(None, None, None)
