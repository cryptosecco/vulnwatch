"""`vulnwatch status`: a read-only summary of the installation, the schedule and the latest run. No network."""
import glob
import os
from typing import Callable, List, Optional

from .config import Config
from .i18n import t
from .selfcheck import verify

LABEL = "local.vulnwatch"
_SUMMARY_PREFIXES = ("Summary per item:", "Riepilogo per elemento:")


def _summary_line(report_path: str) -> Optional[str]:
    try:
        with open(report_path, encoding="utf-8") as f:
            for line in f:
                if line.startswith(_SUMMARY_PREFIXES):
                    return line.strip()
    except OSError:
        return None
    return None


def status_lines(cfg: Config, install_root: str, plist: str, run, uid: int, store,
                 verify_fn: Callable = verify) -> List[str]:
    out: List[str] = []
    if os.path.isdir(install_root):
        try:
            with open(os.path.join(install_root, "VERSION"), encoding="utf-8") as f:
                commit = f.read().strip()[:12] or "?"
        except OSError:
            commit = "?"
        out.append(t("Installed:   commit %s", "Installato:  commit %s") % commit)
        problems = verify_fn(install_root, plist)
        out.append(t("Integrity:   intact", "Integrità:   integra") if not problems else
                   t("Integrity:   %d problems, run vulnwatch selfcheck", "Integrità:   %d problemi, lancia vulnwatch selfcheck")
                   % len(problems))
    else:
        out.append(t('Installed:   not installed (run ./setup.sh, then sudo ./install.sh "$(git rev-parse HEAD)")',
                     'Installato:  non installato (lancia ./setup.sh, poi sudo ./install.sh "$(git rev-parse HEAD)")'))
    loaded = run(["/bin/launchctl", "print", "gui/%d/%s" % (uid, LABEL)], timeout=10).returncode == 0
    out.append(t("Schedule:    every day at 07:30", "Pianificato: ogni giorno alle 07:30") if loaded else
               t("Schedule:    not loaded in launchd", "Pianificato: non caricato in launchd"))

    last = store.last_run() if store is not None else None
    if last is None:
        out.append(t("Last run:    no runs yet", "Ultimo run:  nessun run ancora"))
    elif last.get("finished_at") is None:
        out.append(t("Last run:    started %s, in progress (or interrupted)", "Ultimo run:  partito %s, in corso (o interrotto)")
                   % last.get("started_at"))
    else:
        out.append(t("Last run:    started %s, finished %s UTC, status %s", "Ultimo run:  partito %s, finito %s UTC, esito %s")
                   % (last.get("started_at"), last.get("finished_at"), last.get("status")))
    pending = store.pending_count() if store is not None else 0
    if pending:
        out.append(t("Queue:       %d records still to download", "Coda:        %d record ancora da scaricare") % pending)
    if store is None or not store.has_completed_run():
        out.append(t("First run:   the first download takes about 2 hours; you get a notification when the report is ready.",
                     "Primo run:   il primo download dura circa 2 ore; arriva una notifica quando il report è pronto."))

    reports = sorted(glob.glob(os.path.join(cfg.state_dir, "reports", "*.md")))
    if reports:
        out.append(t("Report:      %s", "Report:      %s") % reports[-1])
        line = _summary_line(reports[-1])
        if line:
            out.append("             " + line)
    out.append(t("Mode:        automatic lane on (green audits are applied for homebrew/core formulae and npm globals)",
                 "Modalità:    corsia automatica accesa (si applicano gli audit verdi di formule homebrew/core e npm globali)")
               if cfg.auto_apply else
               t("Mode:        shadow (reports only, never applies anything on its own)",
                 "Modalità:    ombra (solo report, non applica mai nulla da solo)"))
    return out
