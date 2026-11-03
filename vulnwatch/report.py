"""Daily report (Markdown + JSON) and macOS notification. External text is always inert."""
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Tuple

from .apply import can_apply, instructions
from .audit import parse_time
from .grouping import group_by_item, item_key, representative
from .i18n import t
from .lanes import reason_text
from .model import AuditResult, Finding, to_dict
from .sanitize import clean_text

_NOTIFY_RE = re.compile(r"^[0-9A-Za-zàèéìòù ,.:·-]*$")
_RECENT_DAYS = 30
_MAX_IDS = 30


def _status(st: str) -> str:
    return {"pass": "✅ ok", "fail": "❌ " + t("no", "no"), "unknown": "❔ " + t("unknown", "ignoto"),
            "error": "⚠️ " + t("error", "errore")}.get(st, st)


def _kind(kind) -> str:
    return {"npm_global": t("npm global", "npm globale"), "brew_formula": t("brew formula", "formula brew"),
            "brew_cask": t("brew cask", "cask brew"), "app": "app", "runtime": "runtime", "macos": "macOS",
            "lockfile_pkg": "lockfile"}.get(kind, kind)


def summary_prefix() -> str:
    """Start of the summary line; `vulnwatch status` looks for it in the latest report."""
    return t("Summary per item:", "Riepilogo per elemento:")


@dataclass
class RunSummary:
    date: str
    findings: List[Finding]
    audits: Dict[str, AuditResult]
    applied: List[dict]
    shadow: List[str]
    errors: List[str]
    sources_ok: Dict[str, bool]
    auto_enabled: bool
    ignores: Dict[str, str] = field(default_factory=dict)


def _defang(value: object, max_len: int = 500) -> str:
    s = clean_text(value, max_len).replace("`", "'").replace("|", "/")
    return re.sub(r"(?i)\bhttp", "hxxp", s).replace("://", "[:]//").replace("](", "] (")


def _inert(value: object, max_len: int = 200) -> str:
    s = _defang(value, max_len)
    return "`%s`" % s if s else "`-`"


def _no_data(s: RunSummary) -> bool:
    return bool(s.sources_ok) and not any(s.sources_ok.values())


def _block(group: List[Finding], s: RunSummary) -> List[str]:
    f = representative(group)
    it = f.item
    n = len(group)
    out = ["### %s %s %s · %d %s" % (_kind(it.kind), _inert(it.name, 120), _inert(it.version, 60),
                                     n, t("vulnerabilities", "vulnerabilità") if n != 1 else t("vulnerability", "vulnerabilità")),
           t("- Location: %s", "- Posizione: %s") % _inert(it.location, 200)]
    if f.fixed_version:
        out.append(t("- Fixed version: %s (source: %s)", "- Versione corretta: %s (fonte: %s)") % (clean_text(f.fixed_version, 60), f.range_source or "?"))
    else:
        out.append(t("- Fixed version: unknown", "- Versione corretta: non nota"))
    kev = sum(1 for x in group if x.kev_confirmed)
    crit = sum(1 for x in group if x.critical_confirmed)
    yes = t("yes (%d)", "sì (%d)")
    out.append(t("- KEV: %s · Critical: %s", "- KEV: %s · Critiche: %s") % (yes % kev if kev else "no", yes % crit if crit else "no"))
    reasons: List[str] = []
    for x in group:
        for r in x.reasons:
            if r not in reasons:
                reasons.append(r)
    if reasons:
        out.append(t("- Reasons: ", "- Motivi: ") + "; ".join(reason_text(r) for r in reasons))
    shown = ["%s (`%s`)" % (_inert(x.canonical_id, 80), x.id) for x in group[:_MAX_IDS]]
    more = t(" … and %d more", " … e altre %d") % (n - _MAX_IDS) if n > _MAX_IDS else ""
    out.append(t("- Vulnerabilities: ", "- Vulnerabilità: ") + ", ".join(shown) + more)
    a = next((s.audits[x.id] for x in [f] + group if x.id in s.audits), None)
    if a is not None:
        out += ["", t("| check | result | detail |", "| controllo | esito | dettaglio |"), "|---|---|---|"]
        for c in a.checks:
            out.append("| %s | %s | %s |" % (c.name, _status(c.status), _inert(c.detail) if c.detail else ""))
        out.append("")
    if can_apply(f):
        out.append(t("- Command: `vulnwatch apply %s`", "- Comando: `vulnwatch apply %s`") % f.id)
    else:
        out.append(t("- What to do: ", "- Cosa fare: ") + _defang(instructions(f), 600))
    if f.title:
        out.append(t("> [untrusted text] ", "> [testo non fidato] ") + _inert(f.title))
    out.append("")
    return out


def _section(title: str, body: List[str]) -> List[str]:
    return ["## " + title, ""] + (body if body else [t("_No entries._", "_Nessuna voce._"), ""])


def _blocks(findings: List[Finding], s: RunSummary) -> List[str]:
    body: List[str] = []
    for group in group_by_item(findings):
        body += _block(group, s)
    return body


def _items(findings: List[Finding]) -> int:
    return len({item_key(f) for f in findings})


def render_markdown(s: RunSummary, now: datetime) -> str:
    by_lane: Dict[str, List[Finding]] = {}
    for f in s.findings:
        by_lane.setdefault(f.lane, []).append(f)
    shadow = [f for f in s.findings if f.id in s.shadow]
    waiting = [f for f in by_lane.get("manual", []) if f.match == "exact"]
    approx = [f for f in by_lane.get("manual", []) if f.match == "approximate"]

    lines = ["# vulnwatch · %s" % s.date, ""]
    if _no_data(s):
        lines += [t("**NO DATA: nothing could be checked today. That does not mean you are safe.**",
                   "**NESSUN DATO: oggi non è stato possibile verificare nulla. Non vuol dire che sei al sicuro.**"), ""]
    lines += [t("Automatic lane: %s.", "Corsia automatica: %s.") % (
                  t("on", "accesa") if s.auto_enabled else t("off (shadow mode or a source missing)",
                                                             "spenta (modalità ombra o una fonte mancante)")),
              summary_prefix() + t(" %d malicious · %d applied · %d in shadow · %d waiting for you · %d without a patch · "
                                   "%d to verify (%d vulnerabilities in total).",
                                   " %d malevoli · %d applicati · %d in ombra · %d da approvare · %d senza patch · "
                                   "%d da verificare (%d vulnerabilità in tutto).") % (
                  _items(by_lane.get("malicious", [])), len(s.applied), _items(shadow), _items(waiting),
                  _items(by_lane.get("no_patch", [])), _items(approx), len(s.findings)), ""]

    lines += _section("⚠️ " + t("Malicious packages", "Pacchetti malevoli"), _blocks(by_lane.get("malicious", []), s))

    body = []
    for r in s.applied:
        item = r.get("item") or {}
        status = r.get("status")
        body.append("- %s`%s` · %s %s: %s" % ("⚠️ " if status != "applied" else "", r.get("finding_id"),
                                             _kind(item.get("kind")),
                                             _inert(item.get("name"), 120), status))
        before, after = r.get("before") or {}, r.get("after") or {}
        body.append(t("  - Before: %s · After: %s", "  - Prima: %s · Dopo: %s") % (_inert(before.get("version"), 60), _inert(after.get("version"), 60)))
        checks = r.get("checks") or []
        body.append(t("  - Audit: %d checks, %d green", "  - Audit: %d controlli, %d verdi") % (len(checks), sum(1 for c in checks if c.get("status") == "pass")))
        for p in r.get("problems") or []:
            body.append(t("  - Problem: ", "  - Problema: ") + _inert(p, 200))
        if r.get("rollback"):
            body.append("  - Rollback: " + _inert(r["rollback"], 200))
    lines += _section(t("Applied automatically", "Applicato automaticamente"), body + ([""] if body else []))

    lines += _section(t("Would have applied (shadow mode)", "Avrei applicato (modalità ombra)"), _blocks(shadow, s))
    lines += _section(t("Waiting for you", "Aspetta te"), _blocks(waiting, s))
    lines += _section(t("No patch yet", "Senza patch"), _blocks(by_lane.get("no_patch", []), s))

    recent, old = [], 0
    limit = now - timedelta(days=_RECENT_DAYS)
    for f in approx:
        dt = parse_time(f.published)
        if not f.kev_confirmed and dt is not None and dt < limit:
            old += 1
        else:
            recent.append(f)
    body = _blocks(recent, s)
    if old:
        body += [t("%d approximate matches older than %d days not shown.",
                  "%d corrispondenze approssimate più vecchie di %d giorni non mostrate.") % (old, _RECENT_DAYS), ""]
    lines += _section(t("To verify (approximate matches)", "Da verificare (corrispondenze approssimate)"), body)

    body = []
    for f in by_lane.get("ignored", []):
        body.append(t("- `%s` · %s %s — reason: %s", "- `%s` · %s %s — motivo: %s") % (f.id, _inert(f.canonical_id, 80), _inert(f.item.name, 120),
                                                    _inert(s.ignores.get(f.id, ""))))
    lines += _section(t("Ignored", "Ignorate"), body + ([""] if body else []))

    body = ["- %s: %s" % (name, "✅ ok" if ok else "❌ " + t("failed", "fallita")) for name, ok in sorted(s.sources_ok.items())]
    body += ["- " + clean_text(e, 300) for e in s.errors[:50]]
    if len(s.errors) > 50:
        body.append(t("- … %d more errors", "- … altri %d errori") % (len(s.errors) - 50))
    lines += _section(t("Errors and sources", "Errori e fonti"), body + [""])
    return "\n".join(lines)


def write_report(s: RunSummary, out_dir: str, now: datetime) -> Tuple[str, str]:
    os.makedirs(out_dir, exist_ok=True)
    md_path = os.path.join(out_dir, "%s.md" % s.date)
    json_path = os.path.join(out_dir, "%s.json" % s.date)
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(render_markdown(s, now))
    data = {
        "date": s.date, "auto_enabled": s.auto_enabled, "sources_ok": s.sources_ok, "errors": s.errors,
        "shadow": s.shadow, "applied": s.applied, "ignores": s.ignores,
        "findings": [to_dict(f) for f in s.findings],
        "audits": {k: to_dict(v) for k, v in s.audits.items()},
    }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
    return md_path, json_path


def notification_text(s: RunSummary) -> str:
    if _no_data(s):
        return t("NO DATA", "NESSUN DATO")
    mal = _items([f for f in s.findings if f.lane == "malicious"])
    waiting = _items([f for f in s.findings if (f.lane == "manual" and f.match == "exact") or f.id in s.shadow])
    applied = sum(1 for r in s.applied if r.get("status") == "applied")
    troubled = sum(1 for r in s.applied if r.get("status") != "applied")
    kev = _items([f for f in s.findings if f.kev_confirmed and
                  (f.lane == "no_patch" or (f.lane == "manual" and f.match == "approximate"))])
    text = t("%d waiting for you · %d applied · %d malicious", "%d da approvare · %d applicate · %d malevoli") % (waiting, applied, mal)
    if kev:
        text += t(" · %d KEV to verify", " · %d KEV da verificare") % kev
    if troubled:
        text = t("WARNING: %d applies with problems · %s", "ATTENZIONE: %d applicazioni con problemi · %s") % (troubled, text)
    return text


def notify(text: str, run) -> None:
    if not isinstance(text, str) or not _NOTIFY_RE.match(text):
        raise ValueError("notification text not allowed")
    run(["/usr/bin/osascript", "-e", 'display notification "%s" with title "vulnwatch"' % text], timeout=10)
