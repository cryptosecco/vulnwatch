"""Lane assignment. Reasons are fixed English codes with fixed en/it texts: no external text here."""
import dataclasses
import re
from typing import Dict, Mapping, Sequence, Tuple

from .i18n import t
from .model import Finding

AUTO_CHANNELS = {("brew_formula", "homebrew/core"), ("npm_global", "npm_global")}
# Runtimes stay manual: Python (venvs depend on it), Node (other tools may bundle or share it), Bun.
ALWAYS_MANUAL_FORMULAE = re.compile(r"^(python(@[0-9.]+)?|node(@[0-9]+)?|bun)$")

REASONS: Dict[str, Tuple[str, str]] = {
    "not_kev_not_critical": ("not KEV and not critical according to a primary source",
                             "non è KEV né critica secondo una fonte primaria"),
    "range_not_primary": ("the version range comes only from cve.now", "l'intervallo di versioni c'è solo su cve.now"),
    "manual_channel": ("always-manual channel", "canale sempre manuale"),
    "on_hold": ("on the hold list", "nella lista di blocco"),
    "approximate_match": ("approximate match, to verify", "corrispondenza approssimata, da verificare"),
    "fix_version_unknown": ("no known fixed version", "nessuna versione corretta nota"),
    "audit_red": ("audit red", "audit rosso"),
    "malicious_package": ("package reported as malicious", "pacchetto segnalato come malevolo"),
}


def reason_text(code: str) -> str:
    pair = REASONS.get(code)
    return t(*pair) if pair else code


def classify(f: Finding, hold: Sequence[str], ignores: Mapping[str, str]) -> Finding:
    if f.id in ignores:
        return dataclasses.replace(f, lane="ignored", reasons=())
    if f.malicious:
        return dataclasses.replace(f, lane="malicious", reasons=("malicious_package",))
    if f.match == "approximate":
        return dataclasses.replace(f, lane="manual", reasons=("approximate_match",))
    if f.fixed_version is None:
        return dataclasses.replace(f, lane="no_patch", reasons=("fix_version_unknown",))
    reasons = []
    if not (f.kev_confirmed or f.critical_confirmed):
        reasons.append("not_kev_not_critical")
    if f.range_source not in ("osv", "cverecord"):
        reasons.append("range_not_primary")
    if (f.item.kind, f.item.channel) not in AUTO_CHANNELS or (
            f.item.kind == "brew_formula" and ALWAYS_MANUAL_FORMULAE.match(f.item.name)):
        reasons.append("manual_channel")
    if f.item.name in hold:
        reasons.append("on_hold")
    return dataclasses.replace(f, lane="manual" if reasons else "auto", reasons=tuple(reasons))
