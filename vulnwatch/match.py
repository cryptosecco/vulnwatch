"""Local matching of archived advisories against the inventory. Nothing here touches the network."""
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Tuple

from .i18n import t
from .model import Advisory, Finding, InventoryItem, VersionRange, finding_id
from .versions import affected_by, fixed_for, scheme_for

_PRIMARY = ("osv", "cverecord")
_RANGE_ORDER = ("osv", "cverecord", "cvenow")
_TITLE_ORDER = ("cvenow", "osv", "cverecord", "kev")
_LOOSE_KINDS = {"app", "brew_formula", "brew_cask", "runtime", "macos"}
_MIN_LOOSE = 3


def normalize(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (s or "").lower()).strip()


def _pkg_key(ecosystem: str, name: str) -> Tuple[str, str]:
    eco = ecosystem.lower()
    if eco == "pypi":
        return eco, re.sub(r"[-_.]+", "-", name).lower()
    return eco, name


@dataclass(frozen=True)
class Alias:
    vendor: str
    product: str
    kind: str
    name: str


def load_aliases(path: str) -> List[Alias]:
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    out = []
    for a in raw:
        if not isinstance(a, dict) or set(a) != {"vendor", "product", "kind", "name"}:
            raise ValueError(t("invalid alias entry", "voce alias non valida"))
        out.append(Alias(normalize(a["vendor"]), normalize(a["product"]), a["kind"], a["name"]))
    return out


def _norm_ghsa(x: str) -> str:
    return "GHSA-" + x[5:].lower()


def canonical_id(adv: Advisory) -> str:
    ids = [adv.id] + list(adv.aliases)
    cves = sorted(x for x in ids if x.startswith("CVE-"))
    if cves:
        return cves[0]
    ghsas = sorted(_norm_ghsa(x) for x in ids if x.upper().startswith("GHSA-"))
    if ghsas:
        return ghsas[0]
    return adv.id


@dataclass
class _Group:
    item: InventoryItem
    decisions: Dict[str, Optional[bool]] = field(default_factory=dict)
    ranges: Dict[str, Tuple[VersionRange, ...]] = field(default_factory=dict)
    exact_true: bool = False
    false_primary: bool = False
    malicious: bool = False
    titles: Dict[str, str] = field(default_factory=dict)
    published: Dict[str, str] = field(default_factory=dict)


def build_findings(advisories: Iterable[Advisory], inventory: List[InventoryItem], aliases: List[Alias],
                   now: datetime) -> List[Finding]:
    eco_index: Dict[Tuple[str, str], List[InventoryItem]] = {}
    by_kind_name: Dict[Tuple[str, str], List[InventoryItem]] = {}
    loose: Dict[str, List[InventoryItem]] = {}
    for it in inventory:
        if it.ecosystem:
            eco_index.setdefault(_pkg_key(it.ecosystem, it.name), []).append(it)
        by_kind_name.setdefault((it.kind, it.name), []).append(it)
        if it.kind in _LOOSE_KINDS:
            for label in {normalize(it.name), normalize(it.display_name or "")}:
                if len(label) >= _MIN_LOOSE:
                    loose.setdefault(label, []).append(it)
    alias_by_vendor: Dict[str, List[Alias]] = {}
    for a in aliases:
        alias_by_vendor.setdefault(a.vendor, []).append(a)

    kev_ids, critical_ids = set(), set()
    groups: Dict[Tuple[str, str, str, str], _Group] = {}

    for adv in advisories:
        cid = canonical_id(adv)
        if adv.source == "kev":
            kev_ids.add(cid)
        if adv.source == "cverecord" and adv.cvss is not None and adv.cvss >= 9.0:
            critical_ids.add(cid)
        if adv.source == "osv" and adv.severity == "critical":
            critical_ids.add(cid)
        for aff in adv.affected:
            cands: List[Tuple[InventoryItem, bool]] = []
            if aff.ecosystem and aff.package:
                cands = [(it, True) for it in eco_index.get(_pkg_key(aff.ecosystem, aff.package), [])]
            elif aff.product:
                nv, np_ = normalize(aff.vendor or ""), normalize(aff.product)
                for al in alias_by_vendor.get(nv, []):
                    if np_ == al.product or np_.startswith(al.product + " "):
                        cands += [(it, True) for it in by_kind_name.get((al.kind, al.name), [])]
                if not cands:
                    cands = [(it, False) for it in loose.get(np_, [])]
            for it, exact in cands:
                dec = affected_by(it.version, aff.ranges, aff.versions, scheme_for(it.kind, it.ecosystem))
                g = groups.get((cid, it.kind, it.name, it.location))
                if dec is False:
                    if g is None:
                        g = groups.setdefault((cid, it.kind, it.name, it.location), _Group(it))
                    if adv.source in _PRIMARY:
                        g.false_primary = True
                    continue
                if g is None:
                    g = groups.setdefault((cid, it.kind, it.name, it.location), _Group(it))
                if dec is True:
                    if g.decisions.get(adv.source) is not True:
                        g.decisions[adv.source] = True
                        g.ranges[adv.source] = aff.ranges
                    if exact:
                        g.exact_true = True
                else:
                    g.decisions.setdefault(adv.source, None)
                g.malicious = g.malicious or (adv.source == "osv" and adv.malicious)
                if adv.title and adv.source not in g.titles:
                    g.titles[adv.source] = adv.title
                if adv.published and adv.source not in g.published:
                    g.published[adv.source] = adv.published

    out: List[Finding] = []
    for (cid, kind, name, loc), g in groups.items():
        true_sources = [s for s in _RANGE_ORDER if g.decisions.get(s) is True]
        if not true_sources and not g.decisions:
            continue  # only "not affected" verdicts
        if not true_sources and g.false_primary:
            continue  # a primary source says not affected; an undecidable match does not override it
        range_source = true_sources[0] if true_sources else None
        fixed = None
        if range_source:
            fixed = fixed_for(g.item.version, g.ranges[range_source], scheme_for(g.item.kind, g.item.ecosystem))
        title = next((g.titles[s] for s in _TITLE_ORDER if s in g.titles), "")
        published = next((g.published[s] for s in ("cvenow", "cverecord", "osv", "kev") if s in g.published), None)
        out.append(Finding(
            id=finding_id(cid, kind, name, loc),
            canonical_id=cid,
            item=g.item,
            match="exact" if (g.exact_true and range_source) else "approximate",
            kev_confirmed=cid in kev_ids,
            critical_confirmed=cid in critical_ids,
            malicious=g.malicious,
            range_source=range_source,
            fixed_version=fixed,
            title=title,
            published=published,
        ))
    out.sort(key=lambda f: (f.canonical_id, f.item.kind, f.item.name, f.item.location))
    return out
