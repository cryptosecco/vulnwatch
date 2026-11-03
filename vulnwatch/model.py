"""Data model shared by every module."""
import dataclasses
import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass(frozen=True)
class VersionRange:
    introduced: Optional[str]
    fixed: Optional[str]
    last_affected: Optional[str]


@dataclass(frozen=True)
class Affected:
    ecosystem: Optional[str]
    package: Optional[str]
    vendor: Optional[str]
    product: Optional[str]
    ranges: Tuple[VersionRange, ...]
    versions: Tuple[str, ...]


@dataclass(frozen=True)
class Advisory:
    id: str
    aliases: Tuple[str, ...]
    source: str
    title: str
    description: str
    cvss: Optional[float]
    severity: Optional[str]
    kev: bool
    affected: Tuple[Affected, ...]
    published: Optional[str]
    modified: Optional[str]
    malicious: bool


@dataclass(frozen=True)
class InventoryItem:
    kind: str
    name: str
    version: str
    ecosystem: Optional[str]
    channel: Optional[str]
    location: str
    team_id: Optional[str] = None
    display_name: Optional[str] = None


@dataclass(frozen=True)
class Finding:
    id: str
    canonical_id: str
    item: InventoryItem
    match: str
    kev_confirmed: bool
    critical_confirmed: bool
    malicious: bool
    range_source: Optional[str]
    fixed_version: Optional[str]
    title: str
    published: Optional[str]
    lane: str = "manual"
    reasons: Tuple[str, ...] = ()


@dataclass
class Check:
    name: str
    status: str
    detail: str


@dataclass
class AuditResult:
    finding_id: str
    candidate_version: Optional[str]
    checks: List[Check] = field(default_factory=list)
    evidence: Dict[str, str] = field(default_factory=dict)

    @property
    def green(self) -> bool:
        return bool(self.checks) and all(c.status == "pass" for c in self.checks)


def finding_id(canonical_id: str, kind: str, name: str, location: str) -> str:
    raw = "|".join((canonical_id, kind, name, location)).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:12]


def to_dict(obj: Any) -> dict:
    return dataclasses.asdict(obj)


def _range(d: dict) -> VersionRange:
    return VersionRange(d.get("introduced"), d.get("fixed"), d.get("last_affected"))


def _affected(d: dict) -> Affected:
    return Affected(
        ecosystem=d.get("ecosystem"),
        package=d.get("package"),
        vendor=d.get("vendor"),
        product=d.get("product"),
        ranges=tuple(_range(r) for r in d.get("ranges", ())),
        versions=tuple(d.get("versions", ())),
    )


def advisory_from_dict(d: dict) -> Advisory:
    return Advisory(
        id=d["id"],
        aliases=tuple(d.get("aliases", ())),
        source=d["source"],
        title=d.get("title", ""),
        description=d.get("description", ""),
        cvss=d.get("cvss"),
        severity=d.get("severity"),
        kev=bool(d.get("kev", False)),
        affected=tuple(_affected(a) for a in d.get("affected", ())),
        published=d.get("published"),
        modified=d.get("modified"),
        malicious=bool(d.get("malicious", False)),
    )


def item_from_dict(d: dict) -> InventoryItem:
    return InventoryItem(
        kind=d["kind"],
        name=d["name"],
        version=d["version"],
        ecosystem=d.get("ecosystem"),
        channel=d.get("channel"),
        location=d["location"],
        team_id=d.get("team_id"),
        display_name=d.get("display_name"),
    )


def finding_from_dict(d: dict) -> Finding:
    return Finding(
        id=d["id"],
        canonical_id=d["canonical_id"],
        item=item_from_dict(d["item"]),
        match=d["match"],
        kev_confirmed=bool(d["kev_confirmed"]),
        critical_confirmed=bool(d["critical_confirmed"]),
        malicious=bool(d["malicious"]),
        range_source=d.get("range_source"),
        fixed_version=d.get("fixed_version"),
        title=d.get("title", ""),
        published=d.get("published"),
        lane=d.get("lane", "manual"),
        reasons=tuple(d.get("reasons", ())),
    )


def audit_from_dict(d: dict) -> AuditResult:
    return AuditResult(
        finding_id=d["finding_id"],
        candidate_version=d.get("candidate_version"),
        checks=[Check(c["name"], c["status"], c["detail"]) for c in d.get("checks", ())],
        evidence=dict(d.get("evidence", {})),
    )
