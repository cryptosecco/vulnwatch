"""Vulnerability sources. No sync function ever receives the inventory (invariant I1)."""
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, List, Optional

from ..i18n import t


@dataclass
class SyncStats:
    source: str
    fetched: int = 0
    stored: int = 0
    errors: List[str] = field(default_factory=list)
    failed: int = 0  # network/server failures only (not 404, not malformed data)
    incomplete: bool = False  # the source stopped early today (rate limit, page cap); resumes tomorrow


def iso(now: datetime) -> str:
    return now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def opt_str(value: Any, what: str) -> Optional[str]:
    """None stays None; numbers become text; anything else that is not a string is malformed."""
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError(t("%s: invalid type", "%s: tipo non valido") % what)
    if isinstance(value, (int, float)):
        return str(value)
    if not isinstance(value, str):
        raise ValueError(t("%s: invalid type", "%s: tipo non valido") % what)
    return value


def req_str(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(t("%s: string expected", "%s: stringa attesa") % what)
    return value


def as_list(value: Any, what: str) -> list:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(t("%s: list expected", "%s: lista attesa") % what)
    return value


ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{1,80}$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def req_id(value: Any, what: str) -> str:
    """Advisory ids are external text that ends up in reports: only plain identifier characters."""
    v = req_str(value, what)
    if not ID_RE.match(v):
        raise ValueError(t("%s: invalid identifier", "%s: identificatore non valido") % what)
    return v


def safe_ids(value: Any, what: str) -> tuple:
    return tuple(v for v in as_list(value, what) if isinstance(v, str) and ID_RE.match(v))


def as_dict(value: Any, what: str) -> dict:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(t("%s: object expected", "%s: oggetto atteso") % what)
    return value
