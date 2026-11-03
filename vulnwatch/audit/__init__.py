"""Audit gate helpers. Every check fails closed: missing or unreadable data is 'unknown', never 'pass'."""
from datetime import datetime, timezone
from typing import Optional

from ..i18n import t
from ..model import Check


def parse_time(value: Optional[str]) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    s = value.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def cooldown_check(published_iso: Optional[str], now: datetime, hours: int, accept_fresh: bool) -> Check:
    dt = parse_time(published_iso)
    if dt is None:
        return Check("cooldown", "unknown", t("publication date missing or unreadable",
                                              "data di pubblicazione assente o illeggibile"))
    age = (now - dt).total_seconds() / 3600.0
    if age >= hours:
        return Check("cooldown", "pass", t("published %d hours ago", "pubblicata %d ore fa") % int(age))
    if accept_fresh:
        return Check("cooldown", "pass", t("overridden by hand: published %d hours ago",
                                           "superato a mano: pubblicata %d ore fa") % max(int(age), 0))
    return Check("cooldown", "fail", t("published only %d hours ago (minimum %d)",
                                       "pubblicata solo %d ore fa (minimo %d)") % (max(int(age), 0), hours))
