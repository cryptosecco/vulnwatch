"""cve.now: generic critical+KEV list, then the detail of EVERY listed entry (never chosen by inventory)."""
import re
from datetime import datetime, timedelta
from typing import Optional
from urllib.parse import quote

from ..i18n import t
from ..model import Advisory, Affected, VersionRange
from ..net import Fetcher, FetchError
from ..store import Store
from . import SyncStats, as_dict, as_list, iso, opt_str, req_str, safe_ids

LIST_URL = "https://cve.now/api/v1/entries?filter=critical,kev"
_DETAIL = "https://cve.now/api/v1/entries/"
_ID_RE = re.compile(r"^(CVE-\d{4}-\d{4,}|GHSA(-[0-9A-Za-z]{4}){3}|[A-Z]{2,10}-[0-9A-Za-z._-]{1,64})$")
_MAX_PAGES = 200
_MAX_BYTES = 5_000_000


def detail_url(id_: str) -> str:
    if not isinstance(id_, str) or not _ID_RE.match(id_):
        raise ValueError(t("invalid cve.now id: %r", "id cve.now non valido: %r") % (id_,))
    return _DETAIL + id_


def _range(r) -> VersionRange:
    r = as_dict(r, "range")
    return VersionRange(opt_str(r.get("introduced"), "introduced"), opt_str(r.get("fixed"), "fixed"),
                        opt_str(r.get("lastAffected"), "lastAffected"))


def _affected(a) -> Affected:
    a = as_dict(a, "affected")
    return Affected(
        ecosystem=opt_str(a.get("ecosystem"), "ecosystem"),
        package=opt_str(a.get("package"), "package"),
        vendor=opt_str(a.get("vendor"), "vendor"),
        product=opt_str(a.get("product"), "product"),
        ranges=tuple(_range(r) for r in as_list(a.get("ranges"), "ranges")),
        versions=tuple(opt_str(v, "versions") or "" for v in as_list(a.get("versions"), "versions")),
    )


def parse_entry(doc) -> Advisory:
    doc = as_dict(doc, t("cve.now entry", "voce cve.now"))
    id_ = req_str(doc.get("id"), "id")
    if not _ID_RE.match(id_):
        raise ValueError(t("invalid cve.now id", "id cve.now non valido"))
    severity = as_dict(doc.get("severity"), "severity")
    cvss = severity.get("cvss")
    if isinstance(cvss, bool) or not isinstance(cvss, (int, float)):
        cvss = None
    summary = as_dict(doc.get("summary"), "summary")
    stated = doc.get("statedSeverity")
    return Advisory(
        id=id_,
        aliases=safe_ids(doc.get("aliases"), "aliases"),
        source="cvenow",
        title=opt_str(doc.get("title"), "title") or "",
        description=opt_str(summary.get("text"), "summary") or opt_str(doc.get("originalDescription"), "originalDescription") or "",
        cvss=float(cvss) if cvss is not None else None,
        severity=stated.lower() if isinstance(stated, str) else None,
        kev=bool(as_dict(doc.get("exploitation"), "exploitation").get("kev")),
        affected=tuple(_affected(a) for a in as_list(doc.get("affected"), "affected")),
        published=opt_str(doc.get("publishedAt"), "publishedAt"),
        modified=opt_str(doc.get("modifiedAt"), "modifiedAt"),
        malicious=False,
    )


def _walk(fetcher: Fetcher, store: Store, start: Optional[str], stop: str, stats: SyncStats, first_must_succeed: bool):
    """Walk the generic list from `start` (None = newest page) down to `stop`.

    Returns (newest publishedAt seen (the list is sorted by publishedAt), complete, cursor to resume from when interrupted).
    A failure on the very first page of the day propagates (the source is down); any later failure
    (rate limit, server error) interrupts the walk but keeps what was queued so far.
    """
    cursor, newest = start, None
    for page in range(_MAX_PAGES):
        url = LIST_URL if cursor is None else LIST_URL + "&cursor=" + quote(cursor, safe="")
        try:
            doc = as_dict(fetcher.get_json(url, max_bytes=_MAX_BYTES), t("cve.now list", "lista cve.now"))
        except FetchError as e:
            if page == 0 and first_must_succeed:
                raise
            stats.failed += 1
            stats.incomplete = True
            stats.errors.append(t("cve.now list interrupted (%s): resuming on the next run",
                                  "lista cve.now interrotta (%s): riprendo al prossimo giro") % e)
            return newest, False, cursor
        stats.fetched += 1
        for e in as_list(doc.get("entries"), "entries"):
            e = e if isinstance(e, dict) else {}
            fs, id_ = e.get("publishedAt"), e.get("id")
            if not isinstance(fs, str) or not isinstance(id_, str):
                stats.errors.append(t("cve.now list: malformed entry", "lista cve.now: voce malformata"))
                continue
            if newest is None or fs > newest:
                newest = fs
            if fs <= stop:
                return newest, True, None
            if not store.has_advisory("cvenow", id_):
                store.queue("cvenow", id_)
        nxt = doc.get("nextCursor")
        if not isinstance(nxt, str) or not nxt:
            return newest, True, None
        cursor = nxt
    stats.incomplete = True
    stats.errors.append(t("cve.now list: reached the limit of %d pages, resuming on the next run",
                          "lista cve.now: raggiunto il limite di %d pagine, riprendo al prossimo giro") % _MAX_PAGES)
    return newest, False, cursor


OVERLAP_DAYS = 7


def _minus_days(value: str, days: int) -> str:
    try:
        return iso(datetime.fromisoformat(value.replace("Z", "+00:00")) - timedelta(days=days))
    except ValueError:
        return value


def _list(fetcher: Fetcher, store: Store, now: datetime, backfill_days: int, stats: SyncStats) -> None:
    """Resumable listing over publishedAt (the list's sort key). Cursors: cvenow_pub_since (listed down to
    here), cvenow_pub_top + cvenow_pub_resume (an unfinished descent: newest entry it started from, and the
    page to continue from). Daily walks re-read OVERLAP_DAYS below the cursor to catch late additions."""
    stored = store.get_cursor("cvenow_pub_since") or None
    since = stored or iso(now - timedelta(days=backfill_days))
    top = store.get_cursor("cvenow_pub_top") or None
    resume = store.get_cursor("cvenow_pub_resume") or None
    anchor = top or stored
    stop_a = _minus_days(anchor, OVERLAP_DAYS) if anchor else since
    newest, complete, stopped = _walk(fetcher, store, None, stop_a, stats, True)
    if top is None:
        if complete:
            if newest and newest > since:
                store.set_cursor("cvenow_pub_since", newest)
        elif newest and stopped:
            store.set_cursor("cvenow_pub_top", newest)
            store.set_cursor("cvenow_pub_resume", stopped)
        return
    if not complete:
        return
    if newest and newest > top:
        store.set_cursor("cvenow_pub_top", newest)
    done, stopped_b = True, None
    if resume:
        _, done, stopped_b = _walk(fetcher, store, resume, since, stats, False)
    if done:
        store.set_cursor("cvenow_pub_since", store.get_cursor("cvenow_pub_top") or since)
        store.set_cursor("cvenow_pub_top", "")
        store.set_cursor("cvenow_pub_resume", "")
    elif stopped_b:
        store.set_cursor("cvenow_pub_resume", stopped_b)


def sync(fetcher: Fetcher, store: Store, now: datetime, backfill_days: int, limit: int) -> SyncStats:
    stats = SyncStats("cvenow")
    _list(fetcher, store, now, backfill_days, stats)
    for id_ in store.pending("cvenow", limit):
        try:
            doc = fetcher.get_json(detail_url(id_), max_bytes=_MAX_BYTES)
            stats.fetched += 1
            adv = parse_entry(doc)
        except FetchError as e:
            stats.errors.append("cve.now %s: %s" % (id_, e))
            if e.status == 404:
                store.done("cvenow", id_)
                continue
            stats.failed += 1
            if e.status in (403, 429):
                stats.incomplete = True
                break
            continue
        except ValueError as e:
            stats.errors.append(t("cve.now %s malformed: %s", "cve.now %s malformata: %s") % (id_, e))
            store.done("cvenow", id_)
            continue
        store.put_advisory(adv, iso(now))
        store.done("cvenow", id_)
        stats.stored += 1
        for cid in (adv.id,) + adv.aliases:
            if cid.startswith("CVE-") and not store.has_advisory("cverecord", cid):
                store.queue("cverecord", cid)
    return stats
