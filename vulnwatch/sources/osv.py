"""OSV bulk data for a FIXED list of ecosystems: all.zip once, then modified_id.csv increments."""
import json
import os
import re
import zipfile
from datetime import datetime
from typing import List, Sequence, Tuple

from ..i18n import t
from ..model import Advisory, Affected, VersionRange
from ..net import Fetcher, FetchError
from ..store import Store
from . import SyncStats, as_dict, as_list, iso, opt_str, req_id, req_str, safe_ids

OSV_BASE = "https://osv-vulnerabilities.storage.googleapis.com"
MAX_MEMBER_BYTES = 5_000_000
_CSV_MAX_BYTES = 200_000_000
_ECO_RE = re.compile(r"^[A-Za-z0-9.:-]{1,40}$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?Z$")
_BATCH = 1000


def ts_key(ts: str) -> Tuple[str, int]:
    m = _TS_RE.match(ts)
    if not m:
        raise ValueError(t("invalid OSV timestamp: %r", "timestamp OSV non valido: %r") % ts)
    return m.group(1), int((m.group(2) or "").ljust(9, "0"))


def _ranges(events) -> List[VersionRange]:
    out, intro, open_ = [], None, False
    for ev in as_list(events, "events"):
        ev = as_dict(ev, "event")
        if "introduced" in ev:
            if open_:
                out.append(VersionRange(intro, None, None))
            intro, open_ = opt_str(ev["introduced"], "introduced"), True
        elif "fixed" in ev:
            out.append(VersionRange(intro if open_ else None, opt_str(ev["fixed"], "fixed"), None))
            open_ = False
        elif "last_affected" in ev:
            out.append(VersionRange(intro if open_ else None, None, opt_str(ev["last_affected"], "last_affected")))
            open_ = False
    if open_:
        out.append(VersionRange(intro, None, None))
    return out


def _affected(a) -> Affected:
    a = as_dict(a, "affected")
    pkg = as_dict(a.get("package"), "package")
    ranges: List[VersionRange] = []
    for r in as_list(a.get("ranges"), "ranges"):
        r = as_dict(r, "range")
        if r.get("type") in ("SEMVER", "ECOSYSTEM"):
            ranges.extend(_ranges(r.get("events")))
    return Affected(
        ecosystem=opt_str(pkg.get("ecosystem"), "ecosystem"),
        package=opt_str(pkg.get("name"), "name"),
        vendor=None,
        product=None,
        ranges=tuple(ranges),
        versions=tuple(req_str(v, "version") for v in as_list(a.get("versions"), "versions")),
    )


def parse_osv(doc) -> Advisory:
    doc = as_dict(doc, t("OSV record", "record OSV"))
    id_ = req_id(doc.get("id"), "id")
    sev = as_dict(doc.get("database_specific"), "database_specific").get("severity")
    return Advisory(
        id=id_,
        aliases=safe_ids(doc.get("aliases"), "aliases"),
        source="osv",
        title=opt_str(doc.get("summary"), "summary") or "",
        description="",
        cvss=None,
        severity=sev.lower() if isinstance(sev, str) else None,
        kev=False,
        affected=tuple(_affected(a) for a in as_list(doc.get("affected"), "affected")),
        published=opt_str(doc.get("published"), "published"),
        modified=opt_str(doc.get("modified"), "modified"),
        malicious=id_.startswith("MAL-"),
    )


def _bootstrap(fetcher, store, now, eco, tmp_dir, zip_max_bytes, stats) -> None:
    dest = os.path.join(tmp_dir, "osv-%s-all.zip" % eco)
    newest = None
    try:
        fetcher.download("%s/%s/all.zip" % (OSV_BASE, eco), dest, zip_max_bytes)
        stats.fetched += 1
        batch = []
        with zipfile.ZipFile(dest) as z:
            for info in z.infolist():
                if not info.filename.endswith(".json") or info.is_dir():
                    continue
                if info.file_size > MAX_MEMBER_BYTES:
                    stats.errors.append(t("OSV %s: %s too large, skipped", "OSV %s: %s troppo grande, saltato")
                                        % (eco, info.filename))
                    continue
                try:
                    adv = parse_osv(json.loads(z.read(info)))
                except (ValueError, zipfile.BadZipFile) as e:
                    stats.errors.append(t("OSV %s: %s malformed (%s)", "OSV %s: %s malformato (%s)")
                                        % (eco, info.filename, e))
                    continue
                batch.append(adv)
                if adv.modified and _TS_RE.match(adv.modified):
                    if newest is None or ts_key(adv.modified) > ts_key(newest):
                        newest = adv.modified
                if len(batch) >= _BATCH:
                    store.put_advisories(batch, iso(now))
                    stats.stored += len(batch)
                    batch = []
        if batch:
            store.put_advisories(batch, iso(now))
            stats.stored += len(batch)
    finally:
        if os.path.exists(dest):
            os.remove(dest)
    if newest:
        store.set_cursor("osv_" + eco, newest)


def _incremental(fetcher, store, now, eco, cursor, limit, stats) -> None:
    body = fetcher.get("%s/%s/modified_id.csv" % (OSV_BASE, eco), max_bytes=_CSV_MAX_BYTES)
    stats.fetched += 1
    ck = ts_key(cursor)
    rows = []
    for line in body.decode("utf-8", "replace").splitlines():
        ts, _, id_ = line.strip().partition(",")
        if not id_:
            continue
        try:
            k = ts_key(ts)
        except ValueError:
            stats.errors.append(t("OSV %s: malformed CSV row", "OSV %s: riga CSV malformata") % eco)
            continue
        if k <= ck:
            break
        rows.append((k, ts, id_))
    rows.sort()
    if len(rows) > limit:
        cut = rows[limit - 1][0]
        rows = [r for r in rows if r[0] <= cut]
    done_ts = cursor
    for k, ts, id_ in rows:
        if not _ID_RE.match(id_):
            stats.errors.append(t("OSV %s: invalid id", "OSV %s: id non valido") % eco)
            done_ts = ts
            continue
        try:
            doc = fetcher.get_json("%s/%s/%s.json" % (OSV_BASE, eco, id_), max_bytes=MAX_MEMBER_BYTES)
            stats.fetched += 1
            store.put_advisory(parse_osv(doc), iso(now))
            stats.stored += 1
        except FetchError as e:
            stats.errors.append("OSV %s %s: %s" % (eco, id_, e))
            if e.status != 404:
                break
        except ValueError as e:
            stats.errors.append(t("OSV %s %s malformed: %s", "OSV %s %s malformato: %s") % (eco, id_, e))
        done_ts = ts
    if done_ts != cursor:
        store.set_cursor("osv_" + eco, done_ts)


def sync(fetcher: Fetcher, store: Store, now: datetime, ecosystems: Sequence[str], tmp_dir: str,
         limit: int, zip_max_bytes: int) -> SyncStats:
    stats = SyncStats("osv")
    for eco in ecosystems:
        if not isinstance(eco, str) or not _ECO_RE.match(eco):
            stats.errors.append(t("invalid OSV ecosystem: %r", "ecosistema OSV non valido: %r") % (eco,))
            continue
        cursor = store.get_cursor("osv_" + eco)
        if cursor is None:
            _bootstrap(fetcher, store, now, eco, tmp_dir, zip_max_bytes, stats)
        else:
            _incremental(fetcher, store, now, eco, cursor, limit, stats)
    return stats
