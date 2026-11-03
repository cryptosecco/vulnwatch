"""Official CVE records from cvelistV5, fetched one by one for every CVE id in the public lists (uniform)."""
import re
from datetime import datetime
from typing import Optional

from ..i18n import t
from ..model import Advisory, Affected, VersionRange
from ..net import Fetcher, FetchError
from ..store import Store
from . import SyncStats, as_dict, as_list, iso, opt_str, req_str

_BASE = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"
_CVE_RE = re.compile(r"^CVE-(\d{4})-(\d{4,})$")
_PLACEHOLDER = {None, "", "0", "*", "unspecified", "n/a"}
_CVSS_KEYS = ("cvssV4_0", "cvssV3_1", "cvssV3_0")
_MAX_BYTES = 5_000_000
DELTA_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json"
_DELTA_MAX_BYTES = 100_000_000


def record_url(cve_id: str) -> str:
    m = _CVE_RE.match(cve_id) if isinstance(cve_id, str) else None
    if not m:
        raise ValueError(t("invalid CVE id: %r", "id CVE non valido: %r") % (cve_id,))
    return "%s/%s/%dxxx/%s.json" % (_BASE, m.group(1), int(m.group(2)) // 1000, cve_id)


def _scores(metrics) -> list:
    out = []
    for m in as_list(metrics, "metrics"):
        m = as_dict(m, "metric")
        for k in _CVSS_KEYS:
            if k in m:
                score = as_dict(m[k], k).get("baseScore")
                if isinstance(score, (int, float)) and not isinstance(score, bool):
                    out.append(float(score))
    return out


def _affected(a) -> Affected:
    a = as_dict(a, "affected")
    ranges, versions = [], []
    for v in as_list(a.get("versions"), "versions"):
        v = as_dict(v, "version")
        if v.get("status") != "affected":
            continue
        ver = opt_str(v.get("version"), "version")
        lt = opt_str(v.get("lessThan"), "lessThan")
        lte = opt_str(v.get("lessThanOrEqual"), "lessThanOrEqual")
        intro = None if ver in _PLACEHOLDER else ver
        if lt:
            ranges.append(VersionRange(intro, None if lt == "*" else lt, None))
        elif lte:
            ranges.append(VersionRange(intro, None, None if lte == "*" else lte))
        elif ver not in _PLACEHOLDER:
            versions.append(ver)
    return Affected(None, None, opt_str(a.get("vendor"), "vendor"), opt_str(a.get("product"), "product"),
                    tuple(ranges), tuple(versions))


def parse_record(doc) -> Advisory:
    doc = as_dict(doc, t("CVE record", "record CVE"))
    meta = as_dict(doc.get("cveMetadata"), "cveMetadata")
    cve = req_str(meta.get("cveId"), "cveId")
    if not _CVE_RE.match(cve):
        raise ValueError(t("invalid cveId", "cveId non valido"))
    containers = as_dict(doc.get("containers"), "containers")
    cna = as_dict(containers.get("cna"), "cna")
    scores = _scores(cna.get("metrics"))
    for adp in as_list(containers.get("adp"), "adp"):
        scores.extend(_scores(as_dict(adp, "adp").get("metrics")))
    cvss: Optional[float] = max(scores) if scores else None
    desc = ""
    for d in as_list(cna.get("descriptions"), "descriptions"):
        d = as_dict(d, "description")
        if str(d.get("lang", "")).startswith("en"):
            desc = opt_str(d.get("value"), "description") or ""
            break
    return Advisory(
        id=cve,
        aliases=(),
        source="cverecord",
        title=opt_str(cna.get("title"), "title") or "",
        description=desc,
        cvss=cvss,
        severity="critical" if cvss is not None and cvss >= 9.0 else None,
        kev=False,
        affected=tuple(_affected(a) for a in as_list(cna.get("affected"), "affected")),
        published=opt_str(meta.get("datePublished"), "datePublished"),
        modified=opt_str(meta.get("dateUpdated"), "dateUpdated"),
        malicious=False,
    )


def _refresh_from_delta(fetcher: Fetcher, store: Store, stats: SyncStats) -> None:
    """Re-queue archived records that cvelistV5 says changed (generic download: I1 holds)."""
    since = store.get_cursor("cverecord_delta") or ""
    try:
        log = fetcher.get_json(DELTA_URL, max_bytes=_DELTA_MAX_BYTES)
        stats.fetched += 1
    except FetchError as e:
        stats.failed += 1
        stats.incomplete = True
        stats.errors.append(t("cvelistV5 change log not available: %s",
                              "registro delle modifiche di cvelistV5 non disponibile: %s") % e)
        return
    newest = since
    for block in log if isinstance(log, list) else []:
        if not isinstance(block, dict) or not isinstance(block.get("fetchTime"), str):
            continue
        ft = block["fetchTime"]
        if ft <= since:
            continue
        for key in ("new", "updated"):
            for e in block.get(key) or []:
                cid = e.get("cveId") if isinstance(e, dict) else None
                if isinstance(cid, str) and _CVE_RE.match(cid) and store.has_advisory("cverecord", cid):
                    store.queue("cverecord", cid)
        newest = max(newest, ft)
    if newest and newest != since:
        store.set_cursor("cverecord_delta", newest)


def sync(fetcher: Fetcher, store: Store, now: datetime, limit: int) -> SyncStats:
    stats = SyncStats("cverecord")
    _refresh_from_delta(fetcher, store, stats)
    for cve in store.pending("cverecord", limit):
        try:
            url = record_url(cve)
            doc = fetcher.get_json(url, max_bytes=_MAX_BYTES)
            stats.fetched += 1
            adv = parse_record(doc)
        except FetchError as e:
            stats.errors.append("record %s: %s" % (cve, e))
            if e.status == 404:
                store.done("cverecord", cve)
            else:
                stats.failed += 1
            continue
        except ValueError as e:
            stats.errors.append(t("record %s malformed: %s", "record %s malformato: %s") % (cve, e))
            store.done("cverecord", cve)
            continue
        store.put_advisory(adv, iso(now))
        store.done("cverecord", cve)
        stats.stored += 1
    return stats
