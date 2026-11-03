"""CISA Known Exploited Vulnerabilities catalog (primary source, downloaded whole every day)."""
from datetime import datetime
from typing import List

from ..i18n import t
from ..model import Advisory, Affected
from ..net import Fetcher
from ..store import Store
from . import CVE_RE, SyncStats, as_dict, as_list, iso, opt_str, req_str

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_MAX_BYTES = 30_000_000


def _parse_one(v) -> Advisory:
    v = as_dict(v, t("KEV entry", "voce KEV"))
    cve = req_str(v.get("cveID"), "cveID")
    if not CVE_RE.match(cve):
        raise ValueError(t("invalid cveID", "cveID non valido"))
    return Advisory(
        id=cve,
        aliases=(),
        source="kev",
        title=opt_str(v.get("vulnerabilityName"), "vulnerabilityName") or "",
        description=opt_str(v.get("shortDescription"), "shortDescription") or "",
        cvss=None,
        severity=None,
        kev=True,
        affected=(Affected(None, None, opt_str(v.get("vendorProject"), "vendorProject"),
                           opt_str(v.get("product"), "product"), (), ()),),
        published=opt_str(v.get("dateAdded"), "dateAdded"),
        modified=None,
        malicious=False,
    )


def parse_catalog(doc) -> List[Advisory]:
    doc = as_dict(doc, t("KEV catalog", "catalogo KEV"))
    return [_parse_one(v) for v in as_list(doc.get("vulnerabilities"), "vulnerabilities")]


def sync(fetcher: Fetcher, store: Store, now: datetime) -> SyncStats:
    stats = SyncStats("kev")
    doc = as_dict(fetcher.get_json(KEV_URL, max_bytes=_MAX_BYTES), t("KEV catalog", "catalogo KEV"))
    stats.fetched = 1
    for v in as_list(doc.get("vulnerabilities"), "vulnerabilities"):
        try:
            adv = _parse_one(v)
        except ValueError as e:
            stats.errors.append(t("KEV: malformed entry (%s)", "KEV: voce malformata (%s)") % e)
            continue
        store.put_advisory(adv, iso(now))
        stats.stored += 1
        if not store.has_advisory("cverecord", adv.id):
            store.queue("cverecord", adv.id)
    return stats
