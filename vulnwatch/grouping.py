"""Findings grouped by inventory item: one audit, one apply and one report block per item."""
from functools import cmp_to_key
from typing import Dict, List, Sequence, Tuple

from .model import Finding
from .versions import VersionError, compare, scheme_for


def item_key(f: Finding) -> Tuple[str, str, str]:
    return f.item.kind, f.item.name, f.item.location


def group_by_item(findings: Sequence[Finding]) -> List[List[Finding]]:
    groups: Dict[Tuple[str, str, str], List[Finding]] = {}
    for f in findings:
        groups.setdefault(item_key(f), []).append(f)
    return list(groups.values())


def representative(findings: Sequence[Finding]) -> Finding:
    """The finding with the highest fixed version: upgrading to it fixes every other one too."""
    pool = [f for f in findings if f.fixed_version] or list(findings)
    scheme = scheme_for(pool[0].item.kind, pool[0].item.ecosystem)

    def cmp(a: Finding, b: Finding) -> int:
        if not a.fixed_version or not b.fixed_version:
            return 0
        try:
            return compare(a.fixed_version, b.fixed_version, scheme)
        except VersionError:
            return 0

    return max(pool, key=cmp_to_key(cmp))
