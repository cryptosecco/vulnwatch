"""Version comparison for three schemes and range evaluation. Unparseable input raises VersionError."""
import re
from typing import List, Optional, Sequence, Tuple

from .i18n import t
from .model import VersionRange


class VersionError(ValueError):
    pass


_EMPTY_BOUND = (None, "", "0", "*")
_EMPTY_UPPER = (None, "", "*")


# ---------------------------------------------------------------- generic

def _generic_tokens(v: str) -> list:
    s = v.strip()
    if s[:1] in ("v", "V"):
        s = s[1:]
    toks = re.findall(r"\d+|[A-Za-z]+", s)
    if not toks:
        raise VersionError(t("unreadable version: %r", "versione illeggibile: %r") % v)
    return [int(tok) if tok.isdigit() else tok.lower() for tok in toks]


def _generic_cmp(a: str, b: str) -> int:
    ta, tb = _generic_tokens(a), _generic_tokens(b)
    for i in range(max(len(ta), len(tb))):
        if i >= len(ta):
            return -1 if isinstance(tb[i], int) else 1
        if i >= len(tb):
            return 1 if isinstance(ta[i], int) else -1
        x, y = ta[i], tb[i]
        if isinstance(x, int) != isinstance(y, int):
            return 1 if isinstance(x, int) else -1
        if x != y:
            return 1 if x > y else -1
    return 0


# ---------------------------------------------------------------- semver

_SEMVER = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")


def _semver(v: str) -> Tuple[int, int, int, Optional[Tuple[str, ...]]]:
    m = _SEMVER.match(v.strip())
    if not m:
        raise VersionError(t("unreadable semver: %r", "semver illeggibile: %r") % v)
    pre = tuple(m.group(4).split(".")) if m.group(4) else None
    return int(m.group(1)), int(m.group(2)), int(m.group(3)), pre


def _pre_cmp(a: Optional[Tuple[str, ...]], b: Optional[Tuple[str, ...]]) -> int:
    if a == b:
        return 0
    if a is None:
        return 1
    if b is None:
        return -1
    for x, y in zip(a, b):
        if x == y:
            continue
        xn, yn = x.isdigit(), y.isdigit()
        if xn and yn:
            return 1 if int(x) > int(y) else -1
        if xn != yn:
            return -1 if xn else 1
        return 1 if x > y else -1
    return (len(a) > len(b)) - (len(a) < len(b))


def _semver_key_cmp(a, b) -> int:
    if a[:3] != b[:3]:
        return 1 if a[:3] > b[:3] else -1
    return _pre_cmp(a[3], b[3])


# ---------------------------------------------------------------- pep440

_PEP440 = re.compile(
    r"^\s*v?(?:(\d+)!)?(\d+(?:\.\d+)*)"
    r"(?:[-_.]?(a|alpha|b|beta|rc|c|pre|preview)[-_.]?(\d*))?"
    r"(?:(?:-(\d+))|(?:[-_.]?(post|rev|r)[-_.]?(\d*)))?"
    r"(?:[-_.]?(dev)[-_.]?(\d*))?"
    r"(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?\s*$",
    re.IGNORECASE,
)
_PRE_RANK = {"a": 1, "alpha": 1, "b": 2, "beta": 2, "rc": 3, "c": 3, "pre": 3, "preview": 3}


def _pep440_key(v: str):
    m = _PEP440.match(v)
    if not m:
        raise VersionError(t("unreadable PEP 440 version: %r", "versione PEP 440 illeggibile: %r") % v)
    epoch = int(m.group(1) or 0)
    release = [int(x) for x in m.group(2).split(".")]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    pre = (_PRE_RANK[m.group(3).lower()], int(m.group(4) or 0)) if m.group(3) else None
    post = None
    if m.group(5):
        post = int(m.group(5))
    elif m.group(6):
        post = int(m.group(7) or 0)
    dev = int(m.group(9) or 0) if m.group(8) else None
    if pre is None and post is None and dev is not None:
        pre_key = (-1, 0)
    elif pre is None:
        pre_key = (9, 0)
    else:
        pre_key = pre
    post_key = -1 if post is None else post
    dev_key = float("inf") if dev is None else dev
    return (epoch, tuple(release), pre_key, post_key, dev_key)


# ---------------------------------------------------------------- public API

def compare(a: str, b: str, scheme: str) -> int:
    if not isinstance(a, str) or not isinstance(b, str):
        raise VersionError(t("version is not text", "versione non testuale"))
    if scheme == "generic":
        return _generic_cmp(a, b)
    if scheme == "semver":
        return _semver_key_cmp(_semver(a), _semver(b))
    if scheme == "pep440":
        ka, kb = _pep440_key(a), _pep440_key(b)
        return (ka > kb) - (ka < kb)
    raise VersionError(t("unknown scheme: %r", "schema sconosciuto: %r") % scheme)


def major(v: str, scheme: str) -> int:
    if scheme == "semver":
        return _semver(v)[0]
    if scheme == "pep440":
        return _pep440_key(v)[1][0]
    first = _generic_tokens(v)[0]
    if not isinstance(first, int):
        raise VersionError(t("version without a leading number: %r", "versione senza numero iniziale: %r") % v)
    return first


def scheme_for(kind: str, ecosystem: Optional[str]) -> str:
    if ecosystem == "npm":
        return "semver"
    if ecosystem == "PyPI":
        return "pep440"
    return "generic"


class _Incomparable(VersionError):
    """A range bound uses another numbering (e.g. 'Security Update 2020-001' vs '27.0.1')."""


def _year_like(v: str) -> bool:
    first = _generic_tokens(v)[0]
    return isinstance(first, int) and first >= 1900


def _check_comparable(v: str, r: VersionRange, scheme: str) -> None:
    if scheme != "generic":
        return
    mine = _year_like(v)
    for b in (r.introduced, r.fixed, r.last_affected):
        if b not in _EMPTY_BOUND and _year_like(b) != mine:
            raise _Incomparable(t("different numbering: %r and %r", "numerazioni diverse: %r e %r") % (v, b))


def _contains(v: str, r: VersionRange, scheme: str) -> bool:
    _check_comparable(v, r, scheme)
    if r.introduced not in _EMPTY_BOUND and compare(v, r.introduced, scheme) < 0:
        return False
    if r.fixed not in _EMPTY_UPPER and compare(v, r.fixed, scheme) >= 0:
        return False
    if r.last_affected not in _EMPTY_UPPER and compare(v, r.last_affected, scheme) > 0:
        return False
    return True


def affected_by(version: str, ranges: Sequence[VersionRange], versions: Sequence[str], scheme: str) -> Optional[bool]:
    if not ranges and not versions:
        return None
    try:
        for x in versions:
            if x == version or compare(version, x, scheme) == 0:
                return True
        decided = bool(versions)
        for r in ranges:
            try:
                if _contains(version, r, scheme):
                    return True
                decided = True
            except _Incomparable:
                continue
        return False if decided else None
    except VersionError:
        return None


def fixed_for(version: str, ranges: Sequence[VersionRange], scheme: str) -> Optional[str]:
    try:
        for r in ranges:
            try:
                if _contains(version, r, scheme):
                    return r.fixed if r.fixed not in _EMPTY_UPPER else None
            except _Incomparable:
                continue
    except VersionError:
        return None
    return None


# ---------------------------------------------------------------- npm ranges

_NPM_TOKEN = re.compile(
    r"^(<=|>=|<|>|=|\^|~>?)?v?(\*|x|X|\d+)(?:\.(\*|x|X|\d+))?(?:\.(\*|x|X|\d+))?"
    r"(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$"
)
_HYPHEN = re.compile(r"^(\S+)\s+-\s+(\S+)$")
_LOWEST = ("0",)


def _parts(token: str):
    m = _NPM_TOKEN.match(token)
    if not m:
        raise VersionError(t("unsupported npm range: %r", "intervallo npm non supportato: %r") % token)
    op = m.group(1) or ""
    nums = []
    for g in (m.group(2), m.group(3), m.group(4)):
        if g is None or g in ("*", "x", "X") or (nums and nums[-1] is None):
            nums.append(None)
        else:
            nums.append(int(g))
    pre = tuple(m.group(5).split(".")) if m.group(5) else None
    return op, nums[0], nums[1], nums[2], pre


def _comparators(token: str) -> List[Tuple[str, tuple]]:
    op, M, m, p, pre = _parts(token)
    never = [("<", (0, 0, 0, _LOWEST))]
    if op in ("", "="):
        if M is None:
            return []
        if m is None:
            return [(">=", (M, 0, 0, None)), ("<", (M + 1, 0, 0, _LOWEST))]
        if p is None:
            return [(">=", (M, m, 0, None)), ("<", (M, m + 1, 0, _LOWEST))]
        return [("=", (M, m, p, pre))]
    if op == "^":
        if M is None:
            return []
        lo = (">=", (M, m or 0, p or 0, pre))
        if M > 0 or m is None:
            return [lo, ("<", (M + 1, 0, 0, _LOWEST))]
        if m > 0 or p is None:
            return [lo, ("<", (0, m + 1, 0, _LOWEST))]
        return [lo, ("<", (0, 0, p + 1, _LOWEST))]
    if op in ("~", "~>"):
        if M is None:
            return []
        if m is None:
            return [(">=", (M, 0, 0, None)), ("<", (M + 1, 0, 0, _LOWEST))]
        return [(">=", (M, m, p or 0, pre)), ("<", (M, m + 1, 0, _LOWEST))]
    if op == ">":
        if M is None:
            return never
        if m is None:
            return [(">=", (M + 1, 0, 0, None))]
        if p is None:
            return [(">=", (M, m + 1, 0, None))]
        return [(">", (M, m, p, pre))]
    if op == ">=":
        return [] if M is None else [(">=", (M, m or 0, p or 0, pre))]
    if op == "<":
        if M is None:
            return never
        if m is None or p is None:
            return [("<", (M, m or 0, p or 0, _LOWEST))]
        return [("<", (M, m, p, pre))]
    if op == "<=":
        if M is None:
            return []
        if m is None:
            return [("<", (M + 1, 0, 0, _LOWEST))]
        if p is None:
            return [("<", (M, m + 1, 0, _LOWEST))]
        return [("<=", (M, m, p, pre))]
    raise VersionError(t("unsupported operator: %r", "operatore non supportato: %r") % op)


def _hyphen(lo: str, hi: str) -> List[Tuple[str, tuple]]:
    _, M1, m1, p1, pre1 = _parts(lo)
    _, M2, m2, p2, pre2 = _parts(hi)
    out = []
    if M1 is not None:
        out.append((">=", (M1, m1 or 0, p1 or 0, pre1)))
    if M2 is not None:
        if m2 is None:
            out.append(("<", (M2 + 1, 0, 0, _LOWEST)))
        elif p2 is None:
            out.append(("<", (M2, m2 + 1, 0, _LOWEST)))
        else:
            out.append(("<=", (M2, m2, p2, pre2)))
    return out


def _parse_set(alt: str) -> List[Tuple[str, tuple]]:
    s = alt.strip()
    if s == "":
        return []
    h = _HYPHEN.match(s)
    if h:
        return _hyphen(h.group(1), h.group(2))
    s = re.sub(r"(<=|>=|<|>|=|\^|~>?)\s+", r"\1", s)
    out = []
    for tok in s.split():
        out.extend(_comparators(tok))
    return out


def _check(v, op, ref) -> bool:
    c = _semver_key_cmp(v, ref)
    return {"=": c == 0, ">": c > 0, ">=": c >= 0, "<": c < 0, "<=": c <= 0}[op]


def npm_satisfies(version: str, expr: str) -> bool:
    v = _semver(version)
    sets = [_parse_set(alt) for alt in expr.split("||")]
    return any(all(_check(v, op, ref) for op, ref in comps) for comps in sets)
