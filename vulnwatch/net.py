"""The only way vulnwatch talks to the network: HTTPS, exact host allowlist, checked redirects, size caps."""
import json
import os
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Union
from urllib.parse import urljoin, urlsplit

from .i18n import t

CAFILE = "/etc/ssl/cert.pem"
_REDIRECTS = {301, 302, 303, 307, 308}
_MAX_HOPS = 3
_CHUNK = 1 << 20
_DOWNLOAD_DEADLINE = 1800.0


class FetchError(Exception):
    def __init__(self, msg: str, status: Optional[int] = None):
        super().__init__(msg)
        self.status = status


@dataclass
class Response:
    status: int
    headers: Dict[str, str]
    body: bytes


def read_limited(resp, max_bytes: int, deadline: float, clock: Callable[[], float] = time.monotonic) -> bytes:
    """Read a body with a size cap AND a wall-clock deadline (a server trickling bytes cannot stall the job)."""
    parts, total = [], 0
    while True:
        if clock() > deadline:
            raise FetchError(t("maximum read time exceeded", "tempo massimo di lettura superato"))
        chunk = resp.read(min(_CHUNK, max_bytes + 1 - total))
        if not chunk:
            return b"".join(parts)
        total += len(chunk)
        if total > max_bytes:
            raise FetchError(t("response over the limit of %d bytes", "risposta oltre il limite di %d byte") % max_bytes)
        parts.append(chunk)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class UrllibTransport:
    def __init__(self):
        ctx = ssl.create_default_context(cafile=CAFILE)
        self._opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), _NoRedirect)

    def _open(self, url, headers, timeout):
        req = urllib.request.Request(url, headers=headers)
        try:
            resp = self._opener.open(req, timeout=timeout)
            status = resp.status
        except urllib.error.HTTPError as e:
            resp, status = e, e.code
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise FetchError(t("network error: %s", "errore di rete: %s") % e) from e
        hdrs = {k.lower(): v for k, v in resp.headers.items()}
        return resp, status, hdrs

    @staticmethod
    def _too_big(hdrs, max_bytes):
        cl = hdrs.get("content-length")
        return cl is not None and cl.isdigit() and int(cl) > max_bytes

    def open(self, url, headers, timeout, max_bytes) -> Response:
        resp, status, hdrs = self._open(url, headers, timeout)
        try:
            if status != 200:
                return Response(status, hdrs, b"")
            if self._too_big(hdrs, max_bytes):
                raise FetchError(t("response over the limit of %d bytes", "risposta oltre il limite di %d byte") % max_bytes)
            body = read_limited(resp, max_bytes, time.monotonic() + max(4 * timeout, 120.0))
            return Response(status, hdrs, body)
        except OSError as e:
            raise FetchError(t("read error: %s", "errore di lettura: %s") % e) from e
        finally:
            resp.close()

    def download(self, url, headers, timeout, max_bytes, dest_path) -> Response:
        resp, status, hdrs = self._open(url, headers, timeout)
        try:
            if status != 200:
                return Response(status, hdrs, b"")
            if self._too_big(hdrs, max_bytes):
                raise FetchError(t("download over the limit of %d bytes", "download oltre il limite di %d byte") % max_bytes)
            total = 0
            deadline = time.monotonic() + _DOWNLOAD_DEADLINE
            try:
                with open(dest_path, "wb") as out:
                    while True:
                        if time.monotonic() > deadline:
                            raise FetchError(t("maximum download time exceeded", "tempo massimo di download superato"))
                        chunk = resp.read(_CHUNK)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > max_bytes:
                            raise FetchError(t("download over the limit of %d bytes",
                                               "download oltre il limite di %d byte") % max_bytes)
                        out.write(chunk)
            except (FetchError, OSError):
                if os.path.exists(dest_path):
                    os.remove(dest_path)
                raise
            return Response(status, hdrs, b"")
        except OSError as e:
            raise FetchError(t("download error: %s", "errore di download: %s") % e) from e
        finally:
            resp.close()


class FakeTransport:
    """Test double: routes map URL -> Response or Exception. Unknown URL -> 404."""

    def __init__(self, routes: Dict[str, Union[Response, Exception]]):
        self.routes = dict(routes)
        self.opened: List[str] = []
        self.opened_headers: List[Dict[str, str]] = []

    def _route(self, url, headers):
        self.opened.append(url)
        self.opened_headers.append(dict(headers))
        r = self.routes.get(url)
        if r is None:
            return Response(404, {}, b"")
        if isinstance(r, Exception):
            raise r
        return r

    def open(self, url, headers, timeout, max_bytes) -> Response:
        r = self._route(url, headers)
        if r.status == 200 and len(r.body) > max_bytes:
            raise FetchError(t("response over the limit of %d bytes", "risposta oltre il limite di %d byte") % max_bytes)
        return r

    def download(self, url, headers, timeout, max_bytes, dest_path) -> Response:
        r = self._route(url, headers)
        if r.status != 200:
            return Response(r.status, r.headers, b"")
        if len(r.body) > max_bytes:
            raise FetchError(t("download over the limit of %d bytes", "download oltre il limite di %d byte") % max_bytes)
        with open(dest_path, "wb") as out:
            out.write(r.body)
        return Response(200, r.headers, b"")


@dataclass
class Fetcher:
    transport: Any
    allowed_hosts: Iterable[str]
    user_agent: str = "vulnwatch/0.1"
    timeout: float = 30.0
    max_bytes: int = 50_000_000
    min_interval: float = 0.2
    sleep: Callable[[float], None] = time.sleep
    clock: Callable[[], float] = time.monotonic
    request_log: List[str] = field(default_factory=list)
    host_intervals: Optional[Dict[str, float]] = None

    def __post_init__(self):
        self.allowed_hosts = frozenset(h.lower() for h in self.allowed_hosts)
        self.host_intervals = {h.lower(): float(s) for h, s in (self.host_intervals or {}).items()}
        self._last: Dict[str, float] = {}

    def _validate(self, url: str) -> str:
        try:
            parts = urlsplit(url)
            port = parts.port
        except ValueError as e:
            raise FetchError(t("invalid URL: %s", "URL non valido: %s") % e) from e
        if parts.scheme != "https":
            raise FetchError(t("only https is allowed", "solo https è consentito"))
        if parts.username is not None or parts.password is not None:
            raise FetchError(t("credentials in the URL are not allowed", "credenziali nell'URL non consentite"))
        if port not in (None, 443):
            raise FetchError(t("port not allowed", "porta non consentita"))
        host = (parts.hostname or "").lower()
        if host not in self.allowed_hosts:
            raise FetchError(t("host not allowed: %s", "host non consentito: %s") % host)
        return host

    def _pace(self, host: str) -> None:
        last = self._last.get(host)
        now = self.clock()
        interval = self.host_intervals.get(host, self.min_interval)
        if last is not None and now - last < interval:
            self.sleep(interval - (now - last))
        self._last[host] = self.clock()

    def _request(self, url, max_bytes, headers, dest=None) -> Response:
        hops = 0
        while True:
            host = self._validate(url)
            self._pace(host)
            self.request_log.append(url)
            h = {"User-Agent": self.user_agent}
            h.update(headers or {})
            if dest is None:
                resp = self.transport.open(url, h, self.timeout, max_bytes)
            else:
                resp = self.transport.download(url, h, self.timeout, max_bytes, dest)
            if resp.status in _REDIRECTS:
                loc = resp.headers.get("location")
                if not loc:
                    raise FetchError(t("redirect without a destination", "redirect senza destinazione"), resp.status)
                hops += 1
                if hops > _MAX_HOPS:
                    raise FetchError(t("too many redirects", "troppi redirect"), resp.status)
                url = urljoin(url, loc)
                continue
            if resp.status != 200:
                raise FetchError(t("HTTP status %d", "stato HTTP %d") % resp.status, resp.status)
            return resp

    def get(self, url: str, max_bytes: Optional[int] = None, headers: Optional[Dict[str, str]] = None) -> bytes:
        return self._request(url, max_bytes or self.max_bytes, headers).body

    def get_json(self, url: str, max_bytes: Optional[int] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        body = self.get(url, max_bytes, headers)
        try:
            return json.loads(body)
        except ValueError as e:
            raise FetchError(t("invalid JSON from %s", "JSON non valido da %s") % url) from e

    def download(self, url: str, dest_path: str, max_bytes: int) -> int:
        self._request(url, max_bytes, None, dest=dest_path)
        return os.path.getsize(dest_path)
