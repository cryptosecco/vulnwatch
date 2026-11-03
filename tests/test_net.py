import os
import tempfile
import unittest

from vulnwatch.net import FakeTransport, Fetcher, FetchError, Response

A = "https://cve.now/a"
B = "https://f9gkulwameaj0boi.public.blob.vercel-storage.com/b"
HOSTS = ("cve.now", "f9gkulwameaj0boi.public.blob.vercel-storage.com")


def ok(body=b"ok"):
    return Response(200, {}, body)


def redirect(to, code=302):
    return Response(code, {"location": to}, b"")


class FetcherTest(unittest.TestCase):
    def make(self, routes, **kw):
        t = FakeTransport(routes)
        kw.setdefault("sleep", lambda s: None)
        return t, Fetcher(t, HOSTS, **kw)

    def test_rejects_http(self):
        t, f = self.make({})
        with self.assertRaises(FetchError):
            f.get("http://cve.now/x")
        self.assertEqual(f.request_log, [])
        self.assertEqual(t.opened, [])

    def test_rejects_unlisted_host(self):
        t, f = self.make({})
        with self.assertRaises(FetchError):
            f.get("https://evil.example/x")
        self.assertEqual(t.opened, [])

    def test_rejects_suffix_trick(self):
        t, f = self.make({})
        with self.assertRaises(FetchError):
            f.get("https://cve.now.evil.example/")
        self.assertEqual(t.opened, [])

    def test_rejects_userinfo_trick(self):
        t, f = self.make({})
        with self.assertRaises(FetchError):
            f.get("https://cve.now@evil.example/")
        self.assertEqual(t.opened, [])

    def test_follows_redirect_to_allowed(self):
        t, f = self.make({A: redirect(B), B: ok()})
        self.assertEqual(f.get(A), b"ok")
        self.assertEqual(f.request_log, [A, B])

    def test_rejects_redirect_to_unlisted(self):
        t, f = self.make({A: redirect("https://evil.example/x")})
        with self.assertRaises(FetchError):
            f.get(A)
        self.assertEqual(f.request_log, [A])

    def test_rejects_redirect_to_http(self):
        t, f = self.make({A: redirect("http://cve.now/x")})
        with self.assertRaises(FetchError):
            f.get(A)

    def test_redirect_limit(self):
        urls = ["https://cve.now/%d" % i for i in range(6)]
        routes = {urls[i]: redirect(urls[i + 1]) for i in range(5)}
        routes[urls[5]] = ok()
        t, f = self.make(routes)
        with self.assertRaises(FetchError):
            f.get(urls[0])

    def test_non_200_raises_with_status(self):
        t, f = self.make({A: Response(403, {}, b"")})
        with self.assertRaises(FetchError) as cm:
            f.get(A)
        self.assertEqual(cm.exception.status, 403)

    def test_missing_route_is_404(self):
        t, f = self.make({})
        with self.assertRaises(FetchError) as cm:
            f.get(A)
        self.assertEqual(cm.exception.status, 404)

    def test_transport_exception_propagates_as_fetch_error(self):
        t, f = self.make({A: FetchError("rete giù")})
        with self.assertRaises(FetchError):
            f.get(A)

    def test_size_limit(self):
        t, f = self.make({A: ok(b"x" * 11)})
        with self.assertRaises(FetchError):
            f.get(A, max_bytes=10)

    def test_get_json_invalid(self):
        t, f = self.make({A: ok(b"{")})
        with self.assertRaises(FetchError):
            f.get_json(A)

    def test_get_json_ok(self):
        t, f = self.make({A: ok(b'{"a": 1}')})
        self.assertEqual(f.get_json(A), {"a": 1})

    def test_user_agent_sent(self):
        t, f = self.make({A: ok()})
        f.get(A)
        self.assertEqual(t.opened_headers[0]["User-Agent"], "vulnwatch/0.1")

    def test_min_interval_same_host(self):
        slept = []
        t, f = self.make({A: ok(), A + "2": ok()}, sleep=slept.append, clock=lambda: 100.0)
        f.get(A)
        f.get(A + "2")
        self.assertEqual(len(slept), 1)
        self.assertAlmostEqual(slept[0], 0.2)

    def test_host_interval_overrides_default(self):
        slept = []
        t, f = self.make({A: ok(), A + "2": ok(), B: ok()}, sleep=slept.append, clock=lambda: 100.0,
                         host_intervals={"cve.now": 2.0})
        f.get(A)
        f.get(A + "2")
        f.get(B)
        self.assertEqual(slept, [2.0])

    def test_download_writes_file_after_redirect(self):
        t, f = self.make({A: redirect(B), B: ok(b"zipdata")})
        dest = os.path.join(tempfile.mkdtemp(), "x.zip")
        n = f.download(A, dest, max_bytes=100)
        self.assertEqual(n, 7)
        with open(dest, "rb") as fh:
            self.assertEqual(fh.read(), b"zipdata")
        self.assertEqual(f.request_log, [A, B])

    def test_download_size_limit(self):
        t, f = self.make({A: ok(b"x" * 20)})
        dest = os.path.join(tempfile.mkdtemp(), "x.zip")
        with self.assertRaises(FetchError):
            f.download(A, dest, max_bytes=10)
        self.assertFalse(os.path.exists(dest))


class DeadlineTest(unittest.TestCase):
    def test_trickle_hits_deadline(self):
        from vulnwatch.net import read_limited

        class Slow:
            def read(self, n):
                return b"x"
        t = [0.0]

        def clock():
            t[0] += 10
            return t[0]
        with self.assertRaises(FetchError):
            read_limited(Slow(), 10 ** 6, 30.0, clock)

    def test_reads_until_eof_and_caps_size(self):
        from vulnwatch.net import read_limited

        class R:
            def __init__(self, parts):
                self.parts = list(parts)

            def read(self, n):
                return self.parts.pop(0) if self.parts else b""
        self.assertEqual(read_limited(R([b"ab", b"c"]), 100, 1e9, lambda: 0.0), b"abc")
        with self.assertRaises(FetchError):
            read_limited(R([b"x" * 11]), 10, 1e9, lambda: 0.0)


if __name__ == "__main__":
    unittest.main()
