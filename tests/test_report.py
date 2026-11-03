import dataclasses
import json
import os
import subprocess
import tempfile
import unittest

from tests.helpers import NOW
from vulnwatch.i18n import set_language
from vulnwatch.model import AuditResult, Check, Finding, InventoryItem, finding_id
from vulnwatch.proc import FakeRunner
from vulnwatch.report import _NOTIFY_RE, RunSummary, notification_text, notify, render_markdown, summary_prefix, write_report

NPM = InventoryItem("npm_global", "pnpm", "9.0.0", "npm", "npm_global", "/p")
RT = InventoryItem("runtime", "node", "22.0.0", None, None, "/x/node", display_name="Node di un'app agente")


def f(item=NPM, lane="manual", match="exact", title="t", published="2026-11-01", cid="CVE-2026-1"):
    return Finding(finding_id(cid, item.kind, item.name, item.location), cid, item, match, True, False,
                   lane == "malicious", "osv", "9.1.0", title, published, lane, ())


def summary(findings, **kw):
    base = dict(date="2026-11-03", findings=findings, audits={}, applied=[], shadow=[], errors=[],
                sources_ok={"kev": True, "cvenow": True, "cverecord": True, "osv": True}, auto_enabled=False)
    base.update(kw)
    return RunSummary(**base)


class MarkdownTest(unittest.TestCase):
    def setUp(self):
        set_language("it")

    def tearDown(self):
        set_language("en")

    def test_untrusted_title_neutralized(self):
        md = render_markdown(summary([f(title="\x1b[2J evil ‮ [click](http://evil.example)")]), NOW)
        self.assertNotIn("\x1b", md)
        self.assertNotIn("‮", md)
        self.assertNotIn("](http", md.replace("`[click](http://evil.example)`", ""))
        self.assertIn("[testo non fidato]", md)

    def test_no_data_banner(self):
        s = summary([], sources_ok={"kev": False, "cvenow": False, "cverecord": False, "osv": False})
        self.assertIn("NESSUN DATO", render_markdown(s, NOW))
        self.assertEqual(notification_text(s), "NESSUN DATO")

    def test_shadow_section(self):
        x = f(lane="auto")
        md = render_markdown(summary([x], shadow=[x.id]), NOW)
        shadow_part = md.split("## Avrei applicato (modalità ombra)")[1].split("\n## ")[0]
        self.assertIn(x.id, shadow_part)

    def test_apply_command_only_when_possible(self):
        md_rt = render_markdown(summary([f(item=RT)]), NOW)
        self.assertNotIn("vulnwatch apply", md_rt)
        self.assertIn("/x/node", md_rt)
        x = f()
        self.assertIn("vulnwatch apply %s" % x.id, render_markdown(summary([x]), NOW))

    def test_malicious_first(self):
        md = render_markdown(summary([f(lane="malicious")]), NOW)
        self.assertLess(md.index("Pacchetti malevoli"), md.index("Aspetta te"))
        self.assertIn(f(lane="malicious").id, md.split("Pacchetti malevoli")[1].split("\n## ")[0])

    def test_old_approximate_collapsed(self):
        a = dataclasses.replace(f(match="approximate", published="2026-09-01", cid="CVE-2026-2"), kev_confirmed=False)
        b = dataclasses.replace(f(match="approximate", published="2026-09-02", cid="CVE-2026-3"), kev_confirmed=False)
        c = dataclasses.replace(f(match="approximate", published="2026-11-01", cid="CVE-2026-4"), kev_confirmed=False)
        part = render_markdown(summary([a, b, c]), NOW).split("## Da verificare")[1].split("\n## ")[0]
        self.assertNotIn("CVE-2026-2", part)
        self.assertIn("CVE-2026-4", part)
        self.assertIn("2 corrispondenze", part)

    def test_audit_table(self):
        x = f()
        audit = AuditResult(x.id, "9.1.0", [Check("cooldown", "fail", "pubblicata solo 10 ore fa | x")], {})
        md = render_markdown(summary([x], audits={x.id: audit}), NOW)
        self.assertIn("| cooldown |", md)
        self.assertNotIn("10 ore fa | x", md)

    def test_ignored_with_reason(self):
        x = f(lane="ignored")
        md = render_markdown(summary([x], ignores={x.id: "non usato\x1b[31m"}), NOW)
        self.assertIn("non usato", md.split("## Ignorate")[1])
        self.assertNotIn("\x1b", md)

    def test_source_failure_listed(self):
        md = render_markdown(summary([], sources_ok={"kev": True, "osv": False}, errors=["osv: rete giù"]), NOW)
        part = md.split("## Errori e fonti")[1]
        self.assertIn("osv", part)
        self.assertIn("rete giù", part)


class GroupingTest(unittest.TestCase):
    def setUp(self):
        set_language("it")

    def tearDown(self):
        set_language("en")

    def test_one_block_per_item(self):
        a = dataclasses.replace(f(cid="CVE-2026-1"), fixed_version="9.0.5")
        b = dataclasses.replace(f(cid="CVE-2026-2"), fixed_version="9.1.0")
        c = dataclasses.replace(f(cid="CVE-2026-3"), fixed_version="9.0.1")
        part = render_markdown(summary([a, b, c]), NOW).split("## Aspetta te")[1].split("\n## ")[0]
        self.assertEqual(part.count("\n### "), 1)
        self.assertIn("3 vulnerabilità", part)
        for x in (a, b, c):
            self.assertIn(x.canonical_id, part)
        self.assertIn("vulnwatch apply %s" % b.id, part)
        self.assertIn("Versione corretta: 9.1.0", part)

    def test_long_lists_are_capped(self):
        many = [f(cid="CVE-2026-%d" % (1000 + i)) for i in range(45)]
        part = render_markdown(summary(many), NOW).split("## Aspetta te")[1]
        self.assertIn("e altre 15", part)

    def test_notification_counts_items(self):
        self.assertEqual(notification_text(summary([f(cid="CVE-2026-1"), f(cid="CVE-2026-2")])),
                         "1 da approvare · 0 applicate · 0 malevoli")


class ReviewFixesTest(unittest.TestCase):
    def setUp(self):
        set_language("it")

    def tearDown(self):
        set_language("en")

    def test_kev_approximate_never_collapsed(self):
        k = f(match="approximate", published="2025-01-01", cid="CVE-2025-1111")
        md = render_markdown(summary([k]), NOW)
        self.assertIn("CVE-2025-1111", md.split("## Da verificare")[1].split("\n## ")[0])
        self.assertEqual(notification_text(summary([k])), "0 da approvare · 0 applicate · 0 malevoli · 1 KEV da verificare")

    def test_hostile_id_and_name_rendered_inert(self):
        x = f(cid="CVE-2026-1](https://evil.example/x)",
              item=InventoryItem("lockfile_pkg", "[x](https://evil.example/y)", "1.0", "npm", None, "/p/package-lock.json"))
        md = render_markdown(summary([x]), NOW)
        self.assertNotIn("](https://evil", md)
        self.assertNotIn("](hxxp", md.replace("`", ""))

    def test_apply_problems_raise_alarm(self):
        rec = {"finding_id": "x", "item": {"kind": "npm_global", "name": "pnpm"}, "status": "applied_with_problems",
               "problems": ["venv rotto: /x"], "before": {"version": "9.0.0"}, "after": {"version": "9.1.0"},
               "checks": [{"name": "cooldown", "status": "pass", "detail": ""}]}
        s = summary([], applied=[rec])
        self.assertEqual(notification_text(s), "ATTENZIONE: 1 applicazioni con problemi · 0 da approvare · 0 applicate · 0 malevoli")
        part = render_markdown(s, NOW).split("## Applicato automaticamente")[1].split("\n## ")[0]
        self.assertIn("9.0.0", part)
        self.assertIn("9.1.0", part)
        self.assertIn("venv rotto", part)


class FilesTest(unittest.TestCase):
    def setUp(self):
        set_language("it")

    def tearDown(self):
        set_language("en")

    def test_write_report(self):
        d = tempfile.mkdtemp()
        x = f()
        md, js = write_report(summary([x]), os.path.join(d, "reports"), NOW)
        self.assertTrue(md.endswith("2026-11-03.md"))
        with open(js) as fh:
            data = json.load(fh)
        self.assertEqual([y["id"] for y in data["findings"]], [x.id])


class NotifyTest(unittest.TestCase):
    def setUp(self):
        set_language("it")

    def tearDown(self):
        set_language("en")

    def test_counts_only(self):
        x = f(title="segreto nel titolo")
        text = notification_text(summary([x, f(lane="malicious", cid="CVE-2026-9")]))
        self.assertNotIn("segreto", text)
        self.assertEqual(text, "1 da approvare · 0 applicate · 1 malevoli")

    def test_notify_runs_osascript(self):
        run = FakeRunner({})
        notify("1 da approvare · 0 applicate · 0 malevoli", run)
        argv = run.calls[0][0]
        self.assertEqual(argv[:2], ["/usr/bin/osascript", "-e"])
        self.assertIn("display notification", argv[2])

    def test_notify_rejects_quotes(self):
        with self.assertRaises(ValueError):
            notify('x"y', FakeRunner({}))


class EnglishReportTest(unittest.TestCase):
    def test_report_english_default(self):
        md = render_markdown(summary([f()]), NOW)
        self.assertIn("## Waiting for you", md)
        self.assertIn("\nSummary per item:", md)
        self.assertIn("[untrusted text]", md)
        self.assertNotIn("Aspetta te", md)

    def test_report_italian(self):
        set_language("it")
        try:
            md = render_markdown(summary([f()]), NOW)
        finally:
            set_language("en")
        self.assertIn("## Aspetta te", md)
        self.assertIn("\nRiepilogo per elemento:", md)

    def test_summary_prefix_follows_language(self):
        self.assertEqual(summary_prefix(), "Summary per item:")
        set_language("it")
        try:
            self.assertEqual(summary_prefix(), "Riepilogo per elemento:")
        finally:
            set_language("en")

    def test_notification_english(self):
        x = f()
        self.assertEqual(notification_text(summary([x])), "1 waiting for you · 0 applied · 0 malicious")

    def test_notifications_match_regex_in_both_languages(self):
        s = summary([f()], applied=[{"status": "rolled_back", "item": {}}])
        for lang in ("en", "it"):
            set_language(lang)
            try:
                self.assertTrue(_NOTIFY_RE.match(notification_text(s)), notification_text(s))
                self.assertTrue(_NOTIFY_RE.match(notification_text(summary([], sources_ok={"kev": False}))))
            finally:
                set_language("en")


if __name__ == "__main__":
    unittest.main()
