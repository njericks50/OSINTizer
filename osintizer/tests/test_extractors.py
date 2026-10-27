import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

import samples as S  # noqa: E402
from osintizer.extractors import detect_type, extract, guess_tool  # noqa: E402
from osintizer.store import Store  # noqa: E402

SCOPE = ["acme-corp.com"]


def values(findings, category, scoped_only=False):
    return {f["value"] for f in findings if f["category"] == category and (f["in_scope"] or not scoped_only)}


class TheHarvester(unittest.TestCase):
    def setUp(self):
        self.f = extract(S.THEHARVESTER, "theharvester", "acme-corp.com", SCOPE)

    def test_emails_grouped(self):
        self.assertEqual(values(self.f, "emails"), {"jane.doe@acme-corp.com", "mliu@acme-corp.com", "info@acme-corp.com"})

    def test_banner_ignored(self):
        self.assertNotIn("cmartorella@edge-security.com", values(self.f, "emails"))
        self.assertFalse(any("edge-security" in v for v in values(self.f, "domains")))

    def test_users_from_emails_skip_role_accounts(self):
        users = values(self.f, "users")
        self.assertIn("jane.doe", users)
        self.assertIn("mliu", users)
        self.assertNotIn("info", users)

    def test_people(self):
        self.assertEqual(values(self.f, "people"), {"Jane Doe", "Mark Liu"})

    def test_hosts(self):
        self.assertEqual(values(self.f, "domains", True), {"acme-corp.com"})
        self.assertTrue({"mail.acme-corp.com", "vpn.acme-corp.com", "dev.acme-corp.com", "www.acme-corp.com"}
                        <= values(self.f, "subdomains"))

    def test_ips_and_files(self):
        self.assertTrue({"104.18.22.10", "10.20.1.5"} <= values(self.f, "ips"))
        self.assertIn("https://docs.acme-corp.com/files/2024-annual-report.pdf", values(self.f, "files"))
        self.assertIn("ASN: AS13335", values(self.f, "registration"))


class DnsAndWhois(unittest.TestCase):
    def test_dig(self):
        f = extract(S.DIG, "dig", "acme-corp.com", SCOPE)
        dns = values(f, "dns")
        self.assertIn("MX 1 aspmx.l.google.com", dns)
        self.assertIn("NS ns1.cloudflare.com", dns)
        tech = values(f, "technologies")
        self.assertTrue({"Google Workspace (email)", "SendGrid", "Cloudflare DNS", "Atlassian"} <= tech)
        self.assertIn("104.18.22.10", values(f, "ips"))

    def test_whois(self):
        f = extract(S.WHOIS, "whois", "acme-corp.com", SCOPE)
        reg = values(f, "registration")
        self.assertIn("Registrar: NameCheap, Inc.", reg)
        self.assertIn("Registrant Org: Acme Corporation", reg)
        self.assertIn("Registrant Name: (redacted / privacy protected)", reg)
        self.assertIn("Created: 2012-03-02T15:00:00Z", reg)
        self.assertNotIn("verisign.com", values(f, "domains"))
        self.assertIn("abuse@namecheap.com", values(f, "emails"))
        self.assertFalse(values(f, "people"))


class Identity(unittest.TestCase):
    def test_sherlock(self):
        f = extract(S.SHERLOCK, "sherlock", "jdoe_sec", [])
        self.assertEqual(len(values(f, "accounts")), 3)
        self.assertIn("jdoe_sec", values(f, "users"))

    def test_holehe(self):
        f = extract(S.HOLEHE, "holehe", "jane.doe@acme-corp.com", SCOPE)
        acc = values(f, "accounts")
        self.assertEqual(len(acc), 3)
        self.assertNotIn("Email", " ".join(acc))

    def test_social_urls_become_accounts(self):
        f = extract("see https://twitter.com/acme_sec and https://www.linkedin.com/in/jane-doe-123/", "paste")
        self.assertEqual(len(values(f, "accounts")), 2)
        self.assertTrue({"acme_sec", "jane-doe-123"} <= values(f, "users"))


class InfraTools(unittest.TestCase):
    def test_nmap(self):
        f = extract(S.NMAP, "nmap", "acme-corp.com", SCOPE)
        svc = values(f, "services")
        self.assertIn("acme-corp.com 8443/tcp https-alt — nginx 1.24.0", svc)
        self.assertEqual(len(svc), 3)

    def test_whatweb(self):
        f = extract(S.WHATWEB, "whatweb", "acme-corp.com", SCOPE)
        tech = values(f, "technologies")
        self.assertTrue({"WordPress 6.5.2", "JQuery 3.6.0", "PHP/8.2.1"} <= tech)
        self.assertIn("press@acme-corp.com", values(f, "emails"))

    def test_subfinder_wildcards(self):
        f = extract(S.SUBFINDER, "subfinder", "acme-corp.com", SCOPE)
        self.assertEqual(values(f, "subdomains"),
                         {"api.acme-corp.com", "staging.acme-corp.com", "cdn.acme-corp.com", "shop.acme-corp.com"})


class Noise(unittest.TestCase):
    def test_filenames_and_versions_are_not_findings(self):
        f = extract("saved to results.json and run.py, version 1.2.3.4.5, logo@2x.png, see config.sh", "paste")
        self.assertFalse(values(f, "domains") | values(f, "subdomains"))
        self.assertFalse(values(f, "emails"))

    def test_scope(self):
        f = extract("www.acme-corp.com google.com", "paste", "", SCOPE)
        oos = {x["value"] for x in f if not x["in_scope"]}
        self.assertEqual(oos, {"google.com"})

    def test_guess_tool(self):
        self.assertEqual(guess_tool(S.NMAP), "nmap")
        self.assertEqual(guess_tool(S.THEHARVESTER), "theharvester")
        self.assertEqual(guess_tool(S.DIG), "dig")
        self.assertEqual(guess_tool(S.WHOIS), "whois")
        self.assertEqual(guess_tool(S.HOLEHE), "holehe")

    def test_detect_type(self):
        self.assertEqual(detect_type("acme.com"), "domain")
        self.assertEqual(detect_type("a@acme.com"), "email")
        self.assertEqual(detect_type("8.8.8.8"), "ip")
        self.assertEqual(detect_type("10.0.0.0/24"), "cidr")
        self.assertEqual(detect_type("https://acme.com/x"), "url")
        self.assertEqual(detect_type("jdoe_sec"), "username")


class StoreFlow(unittest.TestCase):
    def test_dedupe_across_runs(self):
        with tempfile.TemporaryDirectory() as d:
            st = Store(os.path.join(d, "t.db"))
            case = st.create_case("Acme", "acme-corp.com")
            r1 = st.create_run(case["id"], "theharvester")
            new1, _ = st.add_findings(case["id"], r1, extract(S.THEHARVESTER, "theharvester", "acme-corp.com", SCOPE))
            r2 = st.create_run(case["id"], "subfinder")
            new2, seen2 = st.add_findings(case["id"], r2, extract(S.THEHARVESTER, "theharvester", "acme-corp.com", SCOPE))
            self.assertGreater(new1, 10)
            self.assertEqual(new2, 0)
            self.assertEqual(seen2, new1)
            f = [x for x in st.list_findings(case["id"]) if x["value"] == "jane.doe@acme-corp.com"][0]
            self.assertEqual(f["sources"], ["subfinder", "theharvester"])
            self.assertEqual(f["hits"], 2)
            # export / import round-trip
            copy = st.import_case(st.export_case(case["id"]))
            self.assertEqual(len(st.list_findings(copy["id"])), len(st.list_findings(case["id"])))


if __name__ == "__main__":
    unittest.main()
