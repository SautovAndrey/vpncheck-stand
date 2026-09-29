"""Ссылка подключения агента по QR: её формат должен совпадать с разбором в Pairing.kt."""
import os
import sys
import unittest
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from stand.ui.pairing import pairing_link  # noqa: E402


class PairingLinkTest(unittest.TestCase):
    def test_server_and_key(self):
        key = "ab" * 32
        link = pairing_link("http://203.0.113.10:8787/", key)
        parsed = urllib.parse.urlparse(link)
        self.assertEqual((parsed.scheme, parsed.netloc), ("vpncheck", "pair"))
        query = urllib.parse.parse_qs(parsed.query)
        self.assertEqual(query["server"], ["http://203.0.113.10:8787"])
        self.assertEqual(query["key"], [key])

    def test_without_key(self):
        query = urllib.parse.parse_qs(urllib.parse.urlparse(pairing_link("https://a.example", "")).query)
        self.assertNotIn("key", query)
        self.assertNotIn("tp", query)
        self.assertNotIn("pin", query)

    def test_tls_port_and_pin_go_together_with_ti(self):
        pin = "sha256/ab+/" + "C" * 39 + "="
        tls = {"port": 8788, "pin": pin}
        manifest = {"issued": 1790671953, "tls": {"port": 8788, "pin": pin}, "signature": "s"}
        link = pairing_link("http://203.0.113.10:8787", "ab" * 32, tls, manifest)
        self.assertIn("tp=8788&pin=sha256%2Fab%2B%2F", link)
        query = urllib.parse.parse_qs(urllib.parse.urlparse(link).query)
        self.assertEqual(query["tp"], ["8788"])
        self.assertEqual(query["pin"], [pin])
        self.assertEqual(query["ti"], ["1790671953"])
        self.assertEqual(query["server"], ["http://203.0.113.10:8787"])
        for broken in ({"port": 8788, "pin": ""}, {"port": 0, "pin": pin}, None):
            query = self.query(pairing_link("http://203.0.113.10:8787", "", broken, manifest))
            self.assertNotIn("tp", query)
            self.assertNotIn("pin", query)
            self.assertEqual(query["ti"], ["1790671953"])

    def test_pin_is_left_out_without_ti_or_when_the_manifest_disagrees(self):
        pin = "sha256/" + "C" * 43 + "="
        tls = {"port": 8788, "pin": pin}
        cases = (None, {}, {"issued": 0, "tls": dict(tls)}, {"issued": True, "tls": dict(tls)},
                 {"issued": "5", "tls": dict(tls)})
        for manifest in cases:
            query = self.query(pairing_link("http://203.0.113.10:8787", "", tls, manifest))
            self.assertNotIn("tp", query)
            self.assertNotIn("pin", query)
            self.assertNotIn("ti", query)
        for other in (None, {"port": 8789, "pin": pin}, {"port": 8788, "pin": "sha256/" + "D" * 43 + "="}):
            query = self.query(pairing_link("http://203.0.113.10:8787", "", tls, {"issued": 9, "tls": other}))
            self.assertNotIn("tp", query)
            self.assertNotIn("pin", query)
            self.assertEqual(query["ti"], ["9"])

    @staticmethod
    def query(link):
        return urllib.parse.parse_qs(urllib.parse.urlparse(link).query)


if __name__ == "__main__":
    unittest.main()
