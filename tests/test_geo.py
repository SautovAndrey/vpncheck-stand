"""Кэш хостеров: lookup_many из нескольких потоков одновременно не падает и не теряет файл."""
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from stand import geo  # noqa: E402


class GeoCacheTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="vpncheck-test-")
        patches = [mock.patch.object(geo, "CACHE_PATH", os.path.join(self.tmp, "geo_cache.json")),
                   mock.patch.object(geo, "APP_DIR", self.tmp),
                   mock.patch.object(geo, "_cache", None),
                   mock.patch.object(geo, "resolve", lambda host: "203.0.113.%d" % (hash(host) % 250)),
                   mock.patch.object(geo, "hoster", lambda ip: {"org": "Org " + ip})]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_parallel_lookup_many(self):
        errors = []

        def work(part):
            try:
                geo.lookup_many(["h%d-%d.example" % (part, i) for i in range(60)], workers=8)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=work, args=(part,)) for part in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        with open(geo.CACHE_PATH, encoding="utf-8") as handle:
            self.assertEqual(len(json.load(handle)), 240)
        self.assertEqual([name for name in os.listdir(self.tmp) if name.endswith(".tmp")], [])
        self.assertTrue(geo.cached("h0-0.example")["org"].startswith("Org "))


if __name__ == "__main__":
    unittest.main()


class GeoResolveTest(unittest.TestCase):
    def test_fake_ip_answers_are_not_node_addresses(self):
        for ip in ("198.18.0.7", "198.19.255.1", "198.20.0.5", "127.0.0.1", "100.64.1.1"):
            self.assertTrue(geo.fake(ip), ip)
        for ip in ("198.51.100.130", "203.0.113.32", "198.21.0.1"):
            self.assertFalse(geo.fake(ip), ip)

    def test_doh_is_asked_before_system_dns(self):
        with mock.patch.object(geo, "resolve_doh", return_value="203.0.113.34"), \
                mock.patch.object(geo.socket, "gethostbyname", return_value="198.20.0.9") as system:
            self.assertEqual(geo.resolve("node.example.org"), "203.0.113.34")
        system.assert_not_called()

    def test_system_dns_fake_answer_is_dropped(self):
        with mock.patch.object(geo, "resolve_doh", return_value=""), \
                mock.patch.object(geo.socket, "gethostbyname", return_value="198.20.0.9"):
            self.assertEqual(geo.resolve("node.example.org"), "")

    def test_cached_fake_ip_is_looked_up_again(self):
        tmp = tempfile.mkdtemp(prefix="vpncheck-test-")
        self.addCleanup(shutil.rmtree, tmp, True)
        with mock.patch.object(geo, "CACHE_PATH", os.path.join(tmp, "geo_cache.json")), \
                mock.patch.object(geo, "_cache", {"n.example.org": {"ip": "198.20.0.9", "org": "Charter"}}), \
                mock.patch.object(geo, "resolve", return_value="203.0.113.34"), \
                mock.patch.object(geo, "hoster", return_value={"org": "Example Hosting LLC"}):
            self.assertEqual(geo.lookup("n.example.org"), {"ip": "203.0.113.34", "org": "Example Hosting LLC"})

    def test_cached_hides_fake_ip_entries(self):
        with mock.patch.object(geo, "_cache", {"n.example.org": {"ip": "198.20.0.9", "org": "Charter"},
                                               "m.example.org": {"ip": "203.0.113.34", "org": "Example"}}):
            self.assertEqual(geo.cached("n.example.org"), {})
            self.assertEqual(geo.cached("m.example.org")["org"], "Example")


class DohBreakerTest(unittest.TestCase):
    def setUp(self):
        geo._doh_down.clear()
        self.addCleanup(geo._doh_down.clear)

    def test_both_doh_down_is_remembered_and_system_dns_used(self):
        with mock.patch.object(geo.urllib.request, "urlopen", side_effect=OSError("timed out")) as opened, \
                mock.patch.object(geo.socket, "gethostbyname", side_effect=["203.0.113.34", "198.20.0.9"]):
            self.assertEqual(geo.resolve("a.example.org"), "203.0.113.34")
            self.assertEqual(geo.resolve("b.example.org"), "")
        self.assertEqual(opened.call_count, 2)
        self.assertTrue(geo._doh_down.is_set())

    def test_doh_answer_without_address_does_not_trip_breaker(self):
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = b'{"Answer": []}'
        with mock.patch.object(geo.urllib.request, "urlopen", return_value=response), \
                mock.patch.object(geo.json, "load", return_value={"Answer": []}):
            self.assertEqual(geo.resolve_doh("a.example.org"), "")
        self.assertFalse(geo._doh_down.is_set())
