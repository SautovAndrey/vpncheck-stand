"""Манифест обновлений: ядро по воздуху больше не выкладывается, старый core из манифеста убирается."""
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from stand import agentapi  # noqa: E402


class ManifestTest(unittest.TestCase):
    def test_core_dropped_app_kept(self):
        server = agentapi.AgentServer("https://example.invalid", "token")
        old = {"core": {"version": "1"}, "app": {"version_code": 5}, "signature": "x"}
        sent = {}
        with mock.patch.object(server, "state", return_value={"manifest": old}), \
                mock.patch.object(server, "set_state", side_effect=lambda **patch: sent.update(patch)), \
                mock.patch.object(agentapi, "sign_manifest", side_effect=lambda m: dict(m, signature="s")):
            signed = server.publish_manifest(app={"version_code": 6})
        self.assertNotIn("core", signed)
        self.assertEqual(signed["app"], {"version_code": 6})
        self.assertEqual(sent["manifest"], signed)
        with self.assertRaises(TypeError):
            server.publish_manifest(core={"version": "2"})


PIN = "sha256/" + "A" * 43 + "="


class TlsManifestTest(unittest.TestCase):
    def publish(self, server, old, **kwargs):
        sent = {}
        with mock.patch.object(server, "state", return_value={"manifest": old}), \
                mock.patch.object(server, "set_state", side_effect=lambda **patch: sent.update(patch)):
            return server.publish_manifest(**kwargs)

    def test_tls_comes_from_the_stand_and_is_signed(self):
        from cryptography.hazmat.primitives.asymmetric import ed25519
        key = ed25519.Ed25519PrivateKey.generate()
        folder = tempfile.mkdtemp(prefix="vpncheck-key-")
        self.addCleanup(shutil.rmtree, folder, True)
        path = os.path.join(folder, "manifest.key")
        with open(path, "wb") as handle:
            handle.write(key.private_bytes_raw())
        old = {"app": {"version_code": 5}, "tls": {"port": 1, "pin": "sha256/evil"}, "signature": "x"}
        with mock.patch.object(agentapi, "KEY_PATH", path):
            pinned = agentapi.AgentServer("http://203.0.113.10:8787", "t", tls={"port": 8788, "pin": PIN})
            signed = self.publish(pinned, old)
            plain = self.publish(agentapi.AgentServer("http://203.0.113.10:8787", "t"), {"app": {"version_code": 5}})
            off = self.publish(pinned, old, disable_tls=True)
        self.assertEqual(signed["tls"], {"port": 8788, "pin": PIN})
        self.assertIsInstance(signed["tls"]["port"], int)
        self.assertIn('"tls":{"pin":"%s","port":8788}' % PIN, agentapi.canonical(signed))
        key.public_key().verify(bytes.fromhex(signed["signature"]), agentapi.canonical(signed).encode())
        self.assertNotIn("tls", plain)
        self.assertEqual(plain["app"], {"version_code": 5})
        self.assertIn("tls", off)
        self.assertIsNone(off["tls"])
        self.assertIn('"tls":null', agentapi.canonical(off))
        key.public_key().verify(bytes.fromhex(off["signature"]), agentapi.canonical(off).encode())

    def test_stand_without_tls_refuses_to_drop_it_from_the_server_manifest(self):
        plain = agentapi.AgentServer("http://203.0.113.10:8787", "t")
        sent = {}
        old = {"app": {"version_code": 5}, "tls": {"port": 8788, "pin": PIN}, "issued": 5, "signature": "x"}
        with mock.patch.object(plain, "state", return_value={"manifest": old}), \
                mock.patch.object(plain, "set_state", side_effect=lambda **patch: sent.update(patch)), \
                mock.patch.object(agentapi, "sign_manifest", side_effect=lambda m: dict(m, signature="s")):
            with self.assertRaises(RuntimeError) as caught:
                plain.publish_manifest(app={"version_code": 6})
            self.assertEqual(sent, {})
            self.assertIn("--disable-tls", str(caught.exception))
            kept = plain.publish_manifest(app={"version_code": 6}, disable_tls=True)
            self.assertIsNone(kept["tls"])
            old["tls"] = None
            again = plain.publish_manifest(app={"version_code": 7})
        self.assertIn("tls", again)
        self.assertIsNone(again["tls"])

    def test_pinned_client_goes_to_the_tls_port(self):
        server = agentapi.AgentServer("http://[2001:db8::1]:8787/", "t", tls={"port": 8788, "pin": PIN})
        self.assertEqual(server.base, "https://[2001:db8::1]:8788")
        self.assertEqual(agentapi.AgentServer("http://h:8787", "t").base, "http://h:8787")

    def test_spki_pin_same_for_pem_and_der(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from test_server_run import make_cert, openssl_pin
        folder = tempfile.mkdtemp(prefix="vpncheck-cert-")
        self.addCleanup(shutil.rmtree, folder, True)
        cert_path, _key = make_cert(folder)
        with open(cert_path, "rb") as handle:
            pem = handle.read()
        der = x509.load_pem_x509_certificate(pem).public_bytes(serialization.Encoding.DER)
        pin = agentapi.spki_pin(pem)
        self.assertEqual(pin, agentapi.spki_pin(der))
        self.assertEqual(pin, agentapi.spki_pin(pem.decode()))
        self.assertRegex(pin, agentapi.PIN_RE)
        expected = openssl_pin(cert_path)
        if expected:
            self.assertEqual(pin, expected)


class NonFiniteTest(unittest.TestCase):
    def test_nan_not_sent(self):
        server = agentapi.AgentServer("https://example.invalid", "token")
        with mock.patch.object(agentapi.safehttp, "urlopen") as urlopen, self.assertRaises(ValueError):
            server.set_state(nodes=[{"key": "k", "outbound": {"settings": {"level": float("inf")}}}])
        urlopen.assert_not_called()


class TrendsTest(unittest.TestCase):
    def test_trends_paged_with_total(self):
        server = agentapi.AgentServer("https://example.invalid", "token")
        asked = []
        answers = [{"nodes": [{"node": "a"}], "total": 7}, {"nodes": [{"node": "a"}]}]
        with mock.patch.object(server, "_request", side_effect=lambda method, path: asked.append(path)
                               or answers.pop(0)):
            self.assertEqual(server.trends(limit=1, offset=3), ([{"node": "a"}], 7))
            self.assertEqual(server.trends(scope="R · Op"), ([{"node": "a"}], None))
        self.assertIn("limit=1&offset=3", asked[0])
        self.assertIn("scope=R", asked[1])


class AgentConfigTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="vpncheck-test-")
        self.path = os.path.join(self.tmp, "agent.json")
        self.patch = mock.patch.object(agentapi, "AGENT_CONFIG", self.path)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_saved_atomically_private_and_keeps_other_fields(self):
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump({"yandex_key": "k"}, handle)
        agentapi.save_agent_config("https://s", "tok")
        self.assertEqual(agentapi.load_agent_config(), {"yandex_key": "k", "server": "https://s", "token": "tok"})
        if os.name == "posix":
            self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)
        self.assertEqual([name for name in os.listdir(self.tmp)], ["agent.json"])

    def test_tls_saved_and_used_only_for_the_same_http_host(self):
        agentapi.save_agent_config("http://203.0.113.10:8787", "tok")
        agentapi.save_tls("203.0.113.10", 8788, PIN)
        cfg = agentapi.load_agent_config()
        self.assertEqual((cfg["tls_host"], cfg["tls_port"], cfg["tls_pin"]), ("203.0.113.10", 8788, PIN))
        self.assertEqual(agentapi.tls_for("http://203.0.113.10:8787"), {"port": 8788, "pin": PIN})
        self.assertEqual(agentapi.connect_from_config().base, "https://203.0.113.10:8788")
        for other in ("http://198.51.100.1:8787", "https://203.0.113.10", "", "http://[bad"):
            self.assertIsNone(agentapi.tls_for(other), other)
        self.assertEqual(agentapi.server_for("http://198.51.100.1:8787", "tok").base, "http://198.51.100.1:8787")
        agentapi.save_agent_config("http://203.0.113.10:8787", "tok2")
        self.assertEqual(agentapi.load_agent_config()["tls_pin"], PIN)
        for bad in ({"tls_port": "8788"}, {"tls_port": True}, {"tls_port": 70000}, {"tls_pin": "sha256/x"}):
            cfg = dict(agentapi.load_agent_config(), **bad)
            self.assertIsNone(agentapi.tls_for("http://203.0.113.10:8787", cfg), bad)
        agentapi.save_tls()
        self.assertFalse(any(key in agentapi.load_agent_config() for key in agentapi.TLS_KEYS))

    def test_broken_file_gives_defaults(self):
        for content in ("{oops", "[1, 2]", ""):
            with open(self.path, "w", encoding="utf-8") as handle:
                handle.write(content)
            self.assertEqual(agentapi.load_agent_config(), {"server": "", "token": ""}, content)


class GzipAnswerTest(unittest.TestCase):
    def test_admin_answer_compressed_or_plain(self):
        import gzip
        body = json.dumps({"agents": [{"agent_id": "a"}]}).encode()
        for encoding, data in (("gzip", gzip.compress(body)), ("", body)):
            response = mock.MagicMock()
            response.__enter__.return_value = response
            response.read.return_value = data
            response.headers = {"Content-Encoding": encoding}
            with mock.patch.object(agentapi.safehttp, "urlopen", return_value=response) as opened:
                self.assertEqual(agentapi.AgentServer("https://example.invalid", "t").agents(), [{"agent_id": "a"}])
            self.assertEqual(opened.call_args[0][0].get_header("Accept-encoding"), "gzip")


if __name__ == "__main__":
    unittest.main()
