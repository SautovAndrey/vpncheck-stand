"""Конфиги xray, которые строит стенд (ссылки, JSON-подписки, цепочки dialerProxy): поля, которые xray 26
принимает, и проверка самим xray (`xray run -test`), если он есть на этом компьютере - путь в VPNCHECK_XRAY_EXE
или xray в PATH; без него эта часть пропускается."""
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from stand import core, dcprobe, subscription, xray  # noqa: E402

UUID = "11111111-2222-3333-4444-555555555555"
PBK = "2u2wXJWCsTvtH_xKLDoqNe2m0nPwY79s8SqCn7Qj8Ag"
PCS = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
LINKS = [
    "vless://%s@a.example.com:443?security=tls&type=ws&path=%%2Fws&host=h.example.com&allowInsecure=1"
    "&pcs=%s&vcn=b.example.com#ws" % (UUID, PCS),
    "vless://%s@b.example.com:443?security=tls&type=grpc&serviceName=svc&authority=g.example.com&mode=multi#grpc"
    % UUID,
    "vless://%s@c.example.com:443?security=tls&type=httpupgrade&path=%%2Fup&host=u.example.com#hu" % UUID,
    "vless://%s@d.example.com:443?security=reality&type=xhttp&path=%%2Fx&mode=auto&sni=a.com&pbk=%s&sid=ab"
    "&extra=%%7B%%22xPaddingBytes%%22%%3A%%22100-1000%%22%%7D#xhttp" % (UUID, PBK),
    "vless://%s@e.example.com:443?security=reality&type=tcp&flow=xtls-rprx-vision&sni=a.com&pbk=%s&sid=ab#r"
    % (UUID, PBK),
]
REALITY = {"network": "tcp", "security": "reality",
           "realitySettings": {"serverName": "a.com", "publicKey": PBK, "shortId": "ab", "fingerprint": "chrome"}}
FRAGMENT = {"tag": "fragment", "protocol": "freedom",
            "settings": {"fragment": {"packets": "tlshello", "length": "100-200", "interval": "10-20"}}}


def json_sub(*outbounds):
    return json.dumps([{"remarks": "DE", "outbounds": list(outbounds)}])


def vless(address, stream, **extra):
    server = {"address": address, "port": 443, "users": [{"id": UUID, "encryption": "none"}]}
    outbound = {"tag": "proxy", "protocol": "vless", "streamSettings": stream, "settings": {"vnext": [server]}}
    outbound.update(extra)
    return outbound


def xray_exe():
    path = os.environ.get("VPNCHECK_XRAY_EXE") or shutil.which("xray") or shutil.which("xray.exe")
    return path if path and os.path.exists(path) else None


class LinkFieldsTest(unittest.TestCase):
    def nodes(self):
        return subscription.parse_any("\n".join(LINKS))

    def test_no_allow_insecure_pinned_certificate_instead(self):
        tls = self.nodes()[0]["outbound"]["streamSettings"]["tlsSettings"]
        self.assertNotIn("allowInsecure", tls)
        self.assertEqual((tls["pinnedPeerCertSha256"], tls["verifyPeerCertByName"]), (PCS, "b.example.com"))

    def test_transports(self):
        streams = {node["address"]: node["outbound"]["streamSettings"] for node in self.nodes()}
        self.assertEqual(streams["a.example.com"]["wsSettings"], {"path": "/ws", "host": "h.example.com"})
        self.assertEqual(streams["b.example.com"]["grpcSettings"],
                         {"serviceName": "svc", "authority": "g.example.com", "multiMode": True})
        self.assertEqual(streams["c.example.com"]["httpupgradeSettings"], {"path": "/up", "host": "u.example.com"})
        self.assertEqual(streams["d.example.com"]["xhttpSettings"]["extra"], {"xPaddingBytes": "100-1000"})

    def test_json_subscription_drops_allow_insecure(self):
        stream = {"network": "tcp", "security": "tls", "tlsSettings": {"serverName": "a.com", "allowInsecure": True}}
        node = subscription.parse_any(json_sub(vless("a.com", stream)))[0]
        self.assertNotIn("allowInsecure", node["outbound"]["streamSettings"]["tlsSettings"])

    def test_flat_vless_form(self):
        flat = {"tag": "proxy", "protocol": "vless", "streamSettings": REALITY,
                "settings": {"address": "1.2.3.4", "port": 443, "id": UUID, "encryption": "none"}}
        nodes = subscription.parse_any(json_sub(flat))
        self.assertEqual([node["key"] for node in nodes], ["1.2.3.4:443"])
        self.assertEqual(nodes[0]["outbound"]["settings"]["id"], UUID)

    def test_dialer_proxy_chain_travels_with_node(self):
        stream = dict(REALITY, sockopt={"dialerProxy": "fragment"})
        node = subscription.parse_any(json_sub(vless("1.2.3.4", stream), FRAGMENT))[0]
        self.assertEqual(node["extra_outbounds"], [FRAGMENT])
        config = xray.socks_config(10810, node["outbound"], node["extra_outbounds"])
        self.assertEqual([item.get("tag") for item in config["outbounds"]], ["proxy", "fragment", "direct"])

    def test_broken_chain_is_reported_not_checked(self):
        stream = dict(REALITY, sockopt={"dialerProxy": "missing"})
        raw = json_sub(vless("1.2.3.4", stream))
        self.assertEqual(subscription.parse_any(raw), [])
        self.assertEqual([item["protocol"] for item in subscription.unsupported(raw)], ["vless+dialerProxy"])
        blackhole = {"tag": "hole", "protocol": "blackhole"}
        raw = json_sub(vless("1.2.3.4", dict(REALITY, sockopt={"dialerProxy": "hole"})), blackhole)
        self.assertEqual(subscription.parse_any(raw), [])

    def test_other_protocols_listed_as_unsupported(self):
        vmess = "vmess://" + base64.b64encode(json.dumps({"add": "v.example.com", "port": "443",
                                                           "ps": "VM"}).encode()).decode()
        text = "\n".join([vmess, "trojan://pw@t.example.com:443?security=tls#TR", "ss://YWVz@s.example.com:8388#SS",
                          LINKS[4]])
        skipped = subscription.unsupported(text)
        self.assertEqual([(item["protocol"], item["address"], item["location"]) for item in skipped],
                         [("vmess", "v.example.com", "VM"), ("trojan", "t.example.com", "TR"),
                          ("ss", "s.example.com", "SS")])
        trojan = {"tag": "proxy", "protocol": "trojan", "settings": {"servers": [{"address": "t", "port": 443}]}}
        self.assertEqual([item["protocol"] for item in subscription.unsupported(json_sub(trojan))], ["trojan"])

    def test_core_keeps_extra_tag_rules_like_server(self):
        self.assertFalse(core.extra_allowed({"tag": "vc-direct", "protocol": "freedom"}))
        redirect = {"tag": "x", "protocol": "freedom", "settings": {"redirect": "1.1.1.1:53"}}
        self.assertFalse(core.extra_allowed(redirect))
        self.assertTrue(core.extra_allowed(FRAGMENT))


class XrayAcceptsConfigsTest(unittest.TestCase):
    def configs(self):
        nodes = subscription.parse_any("\n".join(LINKS))
        stream = dict(REALITY, sockopt={"dialerProxy": "fragment"})
        nodes += subscription.parse_any(json_sub(vless("1.2.3.4", stream), FRAGMENT))
        insecure = {"network": "tcp", "security": "tls", "tlsSettings": {"serverName": "a.com", "allowInsecure": True}}
        nodes += subscription.parse_any(json_sub(vless("5.6.7.8", insecure)))
        configs = [(node["key"], xray.socks_config(10810, node["outbound"], node.get("extra_outbounds")))
                   for node in nodes]
        configs.append(("direct", xray.socks_config(10800)))
        return configs

    def test_xray_test_passes(self):
        exe = xray_exe()
        if not exe:
            self.skipTest("xray not found (VPNCHECK_XRAY_EXE or PATH)")
        folder = tempfile.mkdtemp(prefix="vpncheck-test-")
        self.addCleanup(shutil.rmtree, folder, True)
        for key, config in self.configs():
            path = os.path.join(folder, "cfg.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(config, handle)
            out = subprocess.run([exe, "run", "-test", "-c", path], capture_output=True, text=True, timeout=60)
            self.assertEqual(out.returncode, 0, "%s: %s" % (key, (out.stdout + out.stderr)[-600:]))


class ProbeTransportTest(unittest.TestCase):
    def test_targets_go_through_stdin_not_arguments(self):
        calls = []

        def fake_run(_client, command, timeout=180, data=None):
            calls.append((command, data))
            if command.startswith("cat /tmp/vpncheck_out_"):
                return "VPNCHECK_RESULT {}", "", 0
            return "", "", 0

        stream = dict(REALITY, sockopt={"dialerProxy": "fragment"})
        node = subscription.parse_any(json_sub(vless("1.2.3.4", stream), FRAGMENT))[0]
        targets = [dict(node, key="n%03d" % i) for i in range(300)]
        with mock.patch.object(dcprobe, "connect", return_value=mock.Mock()), \
                mock.patch.object(dcprobe, "ensure_xray", return_value="/x/xray"), \
                mock.patch.object(dcprobe, "run", side_effect=fake_run), \
                mock.patch.object(dcprobe.time, "sleep"):
            dcprobe.probe({"host": "h"}, targets)
        self.assertTrue(all(len(command) < 4096 for command, _data in calls))
        sent = json.loads(next(data for command, data in calls if "vpncheck_targets_" in command))
        self.assertEqual(len(sent), 300)
        self.assertEqual(sent[0]["extra_outbounds"], [FRAGMENT])
        self.assertIn('target.get("extra_outbounds")', dcprobe.PROBE_SCRIPT)

    def test_run_writes_stdin(self):
        client = mock.Mock()
        stdin, stdout, stderr = mock.Mock(), mock.Mock(), mock.Mock()
        stdout.read.return_value, stderr.read.return_value = b"ok", b""
        stdout.channel.recv_exit_status.return_value = 0
        client.exec_command.return_value = (stdin, stdout, stderr)
        self.assertEqual(dcprobe.run(client, "cat", data=b"payload"), ("ok", "", 0))
        stdin.write.assert_called_once_with(b"payload")
        stdin.channel.shutdown_write.assert_called_once()

    def test_diagnose_resolves_ipv6_only_names(self):
        nodes = [{"key": "v6", "address": "::1", "port": 9, "sni": ""}]
        out = subprocess.run([sys.executable, "-c", dcprobe.DIAGNOSE_SCRIPT], input=json.dumps(nodes),
                             capture_output=True, text=True, timeout=60)
        result = json.loads(out.stdout.split(dcprobe.RESULT_MARK, 1)[1])
        self.assertEqual(result["v6"]["ip"], "::1")
        self.assertFalse(result["v6"]["tcp"].startswith("dns"))


class ExitIpTest(unittest.TestCase):
    def test_error_page_is_not_an_ip(self):
        with mock.patch.object(xray, "curl", return_value="error code: 1015") as curl:
            self.assertEqual(xray.exit_ip_via_socks(10810), "")
        self.assertIn("-f", curl.call_args[0][0])
        with mock.patch.object(xray, "curl", return_value="203.0.113.9"):
            self.assertEqual(xray.exit_ip_via_socks(10810), "203.0.113.9")
