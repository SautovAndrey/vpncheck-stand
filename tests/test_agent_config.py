"""Конфиг xray агента: зеркало XrayRunner.buildConfig (agent/…/XrayRunner.kt) на Python и проверка самим xray
(`xray run -test`) для всех веток - прямая проверка с закреплённым DNS (dns.hosts), узел с sendThrough и
связанными outbound'ами (dialerProxy, proxySettings), правило блокировки частных сетей. Списки частных сетей и
правило цепочек сверяются с кодом агента - расхождение Kotlin и зеркала ловится здесь.
xray: путь в VPNCHECK_XRAY_EXE или xray в PATH; без него проверка самим xray пропускается."""
import copy
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "server"))

import app as srv  # noqa: E402
from stand import core  # noqa: E402

AGENT_SRC = os.path.join(ROOT, "agent", "app", "src", "main", "java", "ru", "vpncheck", "agent")
BLOCK_TAG, DIRECT_TAG = "vc-block", "vc-direct"
PRIVATE_V4 = ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
              "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/3"]
PRIVATE_V6 = ["::/128", "::1/128", "64:ff9b:1::/48", "fc00::/7", "fe80::/10", "ff00::/8"]
UUID = "11111111-2222-3333-4444-555555555555"


def private_cidrs():
    """Как XrayRunner.PRIVATE_CIDRS: каждая частная IPv4-сеть ещё и в NAT64 (64:ff9b::/96) и 6to4 (2002::/16)."""
    out = []
    for cidr in PRIVATE_V4:
        ip, bits = cidr.split("/")
        octets = [int(part) for part in ip.split(".")]
        hexed = "%x:%x" % (octets[0] * 256 + octets[1], octets[2] * 256 + octets[3])
        out += [cidr, "64:ff9b::%s/%d" % (hexed, 96 + int(bits)), "2002:%s::/%d" % (hexed, 16 + int(bits))]
    return out + PRIVATE_V6


def dial_sockopts(outbound):
    """Зеркало NodeRules.dialSockopts: sockopt, с которого телефон набирает сам (свой streamSettings, если outbound
    ни через что не ходит, и каналы загрузки)."""
    targets = [] if srv.linked_tags(outbound) else [outbound.setdefault("streamSettings", {})]
    targets += srv.download_settings(outbound)
    return [target.setdefault("sockopt", {}) for target in targets]


def pin_dialing(outbound):
    """Зеркало NodeRules.pinDialing."""
    if str(outbound.get("protocol")).lower() == "freedom" and isinstance(outbound.get("settings"), dict):
        outbound["settings"]["domainStrategy"] = "AsIs"
    for sockopt in dial_sockopts(outbound):
        sockopt["domainStrategy"] = "ForceIP"
        if not isinstance(sockopt.get("happyEyeballs"), dict):
            sockopt["happyEyeballs"] = {"tryDelayMs": 250}


def bind_device(outbound, device):
    """Зеркало NodeRules.bindDevice: sockopt.interface - сеть, которую проверяем (0.12.5); mark и customSockopt
    узла снимаются (0.12.6)."""
    for sockopt in dial_sockopts(outbound):
        for key in [key for key in sockopt if srv.fold_key(key) in ("interface", "mark", "customsockopt")]:
            del sockopt[key]
        sockopt["interface"] = device


def build(node, port, send_through, loglevel, hosts=None, device=None):
    """Зеркало XrayRunner.buildConfig (send_through и device - XrayRunner.Via)."""
    config = {"log": {"loglevel": loglevel},
              "inbounds": [{"port": port, "listen": "127.0.0.1", "protocol": "socks",
                            "settings": {"udp": False, "auth": "password",
                                         "accounts": [{"user": "a1234567", "pass": "p" * 32}]}}]}
    if hosts:
        config["dns"] = {"hosts": {"full:" + host: ips for host, ips in hosts.items()}}
    outbounds = []
    main = node.get("outbound") if node else None
    if main is not None:
        for outbound in [main] + list(node.get("extra_outbounds") or []):
            item = copy.deepcopy(outbound)
            if send_through is not None:
                item["sendThrough"] = send_through
            if hosts:
                pin_dialing(item)
            if device is not None:
                bind_device(item, device)
            outbounds.append(item)
    freedom = {"protocol": "freedom", "tag": DIRECT_TAG, "settings": {"domainStrategy": "UseIP"}}
    if send_through is not None:
        freedom["sendThrough"] = send_through
    if device is not None:
        bind_device(freedom, device)
    config["outbounds"] = outbounds + [freedom, {"protocol": "blackhole", "tag": BLOCK_TAG}]
    config["routing"] = {"domainStrategy": "IPOnDemand" if main is None else "AsIs",
                         "rules": [{"type": "field", "ip": private_cidrs(), "outboundTag": BLOCK_TAG}]}
    return config


REALITY = {"tag": "proxy", "protocol": "vless",
           "settings": {"vnext": [{"address": "1.2.3.4", "port": 443,
                                   "users": [{"id": UUID, "encryption": "none", "flow": "xtls-rprx-vision"}]}]},
           "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
               "serverName": "a.com", "publicKey": "2u2wXJWCsTvtH_xKLDoqNe2m0nPwY79s8SqCn7Qj8Ag", "shortId": "ab",
               "fingerprint": "chrome"}}}
FRAG = {"tag": "fragment", "protocol": "freedom",
        "settings": {"fragment": {"packets": "tlshello", "length": "100-200", "interval": "10-20"}},
        "streamSettings": {"sockopt": {"TcpNoDelay": True}}}
HOP = {"tag": "hop", "protocol": "vless",
       "settings": {"vnext": [{"address": "5.6.7.8", "port": 443, "users": [{"id": UUID, "encryption": "none"}]}]},
       "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {"serverName": "b.com"}}}
NOTAG_MAIN = {key: value for key, value in REALITY.items() if key != "tag"}


def with_link(outbound, tag, via="dialer"):
    item = copy.deepcopy(outbound)
    if via == "dialer":
        item.setdefault("streamSettings", {}).setdefault("sockopt", {})["dialerProxy"] = tag
    else:
        item["proxySettings"] = {"tag": tag}
    return item


HOSTS_V4 = {"api.ipify.org": ["104.26.12.205", "172.67.74.152"], "www.google.com": ["142.250.74.4"]}
HOSTS_V6 = {"api.ipify.org": ["2606:4700::6812:1b3"], "www.google.com": ["2a00:1450:4010:c02::67", "142.250.74.4"]}
PINNED_NODE = {"a.com": ["203.0.113.5"], "dl.example.com": ["198.51.100.20"]}
XHTTP_DL = dict(REALITY, streamSettings={"network": "xhttp", "security": "none", "xhttpSettings": {
    "path": "/x", "extra": {"downloadSettings": {"address": "dl.example.com", "port": 443, "network": "xhttp",
                                                 "xhttpSettings": {"path": "/d"}}}}})
INTERFACE_UPPER = dict(REALITY, streamSettings=dict(REALITY["streamSettings"], sockopt={"Interface": "eth9"}))
DIALER = {"key": "k", "outbound": with_link(REALITY, "fragment"), "extra_outbounds": [FRAG]}
PROXIED = {"key": "k", "outbound": with_link(REALITY, "hop", via="proxy"), "extra_outbounds": [HOP]}
CASES = {
    "direct_v4": (None, "10.1.1.1", "warning", None),
    "direct_no_send_through": (None, None, "warning", None),
    "direct_hosts_v4": (None, "10.1.1.1", "warning", HOSTS_V4),
    "direct_hosts_v6": (None, None, "warning", HOSTS_V6),
    "node_plain": ({"key": "k", "outbound": REALITY}, "10.1.1.1", "warning", None),
    "node_plain_no_send_through": ({"key": "k", "outbound": REALITY}, None, "warning", None),
    "node_no_tag": ({"key": "k", "outbound": NOTAG_MAIN}, "10.1.1.1", "warning", None),
    "node_dialer": (DIALER, "10.1.1.1", "warning", None),
    "node_dialer_no_send_through": (DIALER, None, "warning", None),
    "node_dialer_no_main_tag": ({"key": "k", "outbound": with_link(NOTAG_MAIN, "fragment"), "extra_outbounds": [FRAG]},
                                "10.1.1.1", "warning", None),
    "node_proxy_settings": (PROXIED, "10.1.1.1", "warning", None),
    "node_proxy_settings_no_send_through": (PROXIED, None, "warning", None),
    "node_extra_null": ({"key": "k", "outbound": REALITY, "extra_outbounds": None}, "10.1.1.1", "warning", None),
    "capture_log_dialer": (DIALER, None, "debug", None),
    "capture_log_proxy_settings": (PROXIED, None, "debug", None),
    "bound_direct": (None, "10.1.1.1", "warning", HOSTS_V4, "rmnet_data0"),
    "bound_node_pinned": ({"key": "k", "outbound": REALITY}, "10.1.1.1", "warning", PINNED_NODE, "wlan0"),
    "bound_dialer_pinned": (DIALER, "10.1.1.1", "warning", PINNED_NODE, "rmnet_data0"),
    "bound_proxied_download": ({"key": "k", "outbound": with_link(XHTTP_DL, "hop", via="proxy"),
                                "extra_outbounds": [HOP]}, "10.1.1.1", "warning", PINNED_NODE, "wlan0"),
    "bound_interface_case": ({"key": "k", "outbound": INTERFACE_UPPER}, "10.1.1.1", "warning", PINNED_NODE, "wlan0"),
}
FRAG_X = dict(FRAG, tag="x")
CHAIN_CASES = {
    "ok_dialer": ({"outbound": with_link(REALITY, "fragment"), "extra_outbounds": [FRAG]}, True),
    "ok_proxy_settings": ({"outbound": with_link(REALITY, "hop", via="proxy"), "extra_outbounds": [HOP]}, True),
    "ok_two_hops": ({"outbound": with_link(REALITY, "hop", via="proxy"),
                     "extra_outbounds": [with_link(HOP, "fragment"), FRAG]}, True),
    "self_loop": ({"outbound": with_link(REALITY, "x"), "extra_outbounds": [with_link(FRAG_X, "x")]}, False),
    "x_y_x": ({"outbound": with_link(REALITY, "x"),
               "extra_outbounds": [with_link(FRAG_X, "y"), with_link(dict(FRAG, tag="y"), "x")]}, False),
    "main_to_itself": ({"outbound": with_link(REALITY, "proxy")}, False),
    "link_back_to_main": ({"outbound": with_link(REALITY, "x"), "extra_outbounds": [with_link(FRAG_X, "proxy")]},
                          False),
    "not_linked": ({"outbound": REALITY, "extra_outbounds": [FRAG]}, False),
    "extra_not_linked": ({"outbound": with_link(REALITY, "fragment"), "extra_outbounds": [FRAG, HOP]}, False),
    "link_nowhere": ({"outbound": with_link(REALITY, "nope"), "extra_outbounds": [FRAG]}, False),
}


def xray_exe():
    path = os.environ.get("VPNCHECK_XRAY_EXE") or shutil.which("xray") or shutil.which("xray.exe")
    return path if path and os.path.exists(path) else None


def kotlin(name):
    with open(os.path.join(AGENT_SRC, name), encoding="utf-8") as handle:
        return handle.read()


def kotlin_list(text, pattern):
    found = re.search(pattern, text, re.S)
    return re.findall(r'"([^"]+)"', found.group(1)) if found else None


class AgentMirrorTest(unittest.TestCase):
    def test_private_networks_match_the_agent(self):
        self.assertEqual(kotlin_list(kotlin("SiteCheck.kt"), r"PRIVATE_V4_CIDRS\s*=\s*listOf\((.*?)\)"), PRIVATE_V4)
        runner = kotlin("XrayRunner.kt")
        self.assertEqual(kotlin_list(runner, r"PRIVATE_CIDRS[^=]*=.*?\}\s*\+\s*listOf\((.*?)\)"), PRIVATE_V6)
        self.assertIn('"64:ff9b::$hex/${96 + bits.toInt()}"', runner)
        self.assertIn('"2002:$hex::/${16 + bits.toInt()}"', runner)

    def test_mirror_follows_build_config(self):
        runner = kotlin("XrayRunner.kt")
        for mark in ('put("udp", false).put("auth", "password")', 'pinned.put("full:$host"', 'copy.put("sendThrough"',
                     'put("domainStrategy", "UseIP")', 'if (main == null) "IPOnDemand" else "AsIs"',
                     '.put("ip", JSONArray(PRIVATE_CIDRS)).put("outboundTag", BLOCK_TAG)',
                     'NodeRules.pinDialing(copy)', 'NodeRules.bindDevice(copy, it)',
                     'NodeRules.bindDevice(freedom, it)'):
            self.assertIn(mark, runner)
        rules = kotlin("NodeRules.kt")
        for mark in ('sockopt.put(INTERFACE, device)', 'filter { fold(it) in AGENT_SOCKOPT }',
                     'AGENT_SOCKOPT = setOf(INTERFACE, "mark", "customsockopt")',
                     'for (sockopt in dialSockopts(outbound))', 'if (linkedTags(outbound).isEmpty())',
                     'targets.addAll(downloadsOf(outbound))'):
            self.assertIn(mark, rules)

    def test_bind_device_reaches_every_dialed_sockopt(self):
        node = build({"outbound": with_link(XHTTP_DL, "hop", via="proxy"), "extra_outbounds": [HOP]},
                     1080, "10.1.1.1", "warning", PINNED_NODE, "wlan0")
        main, hop, freedom = node["outbounds"][:3]
        self.assertNotIn("interface", main["streamSettings"].get("sockopt", {}))
        download = main["streamSettings"]["xhttpSettings"]["extra"]["downloadSettings"]
        self.assertEqual(download["sockopt"]["interface"], "wlan0")
        self.assertEqual(download["sockopt"]["domainStrategy"], "ForceIP")
        self.assertEqual(hop["streamSettings"]["sockopt"]["interface"], "wlan0")
        self.assertEqual(freedom["streamSettings"]["sockopt"], {"interface": "wlan0"})
        upper = build({"outbound": INTERFACE_UPPER}, 1080, None, "warning", None, "wlan0")["outbounds"][0]
        self.assertEqual(upper["streamSettings"]["sockopt"], {"interface": "wlan0"})

    def test_chain_rule_same_on_server_and_stand(self):
        for name, (node, good) in CHAIN_CASES.items():
            self.assertEqual(srv.valid_extra_outbounds(node.get("extra_outbounds"), node["outbound"]), good, name)
            outbounds = [node["outbound"]] + list(node.get("extra_outbounds") or [])
            extra = core.extra_outbounds(node["outbound"], outbounds)
            stand_good = extra is not None and len(extra) == len(node.get("extra_outbounds") or [])
            self.assertEqual(stand_good, good, name)

    def test_shared_cases_same_verdict_on_server_and_stand(self):
        with open(os.path.join(ROOT, "tests", "data", "chain_cases.json"), encoding="utf-8") as handle:
            cases = json.load(handle, object_pairs_hook=srv.json_pairs)
        for case in cases["duplicate_json"]:
            node = srv.json.loads(case["json"], object_pairs_hook=srv.json_pairs)
            self.assertEqual(srv.node_refusal(node) or None, case["refusal"], case["name"])
            self.assertEqual(core.node_refusal(core.loads_json(case["json"])) or None, case["refusal"], case["name"])
        for case in cases["chain"]:
            node = case["node"]
            self.assertEqual(srv.node_refusal(node) or None, case["refusal"], case["name"])
            self.assertEqual(core.node_refusal(node) or None, case["refusal"], case["name"])
            chain_good = srv.valid_extra_outbounds(node.get("extra_outbounds"), node["outbound"])
            server_good = chain_good and not srv.node_refusal(node)
            self.assertEqual(server_good, case["refusal"] is None, case["name"])
        for case in cases["addresses"]:
            address = ipaddress.ip_address(case["address"])
            self.assertEqual(srv.is_private(address), case["private"], case["address"])
            self.assertEqual(core.is_private(address), case["private"], case["address"])
        for case in cases["unchecked"]:
            self.assertEqual(srv._clean_unchecked({"results": case["results"]}), case["reasons"] or {}, case["name"])

    def test_node_fields_same_on_server_stand_and_agent(self):
        self.assertEqual(srv.NODE_FIELDS, core.NODE_FIELDS)
        with open(os.path.join(ROOT, "stand", "node_fields.json"), encoding="utf-8") as handle:
            shared = json.load(handle)
        agent = {}
        for context, body in re.findall(r'^\s*"([^"]+)" to mapOf\((.*?)\),$', kotlin("NodeFields.kt"), re.S | re.M):
            agent[context] = dict(re.findall(r'"([^"]*)" to "([^"]*)"', body))
        self.assertEqual(agent, shared)
        for fields in shared.values():
            for spec in fields.values():
                self.assertTrue(spec in ("", "*") or spec[0] == "!" or spec[1:] in shared or spec == "@settings", spec)

    def test_odd_addresses_refused_everywhere(self):
        for address in ("env:HOME", "ENV:x", "1.2.3.4\u0085", "a.com\u00a0", "\t1.2.3.4", "a\u2028b.com", "a.com\u3000",
                        "1.2.3.4\ufeff", "a.com\u007f"):
            self.assertTrue(srv.address_refused(address), repr(address))
            self.assertTrue(core.address_refused(address), repr(address))
        for address in ("1.2.3.4", "a.example.com", "[2001:db8::1]", "xn--e1afmkfd.xn--p1ai"):
            self.assertFalse(srv.address_refused(address), address)
            self.assertFalse(core.address_refused(address), address)
        self.assertIn('"env:"', kotlin("NodeRules.kt"))
        self.assertIn(r'EXTRA_SPACES = "\u1680\u2028\u2029\u202F\u205F\u3000\uFEFF"', kotlin("NodeRules.kt"))
        self.assertEqual(srv.EXTRA_SPACES, core.EXTRA_SPACES)
        self.assertEqual(core.EXTRA_SPACES, "\u1680\u2028\u2029\u202f\u205f\u3000\ufeff")

    def test_protocol_case_does_not_hide_nodes_on_the_stand(self):
        upper = dict(copy.deepcopy(REALITY), protocol="VLESS")
        frag = dict(copy.deepcopy(FRAG), protocol="Freedom")
        targets = core.parse_subscription([{"remarks": "U", "outbounds": [with_link(upper, "fragment"), frag]}])
        self.assertEqual([target["key"] for target in targets], ["1.2.3.4:443"])
        self.assertEqual(targets[0]["extra_outbounds"][0]["tag"], "fragment")
        self.assertTrue(srv.valid_extra_outbounds([frag], with_link(upper, "fragment")))

    def test_port_strategy_node_skipped_with_a_clear_label(self):
        srv_node = copy.deepcopy(REALITY)
        srv_node["streamSettings"]["sockopt"] = {"addressPortStrategy": "SrvPortOnly"}
        skipped = []
        self.assertEqual(core.parse_subscription([{"remarks": "P", "outbounds": [srv_node]}], skipped=skipped), [])
        self.assertEqual(skipped[0]["protocol"], core.t("vless (настройки, которые агент не проверяет)"))

    def test_download_settings_loop_refused_everywhere(self):
        loop = copy.deepcopy(REALITY)
        loop["streamSettings"] = {"network": "xhttp", "security": "none", "xhttpSettings": {
            "path": "/x", "extra": {"downloadSettings": {"address": "198.51.100.20", "port": 443,
                                                         "sockopt": {"dialerProxy": "proxy"}}}}}
        local = copy.deepcopy(loop)
        local["streamSettings"]["xhttpSettings"]["extra"]["downloadSettings"] = {"address": "127.0.0.1", "port": 1}
        for outbound, refusal in ((loop, "unsupported"), (local, "rejected")):
            self.assertEqual(srv.node_refusal({"outbound": outbound}), refusal)
            self.assertEqual(core.node_refusal({"outbound": outbound}), refusal)
            skipped = []
            self.assertEqual(core.parse_subscription([{"remarks": "L", "outbounds": [outbound]}], skipped=skipped), [])
            self.assertEqual(skipped[0]["protocol"], "vless+downloadSettings")

    def test_xray_accepts_every_branch(self):
        exe = xray_exe()
        if not exe:
            self.skipTest("xray not found (VPNCHECK_XRAY_EXE or PATH)")
        folder = tempfile.mkdtemp(prefix="vpncheck-test-")
        self.addCleanup(shutil.rmtree, folder, True)
        good_chains = {"chain_" + name: (dict(node, key="k"), "10.1.1.1", "warning", None)
                       for name, (node, good) in CHAIN_CASES.items() if good}
        for name, case in dict(CASES, **good_chains).items():
            path = os.path.join(folder, name + ".json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(build(case[0], 10808, *case[1:]), handle)
            out = subprocess.run([exe, "run", "-test", "-c", path], capture_output=True, text=True, timeout=60)
            self.assertEqual(out.returncode, 0, "%s: %s" % (name, (out.stdout + out.stderr)[-600:]))
