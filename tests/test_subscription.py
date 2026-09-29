"""Разбор подписок: JSON-массив (Happ), vless-ссылки, и отсев неподдерживаемых узлов (hysteria)."""
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from stand import core, subscription  # noqa: E402

JSON_SUB = json.dumps([
    {"remarks": "🇩🇪 Германия",
     "outbounds": [{"tag": "proxy", "protocol": "vless",
                    "settings": {"vnext": [{"address": "1.2.3.4", "port": 443,
                                            "users": [{"id": "u1"}]}]},
                    "streamSettings": {"network": "tcp", "security": "reality",
                                       "realitySettings": {"serverName": "de.example.com"}}}]},
    {"remarks": "🏴 Домашний",
     "outbounds": [{"tag": "proxy", "protocol": "hysteria",
                    "settings": {"address": "5.6.7.8", "port": 443, "version": 2}}]},
])


class SubscriptionExtraTest(unittest.TestCase):
    def test_parse_json_sub_takes_vless(self):
        targets = subscription.parse_any(JSON_SUB)
        keys = [t["key"] for t in targets]
        self.assertIn("1.2.3.4:443", keys)
        self.assertEqual(len(targets), 1)

    def test_unsupported_lists_hysteria(self):
        skipped = subscription.unsupported(JSON_SUB)
        self.assertEqual(len(skipped), 1)
        self.assertEqual(skipped[0]["protocol"], "hysteria")
        self.assertEqual(skipped[0]["address"], "5.6.7.8")

    def test_unsupported_ignores_links(self):
        self.assertEqual(subscription.unsupported("vless://x@1.2.3.4:443"), [])

    def test_dedupe_same_ip_different_sni(self):
        entries = [
            {"remarks": "A", "outbounds": [{"protocol": "vless", "tag": "proxy",
                "settings": {"vnext": [{"address": "9.9.9.9", "port": 443, "users": [{"id": "u"}]}]},
                "streamSettings": {"network": "tcp", "security": "reality",
                                   "realitySettings": {"serverName": "a.com"}}}]},
            {"remarks": "B", "outbounds": [{"protocol": "vless", "tag": "proxy",
                "settings": {"vnext": [{"address": "9.9.9.9", "port": 443, "users": [{"id": "u"}]}]},
                "streamSettings": {"network": "tcp", "security": "reality",
                                   "realitySettings": {"serverName": "b.com"}}}]},
        ]
        targets = subscription.parse_any(json.dumps(entries))
        self.assertEqual(len(targets), 2)
        self.assertNotEqual(targets[0]["key"], targets[1]["key"])


PANEL_ROUTING = json.dumps([{"remarks": "n", "routing": {"rules": [
    {"type": "field", "protocol": ["bittorrent"], "outboundTag": "direct"}]},
    "outbounds": [{"tag": "proxy", "protocol": "vless",
                   "settings": {"vnext": [{"address": "1.1.1.1", "port": 443, "users": [{"id": "u"}]}]},
                   "streamSettings": {"network": "tcp", "security": "reality",
                                      "realitySettings": {"serverName": "x"}}}]}])

RU_DIRECT = json.dumps([{"remarks": "n", "routing": {"rules": [
    {"type": "field", "ip": ["geoip:ru"], "outboundTag": "direct"},
    {"type": "field", "protocol": ["bittorrent"], "outboundTag": "direct"}]}, "outbounds": []}])


class RoutingSummaryTest(unittest.TestCase):
    def test_only_bittorrent_direct_means_ru_leaks(self):
        s = subscription.routing_summary(PANEL_ROUTING)
        self.assertFalse(s["ru_direct"])
        self.assertEqual(s["ru_ok"], 0)
        self.assertIn("VPN", s["verdict"])

    def test_ru_direct_detected(self):
        s = subscription.routing_summary(RU_DIRECT)
        self.assertTrue(s["ru_direct"])
        self.assertEqual(s["ru_ok"], 1)

    def test_links_have_no_routing(self):
        s = subscription.routing_summary("vless://x@1.2.3.4:443")
        self.assertFalse(s["has_routing"])

    def test_per_location_mixed(self):
        mixed = json.dumps([
            {"remarks": "🇳🇱 НЛ", "routing": {"rules": [
                {"outboundTag": "direct", "domain": ["gosuslugi.ru", "geosite:category-ru"]}]}, "outbounds": []},
            {"remarks": "🇦🇹 Австрия", "routing": {"rules": [
                {"outboundTag": "direct", "protocol": ["bittorrent"]}]}, "outbounds": []}])
        s = subscription.routing_summary(mixed)
        self.assertEqual(s["ru_ok"], 1)
        self.assertEqual(s["total"], 2)
        self.assertFalse(s["ru_direct"])
        self.assertIn("🇳🇱 НЛ", s["verdict"])
        self.assertIn("🇦🇹 Австрия", s["verdict"])


class FullConfigTest(unittest.TestCase):
    def test_full_config_for_matches_node(self):
        cfg = subscription.full_config_for(PANEL_ROUTING, "1.1.1.1", 443)
        self.assertIsNotNone(cfg)
        self.assertIn("routing", cfg)

    def test_full_config_for_missing_node(self):
        self.assertIsNone(subscription.full_config_for(JSON_SUB, "9.9.9.9", 443))

    def test_full_config_for_links_none(self):
        self.assertIsNone(subscription.full_config_for("vless://x@1.2.3.4:443", "1.2.3.4", 443))


class Round3SubscriptionTest(unittest.TestCase):
    def test_full_duplicates_get_numbers(self):
        nodes = [{"key": "1.1.1.1:443", "location": "DE", "sni": "a"} for _ in range(3)]
        nodes.append({"key": "2.2.2.2:443", "location": "US", "sni": "b"})
        keys = [node["key"] for node in subscription.dedupe_keys(nodes)]
        self.assertEqual(len(set(keys)), 4)
        self.assertEqual(keys[3], "2.2.2.2:443")

    def test_full_config_parsed_once_and_copied(self):
        subscription._full_config_index.clear()
        with mock.patch.object(subscription.json, "loads", wraps=subscription.json.loads) as loads:
            first = subscription.full_config_for(PANEL_ROUTING, "1.1.1.1", 443)
            second = subscription.full_config_for(PANEL_ROUTING, "1.1.1.1", 443)
        self.assertEqual(loads.call_count, 1)
        first["mutated"] = True
        self.assertNotIn("mutated", second)
        self.assertNotIn("mutated", subscription.full_config_for(PANEL_ROUTING, "1.1.1.1", 443))


if __name__ == "__main__":
    unittest.main()


def chain_entry(main_links, *extras):
    main = {"tag": "proxy", "protocol": "vless",
            "settings": {"vnext": [{"address": "1.2.3.4", "port": 443, "users": [{"id": "u1"}]}]},
            "streamSettings": dict({"network": "tcp", "security": "none"}, **main_links)}
    return [{"remarks": "DE", "outbounds": [main] + list(extras)}]


def hop(tag, address, **extra):
    return dict({"tag": tag, "protocol": "vless",
                 "settings": {"vnext": [{"address": address, "port": 443, "users": [{"id": "u2"}]}]}}, **extra)


class Round5SubscriptionTest(unittest.TestCase):
    def test_chain_link_is_not_a_node_of_its_own(self):
        nodes = subscription.parse_any(json.dumps(chain_entry({"sockopt": {"dialerProxy": "hop"}},
                                                              hop("hop", "5.6.7.8"))))
        self.assertEqual([node["key"] for node in nodes], ["1.2.3.4:443"])
        self.assertEqual([item["tag"] for item in nodes[0]["extra_outbounds"]], ["hop"])

    def test_rings_and_self_links_are_skipped_not_checked(self):
        rings = [chain_entry({"sockopt": {"dialerProxy": "proxy"}}),
                 chain_entry({"sockopt": {"dialerProxy": "hop"}},
                             hop("hop", "5.6.7.8", proxySettings={"tag": "proxy"})),
                 chain_entry({"sockopt": {"dialerProxy": "a"}}, hop("a", "5.6.7.8", proxySettings={"tag": "b"}),
                             hop("b", "6.7.8.9", proxySettings={"tag": "a"}))]
        for sub in rings:
            self.assertEqual(subscription.parse_any(json.dumps(sub)), [], sub)
            skipped = subscription.unsupported(json.dumps(sub))
            self.assertEqual([item["protocol"] for item in skipped], ["vless+dialerProxy"], sub)

    def test_vless_link_with_slash_before_query(self):
        link = "vless://u1@de.example.com:443/?type=tcp&security=reality&sni=a.com&pbk=k#DE"
        nodes = subscription.parse_any(link)
        self.assertEqual([node["key"] for node in nodes], ["de.example.com:443"])

    def test_broken_vless_link_reported_as_unsupported(self):
        skipped = subscription.unsupported("vless://no-port-here#Broken\nvless://u1@a.example:443#Fine")
        self.assertEqual([(item["protocol"], item["location"]) for item in skipped], [("vless", "Broken")])

    def test_non_object_entries_do_not_break_summaries(self):
        raw = json.dumps([1, "x", None, {"remarks": "DE", "outbounds": [2, {"tag": "proxy", "protocol": "hysteria",
                                                                            "settings": {"address": "a", "port": 1}}],
                                         "routing": {"rules": [3, {"outboundTag": "direct", "domain": "geosite:ru"}]}}])
        self.assertEqual(subscription.routing_summary(raw)["ru_ok"], 1)
        self.assertEqual([item["protocol"] for item in subscription.unsupported(raw)], ["hysteria"])
        self.assertEqual(subscription.parse_any(raw), [])


class Round7SubscriptionTest(unittest.TestCase):
    def outbound(self, address="203.0.113.10", **stream):
        return {"tag": "proxy", "protocol": "vless",
                "settings": {"vnext": [{"address": address, "port": 443, "users": [{"id": "u"}]}]},
                "streamSettings": dict({"network": "tcp"}, **stream)}

    def test_skipped_nodes_say_why(self):
        loop = self.outbound(Sockopt={"dialerProxy": "proxy"})
        local = self.outbound("127.0.0.1")
        raw = json.dumps([{"remarks": "A", "outbounds": [loop]}, {"remarks": "B", "outbounds": [local]}])
        skipped = subscription.unsupported(raw)
        self.assertEqual([item["protocol"] for item in skipped],
                         ["vless (неоднозначные ключи настроек)", "vless (адрес не из интернета)"])
        self.assertEqual(subscription.parse_any(raw), [])

    def test_duplicate_keys_in_subscription_skip_the_node(self):
        good = json.dumps([{"remarks": "A", "outbounds": [self.outbound()]}])
        twice = good.replace('"address": "203.0.113.10"', '"address": "203.0.113.10", "address": "127.0.0.1"')
        self.assertEqual(len(subscription.parse_any(good)), 1)
        self.assertEqual(subscription.parse_any(twice), [])
        self.assertEqual([item["location"] for item in subscription.unsupported(twice)], ["A"])

    def test_hysteria2_and_ech_server_not_checked(self):
        ech = self.outbound(security="tls", tlsSettings={"serverName": "a.com", "echConfigList": "udp://10.0.0.1"})
        raw = json.dumps([{"remarks": "E", "outbounds": [ech]}])
        self.assertEqual(subscription.parse_any(raw), [])
        self.assertEqual(core.node_refusal({"outbound": dict(self.outbound(), protocol="hysteria2")}), "unsupported")
