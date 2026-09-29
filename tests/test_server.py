"""Сервер-приёмник: эндпоинты агента, админ-доступ, шина команд резервного канала, матрица.

Гоняем через FastAPI TestClient на временной БД - без реального сервера и телефона.
"""
import datetime
import io
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
import urllib.error
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "server"))

from fastapi.testclient import TestClient  # noqa: E402

import app as srv  # noqa: E402

GEO_LOOKUP = srv.geo_lookup
TELEGRAM_SEND = srv.telegram_send

ADMIN = {"X-Admin-Token": "testtoken"}
PLACE = {"region": "Москва", "city": "Москва"}
AGENT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def reset_limits():
    for table in (srv._rate, srv._report_agents, srv._report_ips, srv._write_agents, srv._write_ips,
                  srv._new_agents, srv._locate_button, srv._report_quota, srv._report_quota_new, srv._geo_new,
                  srv._report_quota_ip, srv._geo_day):
        table.clear()
    srv._matrix_cache.clear()
    srv._alert_sent.clear()
    srv._known_agents.clear()
    srv._health["ts"] = 0.0
    srv._db_size["ts"] = 0.0
    srv._geo_breaker.reset()
    srv._place_breaker.reset()
    srv._disk.update(low=False, told=0.0, alerted=0.0, full_seen=0.0, free=None)


def flush_alerts(now=None):
    """Пройти поток тревог так, будто окно склейки уже прошло."""
    return srv.flush_alert_digest((now or time.time()) + srv.ALERT_BATCH_WAIT + 1)


def season(*agent_ids):
    """Агенты, известные дольше суток: только они будят Telegram."""
    with srv.db() as conn:
        for agent_id in agent_ids:
            conn.execute("INSERT OR IGNORE INTO agents(agent_id, first_seen, last_seen) VALUES (?,?,?)",
                         (agent_id, time.time() - 2 * 86400, time.time()))


class ServerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="vpncheck-test-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        srv.DB_PATH = os.path.join(self.tmp, "agents.db")
        srv.STATE_PATH = os.path.join(self.tmp, "state.json")
        srv.FILES_DIR = os.path.join(self.tmp, "files")
        srv.BACKUP_DIR = os.path.join(self.tmp, "backups")
        srv.ADMIN_TOKEN = "testtoken"
        srv.LINK_WAIT = 0
        srv.TELEGRAM_PAUSE = 0
        srv._evicted[0] = 0.0
        srv._matrix_cache.clear()
        srv.geo_lookup = lambda ip, **_: dict(PLACE)
        srv._cmds.clear()
        srv._online.clear()
        reset_limits()
        self.client = TestClient(srv.app)
        self.client.__enter__()
        srv.update_state({"nodes": [{"key": "de:443"}, {"key": "us:443"}]})

    def tearDown(self):
        self.client.__exit__(None, None, None)

    def report(self, **extra):
        payload = {"agent_id": AGENT, "app_version": "0.7.0",
                   "results": {"de:443": {"ok": True, "latency": 200}, "us:443": {"ok": False}},
                   "network": {"type": "wifi", "operator": "TestNet"}, "device": {"model": "Pixel"}}
        payload.update(extra)
        return self.client.post("/v1/report", json=payload)

    def test_health(self):
        r = self.client.get("/health")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()["ok"])

    def test_admin_requires_token(self):
        self.assertEqual(self.client.get("/v1/admin/agents").status_code, 401)
        self.assertEqual(self.client.get("/v1/admin/agents", headers=ADMIN).status_code, 200)

    def test_report_registers_agent(self):
        self.assertEqual(self.report().status_code, 200)
        agents = self.client.get("/v1/admin/agents", headers=ADMIN).json()["agents"]
        self.assertEqual(len(agents), 1)
        self.assertEqual(agents[0]["app_version"], "0.7.0")

    def test_config_and_ping(self):
        cfg = self.client.get("/v1/config?agent_id=%s" % AGENT).json()
        self.assertIn("nodes", cfg)
        self.assertIn("interval_min", cfg)
        ping = self.client.get("/v1/ping?agent_id=%s" % AGENT).json()
        self.assertIn("run_now", ping)
        self.assertIn("update_now", ping)

    def test_manifest_endpoint_gives_only_the_signed_manifest(self):
        self.assertEqual(self.client.get("/v1/manifest").json(), {"manifest": None})
        self.put_nodes(2)
        manifest = {"issued": 7, "tls": None, "signature": "ab"}
        self.assertEqual(self.client.post("/v1/admin/state", headers=ADMIN, json={"manifest": manifest})
                         .status_code, 200)
        answer = self.client.get("/v1/manifest")
        self.assertEqual(answer.status_code, 200)
        self.assertEqual(answer.json(), {"manifest": manifest})
        self.assertNotIn("nodes", answer.text)
        self.assertEqual(len(self.client.get("/v1/config").json()["nodes"]), 2)

    def put_nodes(self, count):
        nodes = [{"key": "n%d:443" % i, "location": "L", "outbound": {"protocol": "vless"}}
                 for i in range(count)]
        self.client.post("/v1/admin/state", headers=ADMIN, json={"nodes": nodes})

    def test_incomplete_report_not_counted(self):
        self.put_nodes(14)
        answer = self.report(results={"n0:443": {"ok": False}}).json()
        self.assertEqual(answer.get("ignored"), "incomplete")
        reports = self.client.get("/v1/admin/reports?agent_id=%s" % AGENT, headers=ADMIN).json()["reports"]
        self.assertEqual(reports, [])
        agents = self.client.get("/v1/admin/agents", headers=ADMIN).json()["agents"]
        self.assertEqual([(a["agent_id"], a["alive"], a["total"]) for a in agents], [(AGENT, None, None)])

    def test_full_report_counted(self):
        self.assertNotIn("ignored", self.report().json())

    def fleet(self, alive_flags, seasoned=True, **extra):
        telegrams = []
        srv.telegram_send = lambda text: telegrams.append(text) or True
        ids = ["%08d-0000-4000-8000-000000000000" % i for i in range(len(alive_flags))]
        if seasoned:
            season(*ids)
        for i, alive in enumerate(alive_flags):
            with mock.patch.object(srv, "TRUSTED_PROXIES", {"testclient"}):
                self.client.post("/v1/report", headers={"X-Forwarded-For": "93.184.%d.10" % (100 + i)}, json=dict({
                    "agent_id": ids[i], "app_version": "0.9.1",
                    "results": {"de:443": {"ok": alive}, "us:443": {"ok": False}},
                    "network": {"type": "cellular", "operator": "Op%d" % i}, "device": {"model": "P"}}, **extra))
        flush_alerts()
        return telegrams

    def test_fleet_zero_alert_when_all_agents_zero(self):
        telegrams = self.fleet([False, False, False])
        self.assertEqual(len(telegrams), 1)
        self.assertIn("(агенты из 3 разных сетей)", telegrams[0])
        self.assertIn("Центр управления агентами", telegrams[0])
        kinds = [a["kind"] for a in self.client.get("/v1/admin/alerts", headers=ADMIN).json()["alerts"]]
        self.assertIn("fleet_zero", kinds)

    def test_no_fleet_alert_if_someone_alive_or_too_few(self):
        self.assertEqual(self.fleet([False, True, False]), [])
        self.setUp()
        self.assertEqual(self.fleet([False, False]), [])

    def test_fleet_alert_not_repeated(self):
        self.fleet([False, False, False])
        self.assertEqual(self.fleet([False, False, False]), [])

    def test_command_bus_message(self):
        self.report()
        r = self.client.post("/v1/admin/message", headers=ADMIN, json={"agent_id": AGENT, "text": "привет"})
        self.assertTrue(r.json()["ok"])
        poll = self.client.get("/v1/poll?agent_id=%s&after=1" % AGENT).json()
        actions = [(c["action"], c["text"]) for c in poll["commands"]]
        self.assertIn(("message", "привет"), actions)
        self.assertTrue(srv.online_now(AGENT))

    def test_command_targeting(self):
        self.client.post("/v1/admin/message", headers=ADMIN, json={"agent_id": AGENT, "text": "для одного"})
        other = self.client.get("/v1/poll?agent_id=ffffffff-0000-0000-0000-000000000000&after=1").json()
        self.assertEqual(other["commands"], [])

    def test_vpn_off_command(self):
        self.client.post("/v1/admin/message", headers=ADMIN, json={"agent_id": AGENT, "vpn_off": True})
        poll = self.client.get("/v1/poll?agent_id=%s&after=1" % AGENT).json()
        self.assertIn("vpn_off", [c["action"] for c in poll["commands"]])

    def test_run_now_enqueues_check(self):
        self.client.post("/v1/admin/run_now", headers=ADMIN, json={"agent_id": AGENT})
        poll = self.client.get("/v1/poll?agent_id=%s&after=1" % AGENT).json()
        self.assertIn("check", [c["action"] for c in poll["commands"]])

    def test_unknown_agent_not_marked_online(self):
        stranger = "0123456789abcdef"
        self.client.get("/v1/poll?agent_id=%s&after=0" % stranger)
        self.assertFalse(srv.online_now(stranger))
        self.assertNotIn(stranger, srv._online)

    def test_poll_skips_stale_commands(self):
        srv.enqueue_command("", "check")
        srv._cmds[-1]["ts"] = time.time() - srv.COMMAND_TTL - 1
        srv.enqueue_command("", "update")
        poll = self.client.get("/v1/poll?agent_id=%s&after=1" % AGENT).json()
        self.assertEqual([c["action"] for c in poll["commands"]], ["update"])

    def test_first_poll_gives_only_seq(self):
        srv.enqueue_command("", "check")
        poll = self.client.get("/v1/poll?agent_id=%s&after=0" % AGENT).json()
        self.assertEqual(poll["commands"], [])
        self.assertEqual(poll["seq"], srv._cmd_seq)

    def test_untrusted_reports_do_not_alert_or_count(self):
        for flags in ({"direct_ok": False}, {"same_ip_as": "wifi"}, {"route_mismatch": True}, {"vpn_active": True}):
            self.setUp()
            telegrams = []
            srv.telegram_send = lambda text, telegrams=telegrams: telegrams.append(text) or True
            season(*["%08d-0000-4000-8000-000000000000" % i for i in range(3)])
            for i in range(3):
                self.client.post("/v1/report", json=dict({
                    "agent_id": "%08d-0000-4000-8000-000000000000" % i, "results": {"de:443": {"ok": False}},
                    "network": {"type": "cellular", "operator": "Op%d" % i}, "device": {"model": "P"}}, **flags))
            flush_alerts()
            self.assertEqual(telegrams, [], flags)
            trends = self.client.get("/v1/admin/trends", headers=ADMIN).json()["nodes"]
            self.assertEqual(trends, [], flags)
            matrix = self.client.get("/v1/admin/matrix", headers=ADMIN).json()
            self.assertEqual(matrix["matrix"], {}, flags)
            reports = self.client.get("/v1/admin/reports", headers=ADMIN).json()["reports"]
            self.assertEqual(len(reports), 3, flags)
            key = next(iter(flags))
            self.assertEqual(reports[0]["payload"][key], flags[key])

    def test_partial_report_accepted_but_no_fleet_alarm(self):
        self.put_nodes(14)
        telegrams = []
        srv.telegram_send = lambda text: telegrams.append(text) or True
        ids = ["%08d-0000-4000-8000-000000000000" % i for i in range(3)]
        season(*ids)
        for i, agent_id in enumerate(ids):
            answer = self.client.post("/v1/report", json={
                "agent_id": agent_id, "partial": True,
                "results": {"n0:443": {"ok": False}, "n1:443": {"ok": True}},
                "network": {"type": "cellular", "operator": "Op%d" % i}}).json()
            self.assertNotIn("ignored", answer)
        flush_alerts()
        self.assertEqual(telegrams, [])
        reports = self.client.get("/v1/admin/reports", headers=ADMIN).json()["reports"]
        self.assertEqual([r["payload"].get("partial") for r in reports], [True] * 3)
        trends = self.client.get("/v1/admin/trends", headers=ADMIN).json()["nodes"]
        self.assertEqual({n["node"] for n in trends}, {"n1:443"})
        matrix = self.client.get("/v1/admin/matrix", headers=ADMIN).json()["matrix"]
        self.assertEqual(set(matrix), {"n1:443"})

    def test_report_via_default_keeps_place(self):
        looked = []
        srv.geo_lookup = lambda ip, **_: looked.append(ip) or {"city": "Москва", "region": "Москва", "org": "AS1 Net"}
        self.report(network={"type": "cellular", "operator": "MTS"})
        self.report(report_via="default", direct_ok=False, network={"type": "wifi"})
        agent = self.client.get("/v1/admin/agents", headers=ADMIN).json()["agents"][0]
        self.assertEqual(len(looked), 1)
        self.assertEqual(agent["city"], "Москва")
        self.assertEqual(agent["ip"], "testclient")
        reports = self.client.get("/v1/admin/reports", headers=ADMIN).json()["reports"]
        self.assertEqual(reports[0]["payload"]["report_via"], "default")
        self.assertEqual(reports[0]["operator"], "Wi-Fi")
        self.assertEqual(reports[0]["ip"], "")

    def test_old_database_gets_new_columns(self):
        import sqlite3
        srv.DB_PATH = os.path.join(self.tmp, "old.db")
        conn = sqlite3.connect(srv.DB_PATH)
        conn.execute("CREATE TABLE reports (id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id TEXT, ts REAL, ip TEXT, "
                     "region TEXT, city TEXT, operator TEXT, network TEXT, alive INTEGER, total INTEGER, payload TEXT)")
        conn.commit()
        conn.close()
        srv.init_db()
        srv.init_db()
        self.assertEqual(self.report().status_code, 200)

    def test_bad_json_is_400(self):
        headers = dict(ADMIN, **{"Content-Type": "application/json"})
        for path in ("/v1/admin/state", "/v1/admin/agents/%s/note" % AGENT):
            self.assertEqual(self.client.post(path, headers=headers, content=b"{oops").status_code, 400, path)

    def test_state_writes_are_atomic_and_not_lost(self):
        """Читатели параллельно - только на Linux, где живёт сервер: Windows запрещает подменять открытый файл."""
        import threading
        errors = []

        def writer(i):
            try:
                srv.update_state({"message": "m%d" % i})
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        def reader():
            for _ in range(200):
                try:
                    srv.load_state()
                except Exception as exc:  # noqa: BLE001
                    errors.append(exc)

        readers = 0 if os.name == "nt" else 4
        threads = [threading.Thread(target=writer, args=(i,)) for i in range(50)]
        threads += [threading.Thread(target=reader) for _ in range(readers)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.client.post("/v1/admin/state", headers=ADMIN, json={"interval_min": 60})
        self.client.post("/v1/admin/run_now", headers=ADMIN, json={})
        state = self.client.get("/v1/admin/state", headers=ADMIN).json()
        self.assertEqual(state["interval_min"], 60)
        self.assertGreater(state["run_now"], 0)
        self.assertEqual([f for f in os.listdir(self.tmp) if f.endswith(".tmp")], [])

    def test_location_round_only_finite_numbers_in_range(self):
        for good in (1, 200, 5000, 12.5):
            r = self.client.post("/v1/admin/state", headers=ADMIN, json={"location_round": good})
            self.assertEqual(r.status_code, 200, good)
            self.assertEqual(self.client.get("/v1/admin/state", headers=ADMIN).json()["location_round"], good)
        for bad in (0, -5, 5001, 10 ** 400, True, "200", None, [200]):
            r = self.client.post("/v1/admin/state", headers=ADMIN, json={"location_round": bad})
            self.assertEqual(r.status_code, 400, bad)
        for raw in (b'{"location_round": NaN}', b'{"location_round": 1e999}', b'{"location_round": -Infinity}'):
            r = self.client.post("/v1/admin/state", headers=dict(ADMIN, **{"Content-Type": "application/json"}),
                                 content=raw)
            self.assertEqual(r.status_code, 400, raw)
        self.assertEqual(srv.location_round(float("nan")), 200)
        self.assertEqual(srv.location_round(10 ** 400), 200)
        self.assertEqual(srv.location_round(50), 50)

    def test_enqueue_rejects_unknown_action(self):
        self.assertIsNone(srv.enqueue_command(AGENT, "rm-rf"))
        self.assertIsNotNone(srv.enqueue_command(AGENT, "check"))

    def test_matrix_from_report(self):
        season(AGENT)
        self.report()
        matrix = self.client.get("/v1/admin/matrix?hours=24", headers=ADMIN).json()
        self.assertIn("de:443", matrix["matrix"])
        alive, total = matrix["matrix"]["de:443"][list(matrix["columns"])[0]]
        self.assertEqual((alive, total), (1, 1))

    def test_command_with_result_roundtrip(self):
        self.report()
        r = self.client.post("/v1/admin/command", headers=ADMIN,
                             json={"agent_id": AGENT, "action": "site_check", "text": "https://example.com"})
        self.assertTrue(r.json()["ok"])
        seq = r.json()["seq"]
        poll = self.client.get("/v1/poll?agent_id=%s&after=1" % AGENT).json()
        self.assertIn(("site_check", "https://example.com"), [(c["action"], c["text"]) for c in poll["commands"]])
        r = self.client.post("/v1/result", json={"agent_id": AGENT, "action": "site_check", "seq": seq,
                                                 "result": {"url": "https://example.com", "ok": True, "code": 200}})
        self.assertEqual(r.status_code, 200)
        res = self.client.get("/v1/admin/results?agent_id=%s" % AGENT, headers=ADMIN).json()["results"]
        self.assertEqual(res[0]["action"], "site_check")
        self.assertEqual(res[0]["result"]["code"], 200)

    def test_command_rejects_bad_action_and_missing_text(self):
        r = self.client.post("/v1/admin/command", headers=ADMIN, json={"agent_id": AGENT, "action": "rm-rf"})
        self.assertEqual(r.status_code, 400)
        r = self.client.post("/v1/admin/command", headers=ADMIN, json={"agent_id": AGENT, "action": "speed"})
        self.assertEqual(r.status_code, 400)
        r = self.client.post("/v1/admin/command", headers=ADMIN, json={"agent_id": AGENT, "action": "diag"})
        self.assertEqual(r.status_code, 200)

    def test_result_rejects_unknown_action(self):
        self.report()
        r = self.client.post("/v1/result", json={"agent_id": AGENT, "action": "check", "result": {}})
        self.assertEqual(r.status_code, 400)

    def test_backup_creates_snapshot(self):
        self.report()
        srv.backup_db()
        snaps = [f for f in os.listdir(srv.BACKUP_DIR) if f.startswith("agents-")]
        self.assertTrue(snaps)

    def test_non_object_body_is_400(self):
        for path in ("/v1/result", "/v1/location", "/v1/token", "/v1/errors", "/v1/report"):
            self.assertEqual(self.client.post(path, json=[1, 2]).status_code, 400, path)

    def test_admin_page_has_csp_and_hostile_fields_stay_data(self):
        evil = "<img src=x onerror=alert(1)>"
        self.report(device={"model": evil}, network={"type": "cellular", "operator": evil})
        agents = self.client.get("/v1/admin/agents", headers=ADMIN).json()["agents"]
        self.assertEqual(agents[0]["model"], evil)
        page = self.client.get("/admin")
        self.assertEqual(page.status_code, 200)
        csp = page.headers.get("content-security-policy", "")
        directives = {}
        for part in csp.split(";"):
            name, _sep, value = part.strip().partition(" ")
            directives[name] = value
        self.assertTrue(directives["script-src"].startswith("'self'"))
        self.assertNotIn("unsafe", directives["script-src"])
        self.assertEqual(directives["default-src"], "'self'")
        self.assertIn("https://*.maps.yandex.net", directives["img-src"])
        self.assertIn("https://api-maps.yandex.ru", directives["connect-src"])
        self.assertIn("object-src 'none'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertNotIn("<script>", page.text)
        self.assertNotIn("onclick=", page.text)
        script = self.client.get("/static/admin.js").text
        self.assertIn("const esc", script)
        self.assertNotIn("${a.model", script)

    def test_report_payload_keeps_only_known_fields(self):
        self.report(push_token="secret-token", direct_ip="198.51.100.1", junk="x" * 5000,
                    errors=[{"kind": "crash", "text": "boom"}], duration_s=42,
                    network={"type": "wifi", "operator": "TestNet", "extra": "y" * 500},
                    location={"lat": 55.7, "lon": 37.6, "city": "Москва", "evil": "z"})
        reports = self.client.get("/v1/admin/reports?agent_id=%s" % AGENT, headers=ADMIN).json()["reports"]
        payload = reports[0]["payload"]
        for key in ("push_token", "direct_ip", "junk", "errors"):
            self.assertNotIn(key, payload)
        self.assertEqual(payload["duration_s"], 42)
        self.assertEqual(payload["network"]["operator"], "TestNet")
        self.assertNotIn("extra", payload["network"])
        self.assertEqual(payload["location"], {"lat": 55.7, "lon": 37.6, "city": "Москва"})
        self.assertIn("de:443", payload["results"])

    def test_old_reports_pruned(self):
        self.report()
        with srv.db() as conn:
            conn.execute("UPDATE reports SET ts=?", (0,))
        self.report()
        self.assertEqual(srv.prune_old(), 1)
        reports = self.client.get("/v1/admin/reports?agent_id=%s" % AGENT, headers=ADMIN).json()["reports"]
        self.assertEqual(len(reports), 1)

    def test_telegram_alert_escapes_agent_data(self):
        telegrams = []
        old = srv.telegram_send
        srv.telegram_send = lambda text: telegrams.append(text) or True
        try:
            srv.notify([{"node": "site:<b>x</b>", "scope": "<i>Город</i> · Op", "ok": False, "rate": 0.5,
                         "checks": 4}], "<i>Город</i> · Op")
            flush_alerts()
        finally:
            srv.telegram_send = old
        self.assertEqual(len(telegrams), 1)
        self.assertIn("&lt;i&gt;Город&lt;/i&gt;", telegrams[0])
        self.assertIn("&lt;b&gt;x&lt;/b&gt;", telegrams[0])
        self.assertTrue(telegrams[0].startswith("<b>VPNCheck</b>"))

    def test_first_poll_answers_at_once(self):
        srv.LINK_WAIT = 30
        started = time.time()
        poll = self.client.get("/v1/poll?agent_id=%s&after=0&wait=240" % AGENT).json()
        self.assertLess(time.time() - started, 5)
        self.assertEqual(poll["seq"], srv._cmd_seq)
        seq = srv.enqueue_command(AGENT, "diag")
        after = max(poll["seq"], poll["server_time"] * 1000)
        self.assertGreater(seq, after)
        srv.LINK_WAIT = 0
        again = self.client.get("/v1/poll?agent_id=%s&after=%d" % (AGENT, after)).json()
        self.assertEqual([c["action"] for c in again["commands"]], ["diag"])

    def agent_card(self):
        return self.client.get("/v1/admin/agents", headers=ADMIN).json()["agents"][0]

    def test_untrusted_and_partial_reports_keep_card_counts(self):
        self.report()
        card = self.agent_card()
        self.assertEqual((card["alive"], card["total"], card["last_trusted"], card["last_partial"]),
                         (1, 2, True, False))
        trusted_ts = card["trusted_ts"]
        self.assertTrue(trusted_ts)
        self.report(direct_ok=False, results={"de:443": {"ok": False}, "us:443": {"ok": False}})
        card = self.agent_card()
        self.assertEqual((card["alive"], card["total"], card["last_trusted"]), (1, 2, False))
        self.assertEqual(card["trusted_ts"], trusted_ts)
        self.report(partial=True, results={"de:443": {"ok": False}})
        card = self.agent_card()
        self.assertEqual((card["alive"], card["total"], card["last_trusted"], card["last_partial"]),
                         (1, 2, True, True))

    def test_core_direct_blind_report_is_untrusted_with_reasons(self):
        self.report()
        self.report(direct_ok=True, core_direct_ok=False, bind="device", partial=True, unchecked=2, rejected=2,
                    results={"de:443": {"ok": False, "unchecked": True, "error": "core-direct"},
                             "us:443": {"ok": False, "unchecked": True, "error": "vpn"}})
        card = self.agent_card()
        self.assertEqual((card["alive"], card["total"], card["last_trusted"]), (1, 2, False))
        self.assertEqual(card["doubts"], ["core-direct", "partial"])
        report = self.client.get("/v1/admin/reports", headers=ADMIN).json()["reports"][0]
        self.assertEqual(report["unchecked_nodes"], {"de:443": "core-direct", "us:443": "vpn"})
        self.assertIs(report["core_direct_ok"], False)
        self.assertEqual(report["bind"], "device")

    def test_bind_ip_is_a_doubt_but_trusted(self):
        self.report(bind="ip", core_direct_ok=True)
        card = self.agent_card()
        self.assertIs(card["last_trusted"], True)
        self.assertEqual(card["doubts"], ["bind-ip"])
        self.report(bind="<script>")
        self.assertEqual(self.agent_card()["doubts"], [])
        self.assertEqual(self.client.get("/v1/admin/reports", headers=ADMIN).json()["reports"][0]["bind"], "")

    def test_untrusted_first_report_has_no_counts(self):
        self.report(same_ip_as="wifi")
        card = self.agent_card()
        self.assertIsNone(card["alive"])
        self.assertIsNone(card["trusted_ts"])
        self.assertIs(card["last_trusted"], False)

    def test_vpn_active_report_is_marked_vpn(self):
        self.report(vpn_active=True, network={"type": "cellular", "operator": "MTS"})
        reports = self.client.get("/v1/admin/reports", headers=ADMIN).json()["reports"]
        self.assertTrue(reports[0]["operator"].startswith("VPN · "))
        self.assertTrue(reports[0]["payload"]["vpn_active"])
        self.assertEqual(self.agent_card()["network"], "vpn")
        self.assertEqual(self.client.get("/v1/admin/matrix", headers=ADMIN).json()["matrix"], {})

    def test_unchecked_count_makes_report_partial(self):
        season(AGENT)
        self.put_nodes(14)
        answer = self.report(unchecked=12, results={"n0:443": {"ok": True}, "n1:443": {"ok": False}}).json()
        self.assertNotIn("ignored", answer)
        report = self.client.get("/v1/admin/reports", headers=ADMIN).json()["reports"][0]
        self.assertTrue(report["payload"]["partial"])
        self.assertEqual(report["payload"]["unchecked"], 12)
        trends = self.client.get("/v1/admin/trends", headers=ADMIN).json()["nodes"]
        self.assertEqual({n["node"] for n in trends}, {"n0:443"})

    def test_unchecked_node_entries_are_dropped(self):
        self.report(results={"de:443": {"ok": True}, "us:443": {"ok": False, "unchecked": True}})
        card = self.agent_card()
        self.assertEqual((card["alive"], card["total"]), (1, 1))

    def test_migration_marks_old_reports_and_adds_agent_columns(self):
        import json
        import sqlite3
        srv.DB_PATH = os.path.join(self.tmp, "live.db")
        conn = sqlite3.connect(srv.DB_PATH)
        conn.executescript("""
            CREATE TABLE agents (agent_id TEXT PRIMARY KEY, first_seen REAL, last_seen REAL, app_version TEXT,
                core_version TEXT, model TEXT, android TEXT, ip TEXT, country TEXT, region TEXT, city TEXT, lat REAL,
                lon REAL, org TEXT, operator TEXT, network TEXT, alive INTEGER, total INTEGER, note TEXT DEFAULT '');
            CREATE TABLE reports (id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id TEXT, ts REAL, ip TEXT, region TEXT,
                city TEXT, operator TEXT, network TEXT, alive INTEGER, total INTEGER, payload TEXT,
                trusted INTEGER DEFAULT 1, partial INTEGER DEFAULT 0);
            CREATE TABLE errors (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, agent_id TEXT, app_version TEXT,
                model TEXT, kind TEXT, text TEXT);
        """)
        conn.execute("INSERT INTO agents(agent_id, first_seen, last_seen, alive, total) VALUES ('a', 1, ?, 3, 4)",
                     (time.time(),))
        base = time.time() - 600
        payloads = [{"direct_ok": True}, {}, {"partial": True}, {"same_ip_as": "wifi"}, {"direct_ok": False}]
        for i, payload in enumerate(payloads):
            conn.execute("INSERT INTO reports(agent_id, ts, alive, total, payload) VALUES ('a', ?, ?, 10, ?)",
                         (base + i, i, json.dumps(payload)))
        conn.execute("INSERT INTO reports(agent_id, ts, payload) VALUES ('a', ?, 'not json')", (base - 1,))
        conn.commit()
        conn.close()
        srv.init_db()
        srv.init_db()
        with srv.db() as conn:
            rows = [tuple(r) for r in conn.execute("SELECT trusted, partial FROM reports ORDER BY id").fetchall()]
            agent = dict(conn.execute("SELECT * FROM agents").fetchone())
            version = conn.execute("PRAGMA user_version").fetchone()[0]
        self.assertEqual(rows, [(1, 0), (1, 0), (1, 1), (0, 0), (0, 0), (1, 0)])
        self.assertEqual((agent["alive"], agent["total"], agent["trusted_ts"]), (1, 10, base + 1))
        self.assertEqual((agent["last_trusted"], agent["last_partial"]), (0, 0))
        self.assertIn("trusted_ts", agent)
        self.assertEqual(version, 3)
        with srv.db() as conn:
            conn.execute("UPDATE reports SET trusted=1")
        srv.init_db()
        with srv.db() as conn:
            self.assertEqual(conn.execute("SELECT MIN(trusted) FROM reports").fetchone()[0], 1)
        self.assertEqual(self.report().status_code, 200)

    def test_report_rate_limit_per_agent(self):
        codes = [self.report().status_code for _ in range(srv.REPORTS_PER_AGENT + 1)]
        self.assertEqual(codes[:-1], [200] * srv.REPORTS_PER_AGENT)
        self.assertEqual(codes[-1], 429)
        other = self.client.post("/v1/report", json={"agent_id": "bbbbbbbb-0000-0000-0000-000000000000",
                                                     "results": {"de:443": {"ok": True}}})
        self.assertEqual(other.status_code, 200)

    def test_write_rate_limit_per_ip(self):
        season(*["%08x-0000" % i for i in range(srv.WRITES_PER_IP + 1)])
        codes = [self.client.post("/v1/errors", json={"agent_id": "%08x-0000" % i, "errors": []}).status_code
                 for i in range(srv.WRITES_PER_IP + 1)]
        self.assertEqual(codes[-1], 429)
        self.assertEqual(codes.count(200), srv.WRITES_PER_IP)

    def test_errors_capped_per_agent_and_pruned(self):
        old = srv.MAX_ERRORS_PER_AGENT
        srv.MAX_ERRORS_PER_AGENT = 30
        try:
            for _ in range(3):
                self.client.post("/v1/errors", json={"agent_id": AGENT,
                                                     "errors": [{"kind": "x", "text": "t"}] * 20})
        finally:
            srv.MAX_ERRORS_PER_AGENT = old
        with srv.db() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM errors").fetchone()[0], 30)
            conn.execute("INSERT INTO alerts(ts, kind, text) VALUES (0, 'down', 'x')")
            conn.execute("INSERT INTO node_state(node, scope, ok, checks, ok_checks, changed, ts) "
                         "VALUES ('n', 's', 1, 1, 1, 0, 0)")
            conn.execute("INSERT INTO places(key, data, ts) VALUES ('k', '{}', 0)")
            conn.execute("UPDATE errors SET ts=0")
        srv.prune_old()
        with srv.db() as conn:
            for table in ("errors", "alerts", "node_state", "places"):
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM %s" % table).fetchone()[0], 0, table)

    def test_push_token_rules(self):
        self.assertFalse(self.client.post("/v1/token", json={"agent_id": AGENT, "push_token": "t1"}).json()["ok"])
        self.report(push_token="t1")
        with srv.db() as conn:
            agent = conn.execute("SELECT first_seen, ip FROM agents WHERE agent_id=?", (AGENT,)).fetchone()
            self.assertEqual(conn.execute("SELECT token FROM push").fetchone()[0], "t1")
            now = time.time()
            self.assertFalse(srv.store_push_token(conn, AGENT, "evil", "203.0.113.9", now, agent))
            self.assertTrue(srv.store_push_token(conn, AGENT, "t2", agent["ip"], now, agent))
            self.assertFalse(srv.store_push_token(conn, AGENT, "t3", "203.0.113.9", now + 2 * 3600, agent))
            self.assertTrue(srv.store_push_token(conn, AGENT, "t2", "198.51.100.7", now + 20 * 3600, agent))
            self.assertFalse(srv.store_push_token(conn, AGENT, "t3", "203.0.113.9", now + 30 * 3600, agent))
            self.assertTrue(srv.store_push_token(conn, AGENT, "t3", "203.0.113.9", now + 45 * 3600, agent))
            self.assertEqual(conn.execute("SELECT token FROM push").fetchone()[0], "t3")

    def test_alerts_only_for_known_nodes_and_seasoned_agents(self):
        self.put_nodes(2)
        telegrams = []
        srv.telegram_send = lambda text: telegrams.append(text) or True
        fresh = "cccccccc-0000-0000-0000-000000000000"
        old = "dddddddd-0000-0000-0000-000000000000"
        season(old)
        for agent_id in (fresh, old):
            for ok in (True, True, True, False, False, False, False, False):
                srv._report_agents.clear()
                self.client.post("/v1/report", json={
                    "agent_id": agent_id, "results": {"n0:443": {"ok": ok}, "n1:443": {"ok": True},
                                                      "evil<b>:1": {"ok": ok}},
                    "network": {"type": "cellular", "operator": agent_id[:4]}})
        flush_alerts()
        self.assertEqual(len(telegrams), 1)
        self.assertIn("n0:443", telegrams[0])
        self.assertNotIn("evil", telegrams[0])
        nodes = {n["node"] for n in self.client.get("/v1/admin/trends", headers=ADMIN).json()["nodes"]}
        self.assertEqual(nodes, {"n0:443", "n1:443"})

    def test_new_agents_do_not_raise_fleet_alarm(self):
        self.assertEqual(self.fleet([False, False, False], seasoned=False), [])

    def test_alerts_hourly_cap(self):
        sent = []
        srv.telegram_send = lambda text: sent.append(text) or True
        for i in range(srv.ALERTS_PER_HOUR + 5):
            srv.send_alert("a%d" % i)
        flush_alerts()
        self.assertEqual(len(sent), srv.ALERTS_PER_HOUR)
        srv._alert_sent.clear()
        srv.send_alert("later", now=time.time() + 3601)
        flush_alerts()
        self.assertEqual(sent[-1], "later")

    def test_nominatim_not_more_than_once_a_second(self):
        calls = []

        class Answer:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self):
                return b'{"address": {"city": "X"}}'

        old = srv.urllib.request.urlopen
        srv.urllib.request.urlopen = lambda *a, **k: calls.append(a) or Answer()
        srv._nominatim_last[0] = 0
        try:
            first = srv.place_lookup(55.0, 37.0)
            second = srv.place_lookup(56.0, 38.0)
            again = srv.place_lookup(55.0, 37.0)
        finally:
            srv.urllib.request.urlopen = old
        self.assertEqual(first["city"], "X")
        self.assertEqual(second, {})
        self.assertEqual(again["city"], "X")
        self.assertEqual(len(calls), 1)

    def test_files_are_downloads(self):
        os.makedirs(srv.FILES_DIR, exist_ok=True)
        with open(os.path.join(srv.FILES_DIR, "x.html"), "w", encoding="utf-8") as handle:
            handle.write("<script>alert(1)</script>")
        r = self.client.get("/files/x.html")
        self.assertIn("attachment", r.headers["content-disposition"])
        self.assertIn("sandbox", r.headers["content-security-policy"])
        self.assertEqual(r.headers["x-content-type-options"], "nosniff")

    def test_poll_survives_locked_database(self):
        import sqlite3
        import threading
        self.report()
        self.assertEqual(self.client.get("/v1/poll?agent_id=%s&after=0" % AGENT).status_code, 200)
        srv._online.clear()
        with srv.db() as conn:
            self.assertEqual(conn.execute("PRAGMA journal_mode").fetchone()[0].lower(), "wal")
        holder = sqlite3.connect(srv.DB_PATH, isolation_level=None)
        holder.execute("BEGIN IMMEDIATE")
        holder.execute("UPDATE agents SET note='busy'")
        old, srv.DB_TIMEOUT = srv.DB_TIMEOUT, 0.2
        codes = []
        try:
            threads = [threading.Thread(target=lambda: codes.append(
                self.client.get("/v1/poll?agent_id=%s&after=0" % AGENT).status_code)) for _ in range(4)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(codes, [200] * 4)
            self.assertTrue(srv.online_now(AGENT))
        finally:
            srv.DB_TIMEOUT = old
            holder.execute("ROLLBACK")
            holder.close()

    def test_poll_waits_for_short_write(self):
        import sqlite3
        import threading
        self.report()
        holder = sqlite3.connect(srv.DB_PATH, isolation_level=None, check_same_thread=False)
        holder.execute("BEGIN IMMEDIATE")
        holder.execute("UPDATE agents SET note='busy'")
        srv._known_agents.clear()
        started = time.time()
        timer = threading.Timer(0.5, lambda: holder.execute("COMMIT"))
        timer.start()
        try:
            self.assertEqual(self.client.get("/v1/poll?agent_id=%s&after=0" % AGENT).status_code, 200)
        finally:
            timer.join()
            holder.close()
        self.assertLess(time.time() - started, 10)
        self.assertTrue(srv.online_now(AGENT))

    def test_prune_in_batches(self):
        self.report()
        with srv.db() as conn:
            conn.executemany("INSERT INTO reports(agent_id, ts, payload) VALUES (?, 0, '{}')",
                             [(AGENT,)] * (srv.PRUNE_BATCH * 2 + 7))
        self.assertEqual(srv.prune_old(), srv.PRUNE_BATCH * 2 + 7)

    def test_lifespan_replaces_on_event(self):
        self.assertEqual(srv.app.router.on_startup, [])
        self.assertTrue(srv._alert_worker)


def fake_request(peer, forwarded=None):
    from starlette.requests import Request
    headers = [(b"x-forwarded-for", forwarded.encode())] if forwarded else []
    return Request({"type": "http", "method": "GET", "path": "/", "headers": headers, "client": (peer, 5555)})


class ClientIpTest(unittest.TestCase):
    """X-Forwarded-For - только от своего прокси на этой машине, иначе клиент обходит лимит частоты."""

    def test_direct_client_cannot_spoof(self):
        self.assertEqual(srv.client_ip(fake_request("203.0.113.7", "1.2.3.4")), "203.0.113.7")

    def test_local_proxy_header_trusted(self):
        self.assertEqual(srv.client_ip(fake_request("127.0.0.1", "198.51.100.9")), "198.51.100.9")
        self.assertEqual(srv.client_ip(fake_request("::1", "198.51.100.9")), "198.51.100.9")

    def test_proxy_that_appends_uses_last_hop(self):
        self.assertEqual(srv.client_ip(fake_request("127.0.0.1", "1.2.3.4, 198.51.100.9")), "198.51.100.9")

    def test_local_without_header_is_peer(self):
        self.assertEqual(srv.client_ip(fake_request("127.0.0.1")), "127.0.0.1")

    def test_spoofed_header_does_not_bypass_rate_limit(self):
        srv._rate.clear()
        try:
            hits = [srv.rate_limited(srv.client_ip(fake_request("203.0.113.8", "10.0.0.%d" % i)))
                    for i in range(srv.RATE_LIMIT + 1)]
        finally:
            srv._rate.clear()
        self.assertTrue(hits[-1])

    def test_ipv6_rate_limit_by_64(self):
        self.assertEqual(srv.rate_key("2001:db8:1:2::5"), srv.rate_key("2001:db8:1:2:ffff::9"))
        self.assertNotEqual(srv.rate_key("2001:db8:1:2::5"), srv.rate_key("2001:db8:1:3::5"))
        self.assertEqual(srv.rate_key("203.0.113.8"), "203.0.113.8")
        srv._rate.clear()
        try:
            hits = [srv.rate_limited("2001:db8:1:2::%x" % (i + 1)) for i in range(srv.RATE_LIMIT + 1)]
        finally:
            srv._rate.clear()
        self.assertTrue(hits[-1])

    def test_rate_table_drops_stale_windows_not_everything(self):
        table = srv.RateTable(3, window=60, max_keys=5)
        now = time.time()
        for i in range(4):
            table.hit("198.51.100.%d" % i, now - 3600)
        for _ in range(3):
            table.hit("203.0.113.1", now)
        table.hit("203.0.113.2", now)
        self.assertTrue(table.hit("203.0.113.1", now))
        self.assertLessEqual(len(table), 5)
        self.assertNotIn("198.51.100.0", table.buckets)

    def test_rate_table_is_fast_with_many_keys(self):
        table = srv.RateTable(1, window=60, max_keys=20000)
        started = time.perf_counter()
        for i in range(60000):
            table.hit("k%d" % i)
        self.assertLess(time.perf_counter() - started, 3)
        self.assertEqual(len(table), 20000)


class FcmTest(unittest.TestCase):
    def test_dead_tokens(self):
        import fcm
        self.assertTrue(fcm.dead_token(404, b""))
        self.assertTrue(fcm.dead_token(400, b'{"error": {"status": "INVALID_ARGUMENT", "message": '
                                            b'"The registration token is not a valid FCM registration token"}}'))
        self.assertTrue(fcm.dead_token(403, b"UNREGISTERED"))
        self.assertFalse(fcm.dead_token(400, b'{"error": {"status": "INVALID_ARGUMENT", "message": "bad ttl"}}'))
        self.assertFalse(fcm.dead_token(500, b""))

    def test_send_parallel_with_deadline(self):
        import threading

        import fcm
        old = (fcm.project_id, fcm.access_token, fcm._send_one, fcm.SEND_DEADLINE)
        release = threading.Event()

        def one(project, bearer, token, data):
            if token == "slow":
                release.wait(5)
            return token != "gone", token == "gone"

        fcm.project_id, fcm.access_token, fcm._send_one, fcm.SEND_DEADLINE = (lambda: "p"), (lambda: "b"), one, 0.5
        try:
            started = time.time()
            sent, dead = fcm.send(["a", "b", "gone", "slow"], "check")
            self.assertLess(time.time() - started, 3)
        finally:
            release.set()
            fcm.project_id, fcm.access_token, fcm._send_one, fcm.SEND_DEADLINE = old
        self.assertEqual((sent, dead), (2, ["gone"]))


class ServerLangTest(unittest.TestCase):
    """VPNCHECK_LANG: ru по умолчанию - тексты как есть, en - из словаря EN."""

    def test_env_read_at_start(self):
        import importlib.util
        path = os.path.join(os.path.dirname(srv.__file__), "app.py")
        old = os.environ.get("VPNCHECK_LANG")
        os.environ["VPNCHECK_LANG"] = "en"
        try:
            spec = importlib.util.spec_from_file_location("app_en", path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
        finally:
            if old is None:
                os.environ.pop("VPNCHECK_LANG", None)
            else:
                os.environ["VPNCHECK_LANG"] = old
        self.assertEqual(mod.LANG, "en")
        self.assertEqual(mod.t("нет доступа"), "access denied")
        self.assertEqual(mod.t("файл больше %d МБ") % 120, "file larger than 120 MB")
        self.assertEqual(mod.t("что-то без перевода"), "что-то без перевода")

    def test_ru_default_is_identity(self):
        old, srv.LANG = srv.LANG, "ru"
        try:
            for key in srv.EN:
                self.assertEqual(srv.t(key), key)
        finally:
            srv.LANG = old

    def test_en_detail_in_http_error(self):
        old, srv.LANG = srv.LANG, "en"
        srv.ADMIN_TOKEN = "testtoken"
        try:
            r = TestClient(srv.app).get("/v1/admin/state", headers={"X-Admin-Token": "wrong"})
        finally:
            srv.LANG = old
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json()["detail"], "access denied")

    def test_place_names_latin_in_english(self):
        old, srv.LANG = srv.LANG, "en"
        try:
            self.assertEqual(srv.place_name("Нижегородская область"), "Nizhny Novgorod Oblast")
            self.assertEqual(srv.place_name("Москва"), "Moscow")
            self.assertEqual(srv.place_name("Тверская губерния"), "Tverskaya guberniya")
            self.assertEqual(srv.place_name("Wi-Fi"), "Wi-Fi")
        finally:
            srv.LANG = old
        self.assertEqual(srv.place_name("Москва"), "Москва")

    def test_keys_used_and_placeholders_match(self):
        import ast
        import re
        with open(os.path.join(os.path.dirname(srv.__file__), "app.py"), encoding="utf-8") as f:
            tree = ast.parse(f.read())
        used = {n.args[0].value for n in ast.walk(tree)
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "t"
                and n.args and isinstance(n.args[0], ast.Constant)}
        self.assertEqual(set(srv.EN), used)
        spec = re.compile(r"%[sd%]")
        for ru, en in srv.EN.items():
            self.assertEqual(spec.findall(ru), spec.findall(en), ru)
            self.assertNotIn(chr(0x2014), en)


class HardeningTest(unittest.TestCase):
    """Круг 3: рост базы, NaN, push-токены, координаты, тревоги, отложенные отчёты, каталог данных."""

    setUp = ServerTest.setUp
    tearDown = ServerTest.tearDown
    report = ServerTest.report

    def count(self, table):
        with srv.db() as conn:
            return conn.execute("SELECT COUNT(*) FROM %s" % table).fetchone()[0]

    def stored(self):
        return self.client.get("/v1/admin/reports", headers=ADMIN).json()["reports"]

    def test_only_published_nodes_and_sites_are_stored(self):
        srv.update_state({"sites": [{"url": "https://ok.example", "name": "ok"}]})
        junk = {"junk%d" % i: {"ok": True} for i in range(600)}
        self.report(results=dict(junk, **{"de:443": {"ok": True}, "us:443": {"ok": False}}),
                    sites={"https://ok.example": {"ok": True}, "https://junk.example": {"ok": True}})
        payload = self.stored()[0]["payload"]
        self.assertEqual(set(payload["results"]), {"de:443", "us:443"})
        self.assertEqual(set(payload["sites"]), {"https://ok.example"})

    def test_new_agent_ids_limited_per_address(self):
        ids = ["%08x-0000-4000-8000-000000000000" % i for i in range(srv.NEW_AGENTS_PER_IP + 1)]
        codes = [self.client.post("/v1/report", json={"agent_id": agent_id, "results": {}}).status_code
                 for agent_id in ids]
        self.assertEqual(codes, [200] * srv.NEW_AGENTS_PER_IP + [429])
        self.assertEqual(self.client.post("/v1/errors", json={"agent_id": ids[-1], "errors": []}).status_code, 429)
        self.assertEqual(self.client.post("/v1/report", json={"agent_id": ids[0], "results": {}}).status_code, 200)
        veteran = "ffffffff-0000-4000-8000-000000000000"
        season(veteran)
        self.assertEqual(self.client.post("/v1/errors", json={"agent_id": veteran, "errors": []}).status_code, 200)

    def test_nan_and_infinity_rejected_and_old_rows_readable(self):
        headers = {"content-type": "application/json"}
        for raw in ('{"agent_id":"%s","results":{},"location":{"lat":55,"lon":37,"accuracy":NaN}}' % AGENT,
                    '{"agent_id":"%s","results":{"de:443":{"ok":true,"latency":Infinity}}}' % AGENT,
                    '{"agent_id":"%s","results":{},"unchecked":1e999}' % AGENT):
            reset_limits()
            self.assertEqual(self.client.post("/v1/report", content=raw, headers=headers).status_code, 400, raw)
        raw = '{"agent_id":"%s","action":"diag","result":{"x":-Infinity}}' % AGENT
        self.assertEqual(self.client.post("/v1/result", content=raw, headers=headers).status_code, 400)
        self.report(location={"lat": 55, "lon": 37, "accuracy": "nan"})
        with srv.db() as conn:
            conn.execute("UPDATE reports SET payload=?", ('{"results": {}, "x": NaN}',))
            conn.execute("INSERT INTO results(ts, agent_id, action, seq, payload) VALUES (?,?,?,?,?)",
                         (time.time(), AGENT, "diag", 1, '{"x": Infinity}'))
        reports = self.client.get("/v1/admin/reports", headers=ADMIN)
        self.assertEqual(reports.status_code, 200)
        self.assertIsNone(reports.json()["reports"][0]["payload"]["x"])
        self.assertEqual(self.client.get("/v1/admin/results", headers=ADMIN).status_code, 200)
        self.assertEqual(self.client.get("/v1/admin/matrix", headers=ADMIN).status_code, 200)
        self.assertEqual(srv._int(float("inf")), 0)

    def test_admin_state_rejects_non_finite_numbers_and_stored_ones_are_dropped(self):
        headers = dict(ADMIN, **{"content-type": "application/json"})
        good = {"key": "good:443", "outbound": {"tag": "proxy", "protocol": "vless",
                                                "settings": {"address": "1.1.1.1", "port": 443, "id": "x"}}}
        bad = ('{"key":"bad:443","outbound":{"tag":"proxy","protocol":"vless","settings":{"address":"1.1.1.2",'
               '"port":443,"id":"x","level":%s}}}')
        for value in ("1e400", "-1e999", "Infinity", "NaN"):
            body = '{"nodes":[%s,%s]}' % (json.dumps(good), bad % value)
            self.assertEqual(self.client.post("/v1/admin/state", content=body, headers=headers).status_code, 400)
            self.assertEqual(self.client.get("/v1/config").status_code, 200)
        self.assertEqual(self.client.post("/v1/admin/run_now", content='{"agent_id":NaN}', headers=headers)
                         .status_code, 200)
        with open(srv.STATE_PATH, "w", encoding="utf-8") as handle:
            handle.write('{"nodes": [%s, %s], "message": Infinity}' % (json.dumps(good), bad % "Infinity"))
        config = self.client.get("/v1/config")
        self.assertEqual(config.status_code, 200)
        self.assertEqual([node["key"] for node in config.json()["nodes"]], ["good:443"])
        self.assertEqual(config.json()["message"], "")
        self.assertEqual(self.client.get("/v1/admin/state", headers=ADMIN).status_code, 200)

    def test_admin_state_main_tag_not_string_is_refused(self):
        node = {"key": "k", "outbound": {"tag": ["x"], "protocol": "vless",
                                         "settings": {"address": "1.1.1.1", "port": 443, "id": "x"}}}
        answer = self.client.post("/v1/admin/state", headers=ADMIN, json={"nodes": [node]})
        self.assertEqual(answer.status_code, 400)
        self.assertIn("unsupported", answer.json()["detail"])

    def test_errors_total_cap_applies_on_write(self):
        old = srv.MAX_ERRORS_TOTAL
        srv.MAX_ERRORS_TOTAL = 25
        try:
            for i in range(3):
                agent_id = "%08x-0000-4000-8000-000000000000" % i
                self.client.post("/v1/errors", json={"agent_id": agent_id, "errors": [{"text": "e"}] * 20})
        finally:
            srv.MAX_ERRORS_TOTAL = old
        self.assertEqual(self.count("errors"), 25)

    def test_full_database_refuses_agent_writes(self):
        with mock.patch.object(srv, "db_used_bytes", return_value=10 ** 12):
            self.assertEqual(self.report().status_code, 507)
            self.assertEqual(self.client.post("/v1/errors", json={"agent_id": AGENT, "errors": []}).status_code, 507)
            self.assertEqual(self.client.get("/v1/config").status_code, 200)
        self.assertEqual(self.report().status_code, 200)
        self.assertGreater(srv.db_used_bytes(time.time() + 3600), 0)

    def test_matrix_and_trends_only_from_seasoned_agents(self):
        fresh, old = "cccccccc-0000-0000-0000-000000000000", "dddddddd-0000-0000-0000-000000000000"
        season(old)
        for agent_id in (fresh, old):
            self.client.post("/v1/report", json={"agent_id": agent_id, "results": {"de:443": {"ok": True}},
                                                 "network": {"type": "cellular", "operator": agent_id[:4]}})
        matrix = self.client.get("/v1/admin/matrix", headers=ADMIN).json()
        self.assertEqual(list(matrix["columns"]), ["Москва · dddd"])
        trends = self.client.get("/v1/admin/trends", headers=ADMIN).json()["nodes"]
        self.assertEqual({row["scope"] for row in trends}, {"Москва · dddd"})
        self.assertEqual(len(self.client.get("/v1/admin/trends?limit=-1", headers=ADMIN).json()["nodes"]), 1)
        self.assertEqual(len(self.client.get("/v1/admin/reports?limit=-1", headers=ADMIN).json()["reports"]), 1)
        self.assertEqual(self.client.get("/v1/admin/matrix?hours=-5", headers=ADMIN).status_code, 200)

    def test_push_token_refreshed_and_unseasoned_evicted_when_full(self):
        self.report(push_token="t1")
        with srv.db() as conn:
            conn.execute("UPDATE push SET ts=0")
            agent = conn.execute("SELECT first_seen, ip FROM agents WHERE agent_id=?", (AGENT,)).fetchone()
            self.assertTrue(srv.store_push_token(conn, AGENT, "t1", "198.51.100.1", 100.0, agent))
            self.assertEqual(tuple(conn.execute("SELECT ts, ip FROM push").fetchone()), (100.0, "198.51.100.1"))
        old = srv.MAX_PUSH_TOKENS
        srv.MAX_PUSH_TOKENS = 1
        try:
            veteran = "eeeeeeee-0000-4000-8000-000000000000"
            season(veteran)
            with srv.db() as conn:
                now = time.time()
                self.assertTrue(srv.store_push_token(conn, veteran, "v1", "198.51.100.2", now, None))
                self.assertEqual(conn.execute("SELECT agent_id FROM push").fetchall()[0][0], veteran)
                self.assertFalse(srv.store_push_token(conn, "abababab-0000", "x", "198.51.100.3", now, None))
        finally:
            srv.MAX_PUSH_TOKENS = old

    def test_location_needs_request_or_seasoned_button(self):
        body = {"agent_id": AGENT, "lat": 55.7, "lon": 37.6, "city": "Москва"}
        self.report()
        self.assertEqual(self.client.post("/v1/location", json=body).json(), {"ok": False})
        self.client.post("/v1/admin/locate", headers=ADMIN, json={"agent_id": AGENT})
        self.assertTrue(self.client.post("/v1/location", json=body).json()["ok"])
        self.assertEqual(self.client.post("/v1/location", json=body).json(), {"ok": False})
        with srv.db() as conn:
            conn.execute("UPDATE agents SET first_seen=?", (time.time() - 2 * 86400,))
        self.assertTrue(self.client.post("/v1/location", json=body).json()["ok"])
        self.assertEqual(self.client.post("/v1/location", json=body).status_code, 429)
        self.assertEqual(self.client.post("/v1/location", json=dict(body, lat="nan")).status_code, 400)

    def test_ipv6_geo_cached_per_64(self):
        calls = []

        class Answer:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self):
                return b'{"country": "RU", "city": "X", "loc": "55.0,37.0"}'

        with mock.patch.object(srv.urllib.request, "urlopen", lambda *a, **k: calls.append(a) or Answer()):
            first = GEO_LOOKUP("2a00:1450:4001:81c::200e")
            second = GEO_LOOKUP("2a00:1450:4001:81c::1")
        self.assertEqual(first["city"], "X")
        self.assertEqual(second, first)
        self.assertEqual(len(calls), 1)

    def test_static_html_gets_csp_and_regions_fallback(self):
        page = self.client.get("/static/admin.html")
        self.assertIn("frame-ancestors 'none'", page.headers.get("content-security-policy", ""))
        with mock.patch.object(srv, "STATIC_DIR", self.tmp):
            self.assertEqual(self.client.get("/static/ru_regions.geojson").status_code, 200)
            self.assertEqual(self.client.get("/static/admin.js").status_code, 404)

    def test_health_count_cached(self):
        self.assertEqual(self.client.get("/health").json()["agents"], 0)
        self.report()
        self.assertEqual(self.client.get("/health").json()["agents"], 0)
        srv._health["ts"] = 0.0
        self.assertEqual(self.client.get("/health").json()["agents"], 1)

    def test_long_poll_only_when_asked(self):
        old = srv.LINK_WAIT
        srv.LINK_WAIT = 50
        try:
            self.assertEqual(srv.link_wait(0), 50)
            self.assertEqual(srv.link_wait(240), 240)
            self.assertEqual(srv.link_wait(10), 50)
            self.assertEqual(srv.link_wait(10 ** 6), srv.LINK_WAIT_MAX)
        finally:
            srv.LINK_WAIT = old
        self.assertEqual(self.client.get("/v1/poll?agent_id=%s&after=1&wait=240" % AGENT).status_code, 200)

    def test_alert_marked_only_when_sent_and_cooldown_by_key(self):
        events = [{"node": "de:443", "scope": "R · Op_", "ok": False, "rate": 0.5, "checks": 3}]
        srv.notify(events, "R · Op_")
        with mock.patch.object(srv, "telegram_send", return_value=False), \
                mock.patch.object(srv, "telegram_configured", return_value=True):
            self.assertFalse(flush_alerts())
        self.assertEqual(self.count("alert_last"), 0)
        self.assertEqual(self.count("alert_pending"), 1)
        errors = self.client.get("/v1/admin/errors", headers=ADMIN).json()["errors"]
        self.assertEqual([e["kind"] for e in errors], ["telegram"])
        sent = []
        with mock.patch.object(srv, "telegram_send", lambda text: sent.append(text) or True):
            self.assertTrue(flush_alerts())
            srv.notify(events, "R · Op_")
            srv.notify([dict(events[0], scope="R · OpX")], "R · OpX")
            srv.notify([dict(events[0], scope="R · OpX", node="us:443")], "R · OpX")
            flush_alerts()
        self.assertEqual(len(sent), 2)
        self.assertIn("us:443", sent[1])
        self.assertNotIn("de:443", sent[1])
        with srv.db() as conn:
            keys = {row[0] for row in conn.execute("SELECT key FROM alert_last")}
        self.assertEqual(keys, {"de:443|R · Op_|down", "us:443|R · OpX|down", "node:de:443|down", "node:us:443|down"})

    def test_telegram_retried_before_giving_up(self):
        answers = [False, False, True]
        srv.notify([{"node": "de:443", "scope": "R · Op", "ok": False, "rate": 0.5, "checks": 3}], "R · Op")
        with mock.patch.object(srv, "telegram_send", lambda text: answers.pop(0)), \
                mock.patch.object(srv, "telegram_configured", return_value=True):
            self.assertTrue(flush_alerts())
        self.assertEqual(answers, [])
        self.assertEqual(self.count("alert_pending"), 0)
        self.assertEqual(self.count("errors"), 0)

    def test_alert_last_migrated_from_history(self):
        with srv.db() as conn:
            conn.execute("DROP TABLE alert_last")
            conn.execute("INSERT INTO alerts(ts, kind, text) VALUES (?,?,?)",
                         (time.time(), "down", "de:443|R · Op|down"))
            conn.execute("INSERT INTO alerts(ts, kind, text) VALUES (?,?,?)", (time.time(), "fleet_zero", "..."))
        srv.init_db()
        with srv.db() as conn:
            keys = {row[0] for row in conn.execute("SELECT key FROM alert_last")}
            indexes = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")}
        self.assertEqual(keys, {"de:443|R · Op", "fleet_zero"})
        self.assertIn("reports_agent", indexes)

    def test_deferred_report_backdated_and_outside_trends(self):
        season(AGENT)
        self.report(results={"de:443": {"ok": True}, "us:443": {"ok": True}})
        self.report(report_via="default", deferred_s=7200, rejected=1, sites_unchecked=2, started=1700000000,
                    results={"de:443": {"ok": False}, "us:443": {"ok": False}})
        reports = self.stored()
        self.assertAlmostEqual(reports[0]["ts"] - reports[1]["ts"], 7200, delta=60)
        deferred = reports[1]["payload"]
        self.assertEqual((deferred["deferred_s"], deferred["rejected"], deferred["sites_unchecked"],
                          deferred["started"]), (7200, 1, 2, 1700000000))
        card = self.client.get("/v1/admin/agents", headers=ADMIN).json()["agents"][0]
        self.assertEqual(card["alive"], 2)
        trends = self.client.get("/v1/admin/trends", headers=ADMIN).json()["nodes"]
        self.assertEqual({row["checks"] for row in trends}, {1})
        self.assertEqual(srv.deferred_seconds({"deferred_s": 10 ** 9}), srv.DEFERRED_MAX)

    def test_rejected_nodes_do_not_make_report_incomplete(self):
        srv.update_state({"nodes": [{"key": "n%d:443" % i} for i in range(10)]})
        answer = self.report(rejected=8, results={"n0:443": {"ok": True}, "n1:443": {"ok": True}}).json()
        self.assertNotIn("ignored", answer)

    def test_yandex_key_cleaned(self):
        self.client.post("/v1/admin/state", headers=ADMIN, json={"yandex_key": "ab-12<x>" + "z" * 100})
        key = self.client.get("/v1/admin/state", headers=ADMIN).json()["yandex_key"]
        self.assertTrue(key.startswith("ab-12x"))
        self.assertLessEqual(len(key), 64)

    def test_data_dir_from_environment(self):
        import subprocess
        code = "import app, fcm; print(app.DB_PATH); print(app.BACKUP_DIR); print(fcm.SA_PATH)"
        out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True,
                             cwd=os.path.dirname(srv.__file__), env=dict(os.environ, VPNAGENT_DATA=self.tmp)).stdout
        self.assertEqual(out.split("\n")[:3], [os.path.join(self.tmp, "agents.db"), os.path.join(self.tmp, "backups"),
                                               os.path.join(self.tmp, "service-account.json")])


if __name__ == "__main__":
    unittest.main()


class LimitsTest(unittest.TestCase):
    """Круг 4: предел тела до чтения, опросы по событию и с пределами, вытеснение старых отчётов, квоты."""

    setUp = ServerTest.setUp
    tearDown = ServerTest.tearDown
    report = ServerTest.report
    count = HardeningTest.count

    def test_body_limit_by_content_length_and_stream(self):
        big = b'{"agent_id":"' + b"a" * (srv.MAX_REPORT_BYTES + 10) + b'"}'
        self.assertEqual(self.client.post("/v1/report", content=big,
                                          headers={"content-type": "application/json"}).status_code, 413)

        def chunks():
            for _ in range(8):
                yield b"a" * (64 * 1024)
        self.assertEqual(self.client.post("/v1/location", content=chunks()).status_code, 413)
        self.assertEqual(self.report().status_code, 200)

    def test_admin_body_not_read_without_token(self):
        read = []

        def chunks():
            read.append(1)
            yield b"x" * 1024
        r = self.client.post("/v1/admin/upload", content=chunks(),
                             headers={"content-type": "multipart/form-data; boundary=b"})
        self.assertEqual(r.status_code, 401)
        self.assertEqual(self.client.post("/v1/admin/state", json={"message": "x"}).status_code, 401)
        self.assertEqual(self.client.post("/v1/admin/state", headers=ADMIN, json={"message": "x"}).status_code, 200)

    def test_poll_rejects_bad_id_and_limits_per_address(self):
        self.assertEqual(self.client.get("/v1/poll?agent_id=bad&after=1").status_code, 400)
        self.report()
        srv.LINK_WAIT = 1
        old = srv.POLLS_PER_KEY
        srv.POLLS_PER_KEY = 0
        try:
            self.assertEqual(self.client.get("/v1/poll?agent_id=%s&after=1" % AGENT).status_code, 429)
            self.assertEqual(self.client.get("/v1/poll?agent_id=%s&after=0&wait=240" % AGENT).status_code, 200)
        finally:
            srv.POLLS_PER_KEY = old
            srv.LINK_WAIT = 0
        self.assertEqual(srv._poll_slots["total"], 0)
        self.assertEqual(srv._poll_slots["keys"], {})

    def test_unknown_agents_get_smaller_limit(self):
        srv.LINK_WAIT = 1
        old = srv.UNKNOWN_POLLS_PER_KEY
        srv.UNKNOWN_POLLS_PER_KEY = 0
        try:
            stranger = "0123456789abcdef"
            self.assertEqual(self.client.get("/v1/poll?agent_id=%s&after=1" % stranger).status_code, 429)
            self.report()
            self.assertEqual(self.client.get("/v1/poll?agent_id=%s&after=1" % AGENT).status_code, 200)
        finally:
            srv.UNKNOWN_POLLS_PER_KEY = old
            srv.LINK_WAIT = 0

    def test_old_agent_first_poll_is_held(self):
        self.report()
        srv.LINK_WAIT = 1
        try:
            started = time.time()
            poll = self.client.get("/v1/poll?agent_id=%s&after=0" % AGENT).json()
            self.assertGreaterEqual(time.time() - started, 0.9)
            self.assertEqual(poll["commands"], [])
            self.assertEqual(poll["seq"], srv._cmd_seq)
            self.assertEqual(srv.poll_hold(True, 0, 240), 0)
            self.assertEqual(srv.poll_hold(True, 0, 0), 1)
            self.assertEqual(srv.poll_hold(False, 5, 240), 1)
        finally:
            srv.LINK_WAIT = 0

    def test_poll_wakes_on_command(self):
        import threading
        self.report()
        srv.LINK_WAIT = 50
        answers = []
        try:
            thread = threading.Thread(target=lambda: answers.append(
                self.client.get("/v1/poll?agent_id=%s&after=1&wait=240" % AGENT).json()))
            started = time.time()
            thread.start()
            deadline = time.time() + 10
            while not srv._polling.get(AGENT) and time.time() < deadline:
                time.sleep(0.02)
            srv._online.clear()
            self.assertTrue(srv.online_now(AGENT))
            srv.enqueue_command(AGENT, "diag")
            thread.join(10)
        finally:
            srv.LINK_WAIT = 0
        self.assertLess(time.time() - started, 10)
        self.assertEqual([c["action"] for c in answers[0]["commands"]], ["diag"])
        self.assertNotIn(AGENT, srv._polling)
        self.assertTrue(srv.online_now(AGENT))

    def test_stale_commands_dropped_from_bus(self):
        srv.enqueue_command("", "check")
        srv._cmds[-1]["ts"] = time.time() - srv.COMMAND_TTL - 1
        srv.enqueue_command("", "update")
        self.assertEqual([c["action"] for c in srv._cmds], ["update"])

    def test_full_database_evicts_oldest_reports(self):
        for _ in range(3):
            self.report()
            reset_limits()
        first = self.count("reports")
        old = srv.EVICT_BATCH
        srv.EVICT_BATCH = 2
        try:
            with mock.patch.object(srv, "db_used_bytes", return_value=10 ** 12):
                self.assertEqual(self.report().status_code, 200)
        finally:
            srv.EVICT_BATCH = old
        self.assertEqual(self.count("reports"), first - 2 + 1)

    def test_daily_quota_for_new_agents(self):
        old = srv._report_quota_new.limit
        srv._report_quota_new.limit = 2
        try:
            codes = []
            for _ in range(3):
                for table in (srv._rate, srv._report_agents, srv._report_ips):
                    table.clear()
                codes.append(self.report().status_code)
            self.assertEqual(codes, [200, 200, 429])
            season(AGENT)
            with srv.db() as conn:
                conn.execute("UPDATE agents SET first_seen=?", (time.time() - 2 * 86400,))
            self.assertEqual(self.report().status_code, 200)
        finally:
            srv._report_quota_new.limit = old

    def test_repeated_report_id_stored_once(self):
        first = self.report(report_id="11111111-2222-4333-8444-555555555555").json()
        reset_limits()
        again = self.report(report_id="11111111-2222-4333-8444-555555555555").json()
        self.assertNotIn("duplicate", first)
        self.assertTrue(again["duplicate"])
        self.assertEqual(self.count("reports"), 1)
        reset_limits()
        self.report(report_id="bad id")
        self.assertEqual(self.count("reports"), 2)

    def test_admin_reports_explain_trust(self):
        self.report(direct_ok=False)
        reset_limits()
        self.report(same_ip_as="wifi", deferred_s=900, partial=True)
        items = self.client.get("/v1/admin/reports", headers=ADMIN).json()["reports"]
        newest, oldest = sorted(items, key=lambda item: item["id"], reverse=True)
        self.assertEqual((oldest["trusted"], oldest["direct_ok"], oldest["partial"]), (False, False, False))
        self.assertEqual((newest["trusted"], newest["same_ip_as"], newest["partial"], newest["deferred"]),
                         (False, "wifi", True, 900))

    def test_matrix_skips_old_deferred_and_unplaced(self):
        season(AGENT)
        self.report(deferred_s=900)
        reset_limits()
        self.report(report_via="default")
        matrix = self.client.get("/v1/admin/matrix", headers=ADMIN).json()
        self.assertEqual(matrix["columns"], {})
        reset_limits()
        self.report(deferred_s=100)
        self.assertEqual(len(self.client.get("/v1/admin/matrix", headers=ADMIN).json()["columns"]), 1)

    def test_older_deferred_report_keeps_last_flags(self):
        self.report(direct_ok=False)
        reset_limits()
        self.report(deferred_s=3600)
        agent = self.client.get("/v1/admin/agents", headers=ADMIN).json()["agents"][0]
        self.assertFalse(agent["last_trusted"])

    def test_deferred_report_geo_by_public_direct_ip(self):
        looked = []
        srv.geo_lookup = lambda ip, **_: looked.append(ip) or {"region": "Тверь"}
        self.report(report_via="default", direct_ip="10.0.0.1")
        reset_limits()
        self.report(report_via="default", direct_ip="203.0.113.9")
        self.assertEqual(looked, [])
        reset_limits()
        self.report(report_via="default", direct_ip="8.8.8.8")
        self.assertEqual(looked, ["8.8.8.8"])
        regions = [item["region"] for item in self.client.get("/v1/admin/reports", headers=ADMIN).json()["reports"]]
        self.assertIn("Тверь", regions)

    def test_geo_quota_for_new_agents(self):
        with mock.patch.object(srv.urllib.request, "urlopen") as opened:
            self.assertEqual(GEO_LOOKUP("8.8.8.8", may_fetch=lambda: False), {})
        opened.assert_not_called()

    def test_result_only_from_known_agent_and_capped(self):
        body = {"agent_id": AGENT, "action": "diag", "result": {"x": 1}}
        self.assertFalse(self.client.post("/v1/result", json=body).json()["ok"])
        self.report()
        old = srv.MAX_RESULTS_PER_AGENT
        srv.MAX_RESULTS_PER_AGENT = 3
        try:
            for _ in range(5):
                self.assertTrue(self.client.post("/v1/result", json=body).json()["ok"])
        finally:
            srv.MAX_RESULTS_PER_AGENT = old
        self.assertEqual(self.count("results"), 3)

    def test_new_agent_counted_only_when_stored(self):
        bad = "%08x-0000-4000-8000-000000000000"
        for i in range(srv.NEW_AGENTS_PER_IP + 3):
            self.client.post("/v1/report", json={"agent_id": bad % i, "results": "x"})
        self.assertEqual(self.client.post("/v1/report", json={"agent_id": bad % 999, "results": {}}).status_code,
                         200)

    def test_network_and_device_keys_whitelisted(self):
        self.report(network={"type": "cellular", "operator": "MTS", "evil": "x"},
                    device={"model": "A07", "LD_PRELOAD": "y"})
        payload = self.client.get("/v1/admin/reports", headers=ADMIN).json()["reports"][0]["payload"]
        self.assertEqual(payload["network"], {"type": "cellular", "operator": "MTS"})
        self.assertEqual(payload["device"], {"model": "A07"})

    def test_extra_outbounds_validated_and_served(self):
        fragment = {"tag": "fragment", "protocol": "freedom", "settings": {"fragment": {"packets": "tlshello"}}}
        main = {"tag": "proxy", "protocol": "vless", "streamSettings": {"sockopt": {"dialerProxy": "fragment"}}}
        good = [{"key": "a:443", "outbound": main, "extra_outbounds": [fragment]}]
        self.assertEqual(self.client.post("/v1/admin/state", headers=ADMIN, json={"nodes": good}).status_code, 200)
        self.assertEqual(self.client.get("/v1/config").json()["nodes"][0]["extra_outbounds"], [fragment])
        bad = [[{"tag": "vc-direct", "protocol": "freedom"}], [fragment, fragment], [{"tag": "x", "protocol": "socks"}],
               [{"tag": "r", "protocol": "freedom", "settings": {"redirect": "1.1.1.1:53"}}], [fragment] * 9, {"a": 1}]
        for extra in bad:
            nodes = [{"key": "a:443", "outbound": main, "extra_outbounds": extra}]
            self.assertEqual(self.client.post("/v1/admin/state", headers=ADMIN, json={"nodes": nodes}).status_code,
                             400, extra)

    def test_core_failed_kept_in_history(self):
        self.report(core_failed=2, rejected=2)
        payload = self.client.get("/v1/admin/reports", headers=ADMIN).json()["reports"][0]["payload"]
        self.assertEqual(payload["core_failed"], 2)


class Round5Test(unittest.TestCase):
    """Круг 5: тревоги без потерь, вытеснение без стирания давних агентов, квоты по адресу, цепочки outbound'ов,
    непроверенные узлы, зомби-опросы, кэши и сжатие ответов админки."""

    setUp = ServerTest.setUp
    tearDown = ServerTest.tearDown
    report = ServerTest.report
    count = HardeningTest.count

    def direct_report(self, agent_id, results, ip, **extra):
        for table in (srv._report_agents, srv._report_ips, srv._report_quota, srv._report_quota_ip):
            table.clear()
        body = dict({"agent_id": agent_id, "results": results, "network": {"type": "mobile", "operator": "MTS"}},
                    **extra)
        return srv._handle_report(srv.json.dumps(body).encode(), ip)

    def test_one_agent_cannot_eat_the_alert_budget(self):
        sent = []
        srv.telegram_send = lambda text: sent.append(text) or True
        srv.update_state({"nodes": [{"key": "real:443"}, {"key": "ok:443"}]})
        evil, real, other = "aaaaaaaa-eee1", "bbbbbbbb-bbb2", "bbbbbbbb-bbb3"
        season(evil, real, other)

        def rep(agent, ok, region, ip):
            location = {"lat": 55.0, "lon": 37.0, "city": region, "region": region}
            self.direct_report(agent, {"real:443": {"ok": ok}, "ok:443": {"ok": True}}, ip, location=location)
        for _ in range(3):
            rep(real, True, "Москва", "93.184.216.1")
        rep(other, True, "Москва", "93.184.217.1")
        for n in range(30):
            for ok in (True, False, False, False):
                rep(evil, ok, "fake%03d" % n, "198.51.100.5")
        for _ in range(5):
            rep(real, False, "Москва", "93.184.216.1")
        self.assertEqual(self.count("alert_pending"), 31)
        flush_alerts()
        self.assertEqual(len(sent), 1)
        line = sent[0].split("\n")[1]
        self.assertTrue(line.split(": ", 1)[1].startswith("Москва"), line)
        self.assertIn(srv.t("…и ещё %d") % 21, line)
        self.assertEqual(self.count("alert_pending"), 0)
        self.assertFalse(flush_alerts())

    def test_flip_back_cancels_only_from_another_network(self):
        sent = []
        srv.telegram_send = lambda text: sent.append(text) or True
        down = {"node": "de:443", "scope": "R · Op", "ok": False, "rate": 0.5, "checks": 4}
        srv.notify([down, dict(down, node="us:443")], "R · Op", "cccccccc-0001", 2, "198.51.100.0/24")
        self.assertEqual(self.count("alert_pending"), 2)
        srv.notify([dict(down, node="us:443", ok=True)], "R · Op", "cccccccc-0002", 2, "203.0.113.0/24")
        srv.notify([dict(down, ok=True)], "R · Op", "cccccccc-0001", 2, "198.51.100.0/24")
        self.assertEqual(self.count("alert_pending"), 1)
        self.assertTrue(flush_alerts())
        self.assertIn("de:443", sent[-1])
        self.assertNotIn("us:443", sent[-1])

    def test_recovery_always_follows_a_sent_down_and_cooldown_is_per_direction(self):
        sent = []
        srv.telegram_send = lambda text: sent.append(text) or True
        with srv.db() as conn:
            conn.execute("INSERT INTO node_state(node, scope, ok, checks, ok_checks, changed, ts) "
                         "VALUES ('de:443', 'R · Op', 0, 9, 5, 0, ?)", (time.time(),))
        down = {"node": "de:443", "scope": "R · Op", "ok": False, "rate": 0.5, "checks": 9}
        srv.notify([dict(down, ok=True)], "R · Op")
        self.assertEqual(self.count("alert_pending"), 0)
        srv.notify([down], "R · Op")
        flush_alerts()
        with srv.db() as conn:
            conn.execute("UPDATE node_state SET ok=1")
        srv.notify([dict(down, ok=True)], "R · Op")
        flush_alerts()
        self.assertEqual(len(sent), 2)
        self.assertIn("🔴", sent[0])
        self.assertIn("🟢", sent[1])
        self.assertIn("de:443", sent[1])
        srv.notify([down], "R · Op")
        srv.notify([dict(down, ok=True)], "R · Op")
        self.assertEqual(self.count("alert_pending"), 0)

    def test_digest_takes_agents_in_turn(self):
        rows = [{"agent_id": "evil", "witnesses": 1, "ts": i} for i in range(50)]
        rows.append({"agent_id": "real", "witnesses": 1, "ts": 99})
        self.assertIn("real", [row["agent_id"] for row in srv._digest_order(rows)[:2]])
        rows.append({"agent_id": "seen", "witnesses": 3, "ts": 100})
        self.assertEqual(srv._digest_order(rows)[0]["agent_id"], "seen")

    def test_scope_witnesses_counted(self):
        with srv.db() as conn:
            self.assertEqual(srv.scope_witnesses(conn, "R · Op", "a1", time.time()), 1)
            self.assertEqual(srv.scope_witnesses(conn, "R · Op", "a1", time.time()), 1)
            self.assertEqual(srv.scope_witnesses(conn, "R · Op", "a2", time.time()), 2)
            self.assertEqual(srv.scope_witnesses(conn, "R · N", "a1", time.time(), "198.51.100.0/24"), 1)
            self.assertEqual(srv.scope_witnesses(conn, "R · N", "a2", time.time(), "198.51.100.0/24"), 1)
            self.assertEqual(srv.scope_witnesses(conn, "R · N", "a3", time.time(), "203.0.113.0/24"), 2)

    def seed_reports(self, agent_id, count, first_seen):
        with srv.db() as conn:
            conn.execute("INSERT OR REPLACE INTO agents(agent_id, first_seen, last_seen) VALUES (?,?,?)",
                         (agent_id, first_seen, first_seen))
            conn.executemany("INSERT INTO reports(agent_id, ts, payload) VALUES (?,?,?)",
                             [(agent_id, first_seen + i, "{}") for i in range(count)])

    def reports_by_agent(self):
        with srv.db() as conn:
            return {row[0]: row[1] for row in
                    conn.execute("SELECT agent_id, COUNT(*) FROM reports GROUP BY agent_id").fetchall()}

    def test_eviction_takes_young_agents_first_then_the_oldest_a_tenth_per_agent(self):
        old = time.time() - 30 * 86400
        self.seed_reports("11111111-real", 10, old)
        self.seed_reports("22222222-flood", 50, old + 100)
        self.seed_reports("33333333-young", 30, time.time())
        with mock.patch.object(srv, "EVICT_BATCH", 1000):
            srv.evict_oldest()
            self.assertEqual(self.reports_by_agent(), {"11111111-real": 10, "22222222-flood": 50})
            srv.evict_oldest()
        self.assertEqual(self.reports_by_agent(), {"11111111-real": 9, "22222222-flood": 45})

    def test_reports_capped_per_agent(self):
        with mock.patch.object(srv, "MAX_REPORTS_PER_AGENT", 3):
            for _ in range(5):
                reset_limits()
                self.assertEqual(self.report().status_code, 200)
        self.assertEqual(self.count("reports"), 3)

    def test_daily_quota_per_address_across_agents(self):
        with mock.patch.object(srv, "_report_quota_ip", srv.RateTable(2, window=86400)):
            for i in range(2):
                srv.limit_daily_reports("dddddddd-%04d" % i, True, "2001:db8:1:%x::1" % i)
            with self.assertRaises(srv.HTTPException) as caught:
                srv.limit_daily_reports("dddddddd-0009", True, "2001:db8:1:ff::1")
            srv.limit_daily_reports("dddddddd-0009", True, "2001:db8:2::1")
        self.assertEqual(caught.exception.status_code, 429)
        self.assertEqual(srv.REPORTS_PER_DAY_NEW, 100)

    def test_foreign_agent_id_does_not_burn_the_real_agent_quota(self):
        for _ in range(srv.REPORTS_PER_AGENT):
            srv.limit_writes(AGENT, "198.51.100.66", report=True)
        with self.assertRaises(srv.HTTPException):
            srv.limit_writes(AGENT, "198.51.100.66", report=True)
        srv.limit_writes(AGENT, "203.0.113.5", report=True)
        self.assertEqual(srv.rate_key_wide("2001:db8:1:2::1"), "2001:db8:1::/48")
        self.assertEqual(srv.rate_key_wide("1.2.3.4"), "1.2.3.4")

    def test_old_agents_results_for_chained_nodes_dropped(self):
        chained = {"key": "ch:443", "outbound": {"tag": "proxy", "proxySettings": {"tag": "hop"}},
                   "extra_outbounds": [{"tag": "hop", "protocol": "vless"}]}
        srv.update_state({"nodes": [{"key": "de:443"}, chained]})
        results = {"de:443": {"ok": True}, "ch:443": {"ok": False}}
        self.report(results=results, app_version_code=24)
        reset_limits()
        self.report(results=results, app_version_code=27, report_id="r5-new-0001")
        stored = self.client.get("/v1/admin/reports", headers=ADMIN).json()["reports"]
        self.assertEqual([sorted(item["payload"]["results"]) for item in stored],
                         [["ch:443", "de:443"], ["de:443"]])

    def test_unchecked_nodes_stored_for_published_keys_and_shown_in_matrix(self):
        season(AGENT)
        results = {"de:443": {"ok": True}, "us:443": {"ok": False, "unchecked": True, "error": "core-exit:2"}}
        self.report(results=results, unchecked=1,
                    unchecked_nodes={"de:443": "bogus", "junk:443": "rejected", "us:443": "core-exit:2"})
        reset_limits()
        self.report(results={"de:443": {"ok": True}, "us:443": {"ok": False, "unchecked": True, "error": "x"}},
                    unchecked=1, report_id="r5-unchecked-2")
        reports = self.client.get("/v1/admin/reports", headers=ADMIN).json()["reports"]
        self.assertEqual([item["unchecked_nodes"] for item in reports],
                         [{"us:443": "rejected"}, {"us:443": "core-exit:2"}])
        matrix = self.client.get("/v1/admin/matrix", headers=ADMIN).json()
        self.assertEqual(list(matrix["unchecked"]["us:443"].values()), ["rejected"])
        self.assertNotIn("us:443", matrix["matrix"])

    def test_chain_rings_and_stray_links_rejected(self):
        hop = {"tag": "hop", "protocol": "vless"}
        main = {"tag": "proxy", "proxySettings": {"tag": "hop"}}
        self.assertTrue(srv.valid_extra_outbounds([hop], main))
        self.assertTrue(srv.valid_extra_outbounds(None, {"tag": "proxy"}))
        self.assertFalse(srv.valid_extra_outbounds(None, main))
        ring = dict(hop, proxySettings={"tag": "hop"})
        back = dict(hop, streamSettings={"sockopt": {"dialerProxy": "proxy"}})
        two = dict(hop, proxySettings={"tag": "x"})
        loop = {"tag": "x", "protocol": "vless", "proxySettings": {"tag": "hop"}}
        cases = [[ring], [back], [hop, {"tag": "stray", "protocol": "vless"}], [dict(hop, tag="proxy")],
                 [two, loop], [dict(hop, proxySettings={"tag": "nowhere"})]]
        for extra in cases:
            self.assertFalse(srv.valid_extra_outbounds(extra, main), extra)
        self.assertFalse(srv.valid_extra_outbounds([hop], {"tag": "proxy"}))

    def test_old_agent_without_wait_gets_commands_sent_during_hold(self):
        srv.LINK_WAIT = 2
        season(AGENT)
        timer = srv.threading.Timer(0.3, lambda: srv.enqueue_command(AGENT, "check"))
        timer.start()
        started = time.time()
        answer = self.client.get("/v1/poll", params={"agent_id": AGENT, "after": 0}).json()
        timer.join()
        self.assertEqual([c["action"] for c in answer["commands"]], ["check"])
        self.assertLess(time.time() - started, 1.8)

    def test_dropped_poll_leaves_at_once(self):
        season(AGENT)
        srv.LINK_WAIT = 30
        messages = [{"type": "http.request", "body": b"", "more_body": False}, {"type": "http.disconnect"}]

        async def receive():
            await srv.asyncio.sleep(0.2)
            return messages.pop(0)
        scope = {"type": "http", "method": "GET", "path": "/v1/poll", "headers": [], "query_string": b"",
                 "client": ("198.51.100.7", 5000)}
        started = time.time()
        srv.asyncio.run(srv.poll(srv.Request(scope, receive), agent_id=AGENT, after=5, wait=240))
        self.assertLess(time.time() - started, 5)
        self.assertEqual(srv._poll_slots["total"], 0)
        self.assertNotIn(AGENT, srv._polling)

    def test_trends_paged_with_total(self):
        with srv.db() as conn:
            conn.executemany("INSERT INTO node_state(node, scope, ok, checks, ok_checks, changed, ts) "
                             "VALUES (?,?,?,?,?,?,?)", [("n%d" % i, "S", 1, 3, 3, 0, i) for i in range(5)])
        page = self.client.get("/v1/admin/trends?limit=2&offset=1", headers=ADMIN).json()
        self.assertEqual((page["total"], page["offset"], len(page["nodes"])), (5, 1, 2))
        self.assertEqual({row["node"] for row in page["nodes"]}, {"n3", "n2"})

    def test_matrix_cached_until_new_report(self):
        season(AGENT)
        self.report()
        first = self.client.get("/v1/admin/matrix", headers=ADMIN).json()
        with srv.db() as conn:
            conn.execute("UPDATE reports SET region='changed'")
        self.assertEqual(self.client.get("/v1/admin/matrix", headers=ADMIN).json()["columns"], first["columns"])
        reset_limits()
        self.report(report_id="r5-matrix-0002")
        self.assertEqual(len(self.client.get("/v1/admin/matrix", headers=ADMIN).json()["columns"]), 2)

    def test_admin_answers_gzipped_agent_ones_not(self):
        srv.update_state({"message": "x" * 300, "sites": [{"url": "https://s%d.example/" % i} for i in range(40)]})
        headers = dict(ADMIN, **{"Accept-Encoding": "gzip"})
        self.assertEqual(self.client.get("/v1/admin/state", headers=headers).headers.get("content-encoding"), "gzip")
        answer = self.client.get("/v1/config", headers={"Accept-Encoding": "gzip"})
        self.assertIsNone(answer.headers.get("content-encoding"))

    def test_state_cache_sees_every_write(self):
        for i in range(20):
            srv.update_state({"message": "m%d" % (i % 2)})
            self.assertEqual(srv.load_state()["message"], "m%d" % (i % 2))
        state = srv.load_state()
        state["message"] = "local"
        self.assertNotEqual(srv.load_state()["message"], "local")

class Round6Test(unittest.TestCase):
    """Круг 6: подтверждённые и склеенные тревоги, «снова отвечает», учётка узлов, бэкапы 7+4 и чистка отдельно,
    регионы одним названием, матрица с границей, dns-sinkhole, downloadSettings, гео по сети, потолок по адресу."""

    setUp = ServerTest.setUp
    tearDown = ServerTest.tearDown
    report = ServerTest.report
    count = HardeningTest.count
    direct_report = Round5Test.direct_report

    def trends(self):
        return {(n["node"], n["scope"]): n for n in self.client.get("/v1/admin/trends", headers=ADMIN).json()["nodes"]}

    def test_single_failure_is_not_a_flip_two_in_a_row_are(self):
        with srv.db() as conn:
            events = []
            for ok in (True, True, True, False, True, False, False, True, False, False, False, True, True):
                events.append([e["ok"] for e in srv.update_trends(conn, "R · Op", {"de:443": {"ok": ok}}, {})])
            self.assertEqual(events, [[]] * 9 + [[False], [], [], [True]])
            srv.update_trends(conn, "R · Op2", {"de:443": {"ok": False}}, {})
            events = [srv.update_trends(conn, "R · Op", {"de:443": {"ok": False}}, {}) for _ in range(2)]
        self.assertEqual([[e["ok"] for e in item] for item in events], [[], [False]])

    def test_rate_is_for_the_last_week(self):
        now = time.time()
        with srv.db() as conn:
            conn.execute("INSERT INTO node_state(node, scope, ok, checks, ok_checks, changed, ts, w_checks, w_ok) "
                         "VALUES ('de:443', 'R · Op', 0, 500, 0, 0, ?, 500, 0)", (now - 60 * 86400,))
            for _ in range(5):
                srv.update_trends(conn, "R · Op", {"de:443": {"ok": True}}, {})
        row = self.trends()[("de:443", "R · Op")]
        self.assertGreater(row["rate"], 0.95)
        self.assertEqual(row["checks_all"], 505)
        self.assertTrue(row["stable"])

    def test_old_database_gets_week_counters(self):
        with srv.db() as conn:
            conn.execute("INSERT INTO node_state(node, scope, ok, checks, ok_checks, changed, ts) "
                         "VALUES ('de:443', 'R · Op', 1, 1000, 900, 0, ?)", (time.time(),))
            conn.execute("UPDATE node_state SET w_checks=NULL, w_ok=NULL")
        srv.init_db()
        with srv.db() as conn:
            row = conn.execute("SELECT w_checks, w_ok FROM node_state").fetchone()
        self.assertEqual((row[0], round(row[1])), (srv.TREND_START_CHECKS, 45))

    def test_one_outage_in_many_places_is_one_line(self):
        sent = []
        srv.telegram_send = lambda text: sent.append(text) or True
        events = [{"node": "de:443", "scope": "Регион%d · Op" % i, "ok": False, "rate": 0.9, "checks": 9}
                  for i in range(12)]
        for event in events:
            srv.notify([event], event["scope"], "a%d" % len(sent), 2)
        self.assertFalse(srv.flush_alert_digest(time.time() + 60))
        self.assertTrue(flush_alerts())
        self.assertEqual(len(sent), 1)
        lines = sent[0].split("\n")
        self.assertEqual(len(lines), 2)
        self.assertIn(srv.t("…и ещё %d") % 2, lines[1])

    def test_message_has_at_most_ten_node_lines(self):
        sent = []
        srv.telegram_send = lambda text: sent.append(text) or True
        srv.notify([{"node": "n%02d:443" % i, "scope": "R · Op", "ok": False, "rate": 0.9, "checks": 9}
                    for i in range(14)], "R · Op")
        flush_alerts()
        lines = sent[0].split("\n")
        self.assertEqual(len(lines), 1 + srv.ALERT_LINES + 1)
        self.assertIn("4", lines[-1])

    def test_fleet_zero_goes_past_hourly_cap_and_drops_node_downs(self):
        sent = []
        srv.telegram_send = lambda text: sent.append(text) or True
        for i in range(srv.ALERTS_PER_HOUR):
            srv.send_alert("x%d" % i)
        srv.notify([{"node": "de:443", "scope": "R · Op0", "ok": False, "rate": 0.9, "checks": 9}], "R · Op0")
        fleet = ServerTest.fleet(self, [False, False, False])
        self.assertTrue(any("ни один агент" in text for text in fleet))
        self.assertEqual(self.count("alert_pending"), 0)
        self.assertFalse(any("de:443" in text for text in sent + fleet))

    def test_expiry_warned_three_and_one_day_before(self):
        sent = []
        srv.telegram_send = lambda text: sent.append(text) or True
        now = time.time()
        srv.update_state({"nodes_expire": now + 5 * 86400, "nodes_user": "vpnagent_x"})
        self.assertFalse(srv.flush_alert_digest(now))
        self.assertTrue(srv.flush_alert_digest(now + 2.5 * 86400))
        self.assertFalse(srv.flush_alert_digest(now + 2.6 * 86400))
        self.assertTrue(srv.flush_alert_digest(now + 4.5 * 86400))
        self.assertFalse(srv.flush_alert_digest(now + 4.6 * 86400))
        self.assertEqual(len(sent), 2)
        self.assertIn("vpnagent_x", sent[0])

    def test_expired_account_reports_stay_out_of_trends(self):
        season(AGENT)
        srv.update_state({"nodes_expire": time.time() - 60})
        self.report()
        self.assertEqual(self.trends(), {})
        self.assertEqual(self.count("reports"), 1)

    def test_backup_gzipped_and_rotated_seven_plus_four(self):
        self.report()
        srv.backup_db()
        snaps = [name for name in os.listdir(srv.BACKUP_DIR) if name.startswith("agents-")]
        self.assertEqual(len(snaps), 1)
        self.assertTrue(snaps[0].endswith(".db.gz"))
        with srv.gzip.open(os.path.join(srv.BACKUP_DIR, snaps[0])) as packed:
            self.assertEqual(packed.read(16), b"SQLite format 3\x00")
        shutil.rmtree(srv.BACKUP_DIR)
        os.makedirs(srv.BACKUP_DIR)
        day = srv.datetime.date(2026, 9, 28)
        for back in range(60):
            stamp = (day - srv.datetime.timedelta(days=back)).strftime("%Y%m%d")
            for name in ("agents-%s.db" % stamp, "state-%s.json" % stamp, "keep-%s.txt" % stamp):
                with open(os.path.join(srv.BACKUP_DIR, name), "w") as handle:
                    handle.write("x")
        srv.rotate_backups()
        names = os.listdir(srv.BACKUP_DIR)
        self.assertEqual(len([n for n in names if n.startswith("state-")]), srv.BACKUP_DAILY + srv.BACKUP_WEEKLY)
        self.assertEqual(len([n for n in names if n.startswith("keep-")]), 60)
        self.assertIn("agents-20260922.db", names)
        self.assertNotIn("agents-20260921.db", names)

    def test_backup_skipped_without_room_and_logged(self):
        self.report()
        with mock.patch.object(srv.shutil, "disk_usage", return_value=mock.Mock(free=1)):
            srv.backup_db()
        self.assertFalse([n for n in os.listdir(srv.BACKUP_DIR) if n.startswith("agents-")])
        errors = self.client.get("/v1/admin/errors", headers=ADMIN).json()["errors"]
        self.assertEqual([e["kind"] for e in errors], ["backup"])

    def test_backup_finishes_under_constant_writes(self):
        self.report()
        with srv.db() as conn:
            conn.executemany("INSERT INTO errors(ts, agent_id, kind, text) VALUES (?,?,?,?)",
                             [(0, "a", "k", "x" * 2000) for _ in range(3000)])
        stop = srv.threading.Event()

        def writer():
            while not stop.is_set():
                srv._touch_agent(AGENT)
        thread = srv.threading.Thread(target=writer, daemon=True)
        thread.start()
        try:
            started = time.time()
            srv.backup_db()
        finally:
            stop.set()
            thread.join()
        self.assertLess(time.time() - started, 30)
        self.assertTrue([n for n in os.listdir(srv.BACKUP_DIR) if n.endswith(".db.gz")])

    def test_regions_merged_into_one_place(self):
        season(AGENT, "bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee")
        srv.geo_lookup = lambda ip, **_: {"region": "Krasnodar Krai", "city": "Krasnodar", "org": "AS1 T2"}
        self.report(network={"type": "cellular", "operator": "Tele2"})
        self.report(agent_id="bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee", network={"type": "cellular", "operator": "Tele2"},
                    location={"lat": 45.0, "lon": 39.0, "region": "Краснодарский край", "city": "Краснодар"})
        scopes = {scope for _node, scope in self.trends()}
        self.assertEqual(scopes, {"Краснодарский край · Tele2"})
        with srv.db() as conn:
            conn.execute("UPDATE reports SET region='St.-Petersburg'")
            conn.execute("INSERT INTO reports(agent_id, ts, region, operator, network, payload, trusted, partial) "
                         "SELECT agent_id, ts, 'Санкт-Петербург', operator, network, payload, trusted, partial "
                         "FROM reports")
        columns = self.client.get("/v1/admin/matrix", headers=ADMIN).json()["columns"]
        self.assertEqual(list(columns), ["Санкт-Петербург · Tele2"])

    def test_matrix_says_when_cut_and_why_node_is_dead(self):
        season(AGENT)
        self.report(results={"de:443": {"ok": False, "error": "dns-sinkhole"}, "us:443": {"ok": True}})
        self.report(results={"de:443": {"ok": True, "latency": 3, "error": "dns-fail"}, "us:443": {"ok": True}})
        matrix = self.client.get("/v1/admin/matrix", headers=ADMIN).json()
        self.assertFalse(matrix["truncated"])
        self.assertEqual(matrix["reasons"], {"de:443": {"Москва · Wi-Fi": "dns-fail"}})
        self.assertEqual(matrix["matrix"]["de:443"]["Москва · Wi-Fi"], [0, 2])
        reports = self.client.get("/v1/admin/reports", headers=ADMIN).json()["reports"]
        self.assertEqual(reports[1]["dead_reasons"], {"de:443": "dns-sinkhole"})
        with mock.patch.object(srv, "MATRIX_MAX_REPORTS", 1):
            srv._matrix_cache.clear()
            matrix = self.client.get("/v1/admin/matrix?hours=720", headers=ADMIN).json()
        self.assertTrue(matrix["truncated"])
        self.assertGreater(matrix["since"], time.time() - 3600)

    def test_download_settings_chain_refused_by_state(self):
        outbound = {"tag": "proxy", "protocol": "vless", "settings": {"vnext": [{"address": "203.0.113.10"}]},
                    "streamSettings": {"network": "xhttp", "xhttpSettings": {"downloadSettings": {
                        "address": "198.51.100.20", "sockopt": {"dialerProxy": "proxy"}}}}}
        answer = self.client.post("/v1/admin/state", headers=ADMIN,
                                  json={"nodes": [{"key": "x", "outbound": outbound}]})
        self.assertEqual(answer.status_code, 400)
        self.assertIn("unsupported", answer.json()["detail"])
        outbound["streamSettings"]["xhttpSettings"]["downloadSettings"] = {"address": "10.0.0.1"}
        answer = self.client.post("/v1/admin/state", headers=ADMIN,
                                  json={"nodes": [{"key": "x", "outbound": outbound}]})
        self.assertIn("rejected", answer.json()["detail"])

    def test_geo_cached_per_network_and_capped_per_day(self):
        calls = []

        class Answer:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self):
                return b'{"country": "RU", "region": "Moscow", "city": "X", "loc": "55.0,37.0"}'

        srv._geo_day.clear()
        with mock.patch.object(srv.urllib.request, "urlopen", lambda *a, **k: calls.append(a) or Answer()):
            self.assertEqual(GEO_LOOKUP("93.184.216.1")["city"], "X")
            self.assertEqual(GEO_LOOKUP("93.184.216.200")["city"], "X")
            with mock.patch.object(srv._geo_day, "limit", 1):
                self.assertEqual(GEO_LOOKUP("93.184.217.1"), {})
        self.assertEqual(len(calls), 1)

    def test_place_kept_from_card_when_geo_quota_is_out(self):
        answers = [{"region": "Москва", "city": "Москва", "org": "AS1 X"}, {}]
        srv.geo_lookup = lambda ip, **_: answers.pop(0)
        season(AGENT)
        self.direct_report(AGENT, {"de:443": {"ok": True}}, "93.184.216.1")
        self.direct_report(AGENT, {"de:443": {"ok": True}}, "93.184.216.7")
        reports = self.client.get("/v1/admin/reports", headers=ADMIN).json()["reports"]
        self.assertEqual([r["region"] for r in reports], ["Москва", "Москва"])

    def test_flood_from_another_address_erases_only_its_own_reports(self):
        with mock.patch.object(srv, "MAX_REPORTS_PER_AGENT", 4):
            for _ in range(3):
                self.direct_report(AGENT, {"de:443": {"ok": True}}, "93.184.216.1")
            for _ in range(5):
                self.direct_report(AGENT, {"de:443": {"ok": True}}, "198.51.100.5")
        with srv.db() as conn:
            ips = sorted(row[0] for row in conn.execute("SELECT ip FROM reports"))
        self.assertEqual(ips, ["198.51.100.5", "93.184.216.1", "93.184.216.1", "93.184.216.1"])

    def test_many_known_agents_behind_one_address_keep_their_link(self):
        self.assertGreaterEqual(srv.POLLS_PER_KEY, 48)
        self.assertEqual(srv.UNKNOWN_POLLS_PER_KEY, 2)

    def test_prune_runs_on_its_own_timer_and_forgets_old_alert_marks(self):
        with srv.db() as conn:
            conn.execute("INSERT INTO alert_last(key, ts) VALUES ('old', 0), ('new', ?)", (time.time(),))
        srv.prune_old()
        with srv.db() as conn:
            self.assertEqual([row[0] for row in conn.execute("SELECT key FROM alert_last")], ["new"])
        self.assertIn("_prune_loop", dir(srv))


def telegram_refusal(code, description):
    def send(*_args, **_kwargs):
        body = io.BytesIO(json.dumps({"ok": False, "description": description}).encode())
        raise urllib.error.HTTPError("https://api.telegram.org/bot***/sendMessage", code, "x", {}, body)
    return send


class Round7Test(unittest.TestCase):
    """Круг 7: ключи в другом регистре и дубли, echConfigList, тревоги (4096 символов, молчание Telegram, пауза
    только по подтверждённым местам, «мигает», доля неудач в окне), вытеснение, бэкап, миграция мест, гео."""

    setUp = ServerTest.setUp
    tearDown = ServerTest.tearDown
    report = ServerTest.report
    count = HardeningTest.count
    direct_report = Round5Test.direct_report

    def outbound(self, **stream):
        outbound = {"tag": "proxy", "protocol": "vless",
                    "settings": {"vnext": [{"address": "203.0.113.10", "port": 443, "users": [{"id": "u"}]}]}}
        if stream:
            outbound["streamSettings"] = stream
        return outbound

    def sent_texts(self):
        sent = []
        srv.telegram_send = lambda text: sent.append(text) or True
        return sent

    def down(self, node="de:443", scope="R · Op", **extra):
        return dict({"node": node, "scope": scope, "ok": False, "rate": 0.5, "checks": 9}, **extra)

    def state_row(self, node="de:443", scope="R · Op", ok=0):
        with srv.db() as conn:
            conn.execute("INSERT OR REPLACE INTO node_state(node, scope, ok, checks, ok_checks, changed, ts) "
                         "VALUES (?,?,?,?,?,?,?)", (node, scope, ok, 9, 5, 0, time.time()))

    def test_state_refuses_duplicate_and_case_folded_keys(self):
        good = {"key": "k", "outbound": self.outbound(network="tcp")}
        body = json.dumps({"nodes": [good]})
        duplicate = body.replace('"address": "203.0.113.10"', '"address": "203.0.113.10", "address": "127.0.0.1"')
        answer = self.client.post("/v1/admin/state", headers=dict(ADMIN, **{"Content-Type": "application/json"}),
                                  content=duplicate)
        self.assertEqual(answer.status_code, 400)
        self.assertIn("unsupported", answer.json()["detail"])
        for stream in ({"network": "tcp", "Sockopt": {"dialerProxy": "proxy"}},
                       {"network": "tcp", chr(0x17f) + "ockopt": {"dialerProxy": "proxy"}},
                       {"network": "tcp", "sockopt": {"dialerProxy": "a", "dialerproxy": "proxy"}}):
            node = {"key": "k", "outbound": dict(self.outbound(), streamSettings=stream)}
            answer = self.client.post("/v1/admin/state", headers=ADMIN, json={"nodes": [node]})
            self.assertEqual(answer.status_code, 400, stream)
            self.assertEqual(srv.node_refusal(node), "unsupported", stream)
        ech = self.outbound(network="tcp", security="tls", tlsSettings={
            "serverName": "example.com", "echConfigList": "example.com+https://127.0.0.1:18080/dns-query"})
        answer = self.client.post("/v1/admin/state", headers=ADMIN, json={"nodes": [{"key": "k", "outbound": ech}]})
        self.assertIn("rejected", answer.json()["detail"])
        self.assertEqual(self.client.post("/v1/admin/state", headers=ADMIN, content=body).status_code, 200)

    def test_config_hides_nodes_published_before_the_new_rules(self):
        loop = {"key": "loop", "outbound": self.outbound(network="tcp", Sockopt={"dialerProxy": "proxy"})}
        srv.update_state({"nodes": [{"key": "old"}, loop, {"key": "good", "outbound": self.outbound(network="tcp")}]})
        keys = [node.get("key") for node in self.client.get("/v1/config").json()["nodes"]]
        self.assertEqual(keys, ["old", "good"])

    def test_long_digest_fits_telegram_and_rows_go_out(self):
        sent = self.sent_texts()
        for node in range(11):
            srv.notify([self.down("n%02d.%s:443" % (node, "x" * 100), "%s%03d · %s" % ("Я" * 64, place, "Ж" * 48))
                        for place in range(11)], "R · Op", "a", 1)
        self.assertTrue(flush_alerts())
        self.assertEqual(len(sent), 1)
        self.assertLessEqual(len(sent[0]), srv.ALERT_TEXT_MAX)
        self.assertIn(srv.t("…и ещё %d - все тревоги: стенд → Агенты → Центр управления агентами → Стабильность")
                      .split(" %d")[0], sent[0])
        self.assertEqual(self.count("alert_pending"), 0)
        history = self.client.get("/v1/admin/alerts", headers=ADMIN, params={"limit": 1000}).json()["alerts"]
        self.assertEqual(len(history), 11)
        self.assertEqual({a["kind"] for a in history}, {"down"})

    def test_telegram_400_drops_message_4xx_not_retried_and_failures_do_not_use_budget(self):
        calls = []
        refuse = telegram_refusal(400, "Bad Request: can't parse entities")
        srv.notify([self.down()], "R · Op")
        with mock.patch.dict(os.environ, {"TG_BOT_TOKEN": "1:x", "TG_ADMIN": "1"}), \
                mock.patch.object(srv, "telegram_send", TELEGRAM_SEND), \
                mock.patch.object(srv.urllib.request, "urlopen", lambda *a, **k: calls.append(a) or refuse()):
            self.assertFalse(flush_alerts())
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.count("alert_pending"), 0)
        texts = [e["text"] for e in self.client.get("/v1/admin/errors", headers=ADMIN).json()["errors"]]
        self.assertTrue(any("can't parse entities" in text for text in texts), texts)
        self.assertTrue(any("de:443" in text for text in texts), texts)
        self.assertEqual(len(srv._alert_sent), 0)
        with mock.patch.object(srv, "telegram_send", return_value=False), \
                mock.patch.object(srv, "telegram_configured", return_value=True):
            for _ in range(srv.ALERTS_PER_HOUR + 5):
                self.assertFalse(srv.send_alert("x"))
        with mock.patch.object(srv, "telegram_send", return_value=True):
            self.assertTrue(srv.send_alert("y"))

    def test_hour_limit_after_old_400_keeps_alerts(self):
        srv.notify([self.down()], "R · Op")
        srv._telegram_status[0] = 400
        srv._alert_sent.extend([time.time()] * srv.ALERTS_PER_HOUR)
        with mock.patch.dict(os.environ, {"TG_BOT_TOKEN": "1:x", "TG_ADMIN": "1"}):
            self.assertFalse(flush_alerts())
        self.assertEqual(self.count("alert_pending"), 1)

    def test_telegram_error_says_what_to_check_and_repeats_are_one_row(self):
        refuse = telegram_refusal(403, "Forbidden: bot was blocked by the user")
        srv.notify([self.down()], "R · Op")
        with mock.patch.dict(os.environ, {"TG_BOT_TOKEN": "1:x", "TG_ADMIN": "1"}), \
                mock.patch.object(srv, "telegram_send", TELEGRAM_SEND), \
                mock.patch.object(srv.urllib.request, "urlopen", lambda *a, **k: refuse()):
            for minute in range(5):
                flush_alerts(time.time() + minute * 60)
        errors = [e for e in self.client.get("/v1/admin/errors", headers=ADMIN).json()["errors"]
                  if e["kind"] == "telegram"]
        self.assertEqual(len(errors), 1)
        self.assertIn("bot was blocked", errors[0]["text"])
        self.assertIn("TG_BOT_TOKEN", errors[0]["text"])
        self.assertEqual(self.count("alert_pending"), 1)

    def test_queue_outlives_long_telegram_silence_and_says_how_old(self):
        self.state_row()
        srv.notify([self.down()], "R · Op", "a", 2)
        with mock.patch.object(srv, "telegram_send", return_value=False), \
                mock.patch.object(srv, "telegram_configured", return_value=True):
            flush_alerts()
        srv.prune_old(time.time() + 30 * 3600)
        self.assertEqual(self.count("alert_pending"), 1)
        sent = self.sent_texts()
        self.assertTrue(srv.flush_alert_digest(time.time() + 30 * 3600))
        self.assertIn(" · " + srv.t("было %d ч назад") % 30, sent[0])
        self.assertNotIn(") (", sent[0])
        srv.notify([self.down(scope="R · Op2")], "R · Op2", "b", 2)
        self.assertTrue(srv.flush_alert_digest(time.time() + 80 * 3600))
        self.assertIn(" · " + srv.t("было %d дн. назад") % 3, sent[1])

    def test_fake_place_does_not_mute_real_downs(self):
        self.sent_texts()
        srv.notify([self.down("nl-1", "Фейк · X")], "Фейк · X", "attacker", 1, "1.2.3.0/24")
        self.assertTrue(flush_alerts())
        srv.notify([self.down("nl-1", "Москва · МТС")], "Москва · МТС", "real", 2, "5.6.7.0/24")
        self.assertEqual(self.count("alert_pending"), 1)
        self.assertTrue(flush_alerts())
        srv.notify([self.down("nl-1", "Москва · Билайн")], "Москва · Билайн", "real", 2, "5.6.7.0/24")
        self.assertEqual(self.count("alert_pending"), 1)
        self.assertFalse(flush_alerts())
        self.assertEqual(self.count("alert_pending"), 1)
        self.assertTrue(flush_alerts(time.time() + srv.ALERT_COOLDOWN))
        self.assertEqual(self.count("alert_pending"), 0)

    def test_down_undone_before_sending_is_not_sent(self):
        sent = self.sent_texts()
        self.state_row(ok=1)
        srv.notify([self.down()], "R · Op", "a1", 1, "1.2.3.0/24")
        srv.notify([self.down(ok=True)], "R · Op", "a1", 1, "1.2.3.0/24")
        flush_alerts()
        self.assertEqual(sent, [])
        self.assertEqual(self.count("alert_pending"), 0)
        with srv.db() as conn:
            self.assertIsNone(conn.execute("SELECT down_sent FROM node_state").fetchone()[0])

    def test_recovery_everywhere_said_plainly(self):
        sent = self.sent_texts()
        self.state_row()
        srv.notify([self.down()], "R · Op")
        flush_alerts()
        with srv.db() as conn:
            conn.execute("UPDATE node_state SET ok=1")
        srv.notify([self.down(ok=True)], "R · Op")
        flush_alerts()
        self.assertIn(srv.t("(не отвечает в единственном месте, где его проверяют)"), sent[0])
        self.assertIn("(теперь отвечает везде)", sent[1])
        alerts = self.client.get("/v1/admin/alerts", headers=ADMIN).json()["alerts"]
        self.assertEqual([a["kind"] for a in alerts], ["up", "down"])
        self.assertTrue(all("<b>" not in a["text"] and "|down" not in a["text"] and a["node"] == "de:443"
                            for a in alerts))

    def test_flapping_place_told_once_then_muted_for_a_day(self):
        sent = self.sent_texts()
        self.state_row()
        with srv.db() as conn:
            conn.execute("UPDATE node_state SET down_sent=1, d_since=?, d_checks=10, d_ok=6", (time.time(),))
        srv.notify([self.down(scope="Fake · X", flips=5)], "Fake · X", "a", 1)
        self.assertEqual(self.count("alert_pending"), 0)
        srv.notify([self.down(flips=5)], "R · Op", "a", 2)
        srv.notify([self.down()], "R · Op", "a", 2)
        self.assertEqual(self.count("alert_pending"), 1)
        self.assertTrue(flush_alerts())
        self.assertIn(srv.t("%s %s работает с перебоями: %s - отвечал в %d%% проверок за сутки, %s. Пока перебои "
                            "не кончатся (не меньше суток), тревог по нему там не будет, потом придёт итог.")
                      % (srv.t("узел"), "de:443", "R · Op", 60, srv.t("сейчас не отвечает")), sent[0])
        with srv.db() as conn:
            self.assertEqual(conn.execute("SELECT down_sent FROM node_state").fetchone()[0], 1)
        srv.notify([self.down(scope="R · Op3")], "R · Op3", "c", 2)
        self.assertEqual(self.count("alert_pending"), 1)

    def test_noise_in_a_busy_place_is_not_a_down(self):
        with srv.db() as conn:
            events = []
            for ok in [True] * 6 + [False] * 5:
                events.append([e["ok"] for e in srv.update_trends(conn, "R · Op", {"de:443": {"ok": ok}}, {},
                                                                  None, "1.2.3.0/24")])
        self.assertEqual(events, [[]] * 10 + [[False]])
        self.assertLess(srv._decay(7 * 86400), 0.1)

    def test_mobile_agent_at_the_cap_keeps_its_new_report(self):
        with mock.patch.object(srv, "MAX_REPORTS_PER_AGENT", 3), srv.db() as conn:
            for i in range(6):
                srv._insert_report(conn, "agent1", {"n": i}, {}, {}, "10.0.%d.1" % i, 0, 0, time.time() + i)
            ips = [row[0] for row in conn.execute("SELECT ip FROM reports ORDER BY ts")]
        self.assertEqual(ips, ["10.0.3.1", "10.0.4.1", "10.0.5.1"])

    def test_backup_leftovers_removed_and_one_backup_a_day(self):
        self.report()
        os.makedirs(srv.BACKUP_DIR, exist_ok=True)
        for name in ("agents-20260101.db.gz.tmp", "agents-20260101.db.gz.tmp.db", "keep.tmp"):
            with open(os.path.join(srv.BACKUP_DIR, name), "w") as handle:
                handle.write("x")
        srv.backup_db()
        names = sorted(os.listdir(srv.BACKUP_DIR))
        self.assertFalse(srv.backup_due())
        self.assertNotIn("agents-20260101.db.gz.tmp", names)
        self.assertNotIn("agents-20260101.db.gz.tmp.db", names)
        self.assertIn("keep.tmp", names)

    def test_migration_merges_places_named_before_the_region_table(self):
        now = time.time()
        with srv.db() as conn:
            conn.executemany("INSERT INTO node_state(node, scope, ok, checks, ok_checks, changed, ts, w_checks, w_ok, "
                             "down_sent) VALUES (?,?,?,?,?,?,?,?,?,?)",
                             [("de:443", "Krasnodar Krai · Tele2", 0, 10, 4, now - 50, now - 10, 10.0, 4.0, now - 60),
                              ("de:443", "Краснодарский край · Tele2", 1, 5, 5, now - 90, now - 100, 5.0, 5.0, None),
                              ("us:443", "Москва · MTS", 1, 3, 3, 0, now, 3.0, 3.0, None)])
            conn.executemany("INSERT INTO scope_agents(scope, agent_id, ts, net) VALUES (?,?,?,?)",
                             [("Krasnodar Krai · Tele2", "a", now, "1.2.3.0/24"),
                              ("Краснодарский край · Tele2", "a", now - 5, None)])
            conn.execute("INSERT INTO alert_pending(key, node, scope, ok, rate, checks, agent_id, witnesses, ts) "
                         "VALUES ('de:443|Krasnodar Krai · Tele2', 'de:443', 'Krasnodar Krai · Tele2', 0, 0.4, 10, "
                         "'a', 2, ?)", (now,))
            conn.execute("INSERT INTO alert_last(key, ts) VALUES ('de:443|Krasnodar Krai · Tele2|down', ?), "
                         "('fleet_zero', ?)", (now, now))
            conn.execute("PRAGMA user_version = 2")
        srv.init_db()
        srv.init_db()
        with srv.db() as conn:
            rows = [dict(row) for row in conn.execute("SELECT * FROM node_state ORDER BY node")]
            agents = [tuple(row) for row in conn.execute("SELECT scope, agent_id, net FROM scope_agents")]
            pending = [row[0] for row in conn.execute("SELECT key FROM alert_pending")]
            marks = {row[0] for row in conn.execute("SELECT key FROM alert_last")}
            version = conn.execute("PRAGMA user_version").fetchone()[0]
        self.assertEqual(version, 3)
        self.assertEqual([(r["scope"], r["ok"], r["checks"], r["ok_checks"], r["down_sent"]) for r in rows],
                         [("Краснодарский край · Tele2", 0, 15, 9, now - 60), ("Москва · MTS", 1, 3, 3, None)])
        self.assertEqual(agents, [("Краснодарский край · Tele2", "a", "1.2.3.0/24")])
        self.assertEqual(pending, ["de:443|Краснодарский край · Tele2"])
        self.assertEqual(marks, {"de:443|Краснодарский край · Tele2|down", "fleet_zero"})

    def test_place_from_card_for_same_mobile_net_and_unplaced_reports_left_out(self):
        answers = [{"region": "Москва", "city": "Москва", "org": "AS1 X"}, {}, {}]
        srv.geo_lookup = lambda ip, **_: answers.pop(0) if answers else {}
        season(AGENT)
        self.direct_report(AGENT, {"de:443": {"ok": True}}, "93.184.216.1")
        self.direct_report(AGENT, {"de:443": {"ok": True}}, "31.173.80.9")
        self.direct_report(AGENT, {"de:443": {"ok": True}}, "31.173.81.9", network={"type": "wifi"})
        reports = self.client.get("/v1/admin/reports", headers=ADMIN).json()["reports"]
        self.assertEqual([r["region"] for r in reports], ["", "Москва", "Москва"])
        scopes = {n["scope"] for n in self.client.get("/v1/admin/trends", headers=ADMIN).json()["nodes"]}
        self.assertEqual(scopes, {"Москва · MTS"})
        self.assertEqual(list(self.client.get("/v1/admin/matrix", headers=ADMIN).json()["columns"]), ["Москва · MTS"])

    def test_expiry_texts_warn_in_utc_and_expired_told_once(self):
        sent = self.sent_texts()
        now = time.time()
        srv.update_state({"nodes_expire": now + 2.5 * 86400, "nodes_user": "vpnagent_x"})
        self.assertTrue(srv.flush_alert_digest(now))
        self.assertIn("(осталось дней: 3)", sent[0])
        self.assertIn("UTC", sent[0])
        self.assertTrue(srv.flush_alert_digest(now + 3 * 86400))
        self.assertIn("⛔", sent[1])
        history = self.client.get("/v1/admin/alerts", headers=ADMIN).json()["alerts"]
        self.assertEqual([a["kind"] for a in history], ["expired", "expiry"])
        self.assertTrue(all(not a["text"].startswith("VPNCheck") for a in history), history)
        self.assertFalse(srv.flush_alert_digest(now + 3.1 * 86400))
        srv.update_state({"nodes_expire": now - 30 * 86400})
        self.assertFalse(srv.flush_alert_digest(now))

    def test_fleet_zero_counts_networks_not_agent_ids(self):
        ids = ["%08d-0000-4000-8000-000000000000" % i for i in range(4)]
        season(*ids)
        for agent_id in ids:
            self.direct_report(agent_id, {"de:443": {"ok": False}, "us:443": {"ok": False}}, "198.51.100.5")
        with srv.db() as conn:
            self.assertEqual(srv.fleet_zero_status(conn), (1, 1))
        self.assertEqual(self.count("alert_pending"), 0)

    def test_new_agents_counted_for_empty_matrix_and_stability(self):
        self.report()
        self.assertEqual(self.client.get("/v1/admin/matrix", headers=ADMIN).json()["new_agents"], 1)
        self.assertEqual(self.client.get("/v1/admin/trends", headers=ADMIN).json()["new_agents"], 1)

    def test_database_near_the_limit_warns_once_a_day(self):
        sent = self.sent_texts()
        with mock.patch.object(srv, "db_used_bytes", return_value=int(0.9 * srv.db_limit_bytes())):
            self.assertTrue(srv.flush_alert_digest())
            self.assertFalse(srv.flush_alert_digest())
        self.assertIn("90%", sent[0])


class Round8Test(unittest.TestCase):
    """Круг 8: пауза «работает с перебоями» на место и итог после неё, «перестал отвечать» под паузой ждёт, а не
    теряется, вся пачка и отказы Telegram - в истории, тексты чисел и дат, миграция мест."""

    setUp = ServerTest.setUp
    tearDown = ServerTest.tearDown
    down = Round7Test.down
    sent_texts = Round7Test.sent_texts
    count = HardeningTest.count

    def place(self, scope="R · Op", ok=0, ts=None, down_sent=None, nets=("1.1.1.0/24", "2.2.2.0/24")):
        with srv.db() as conn:
            conn.execute("INSERT OR REPLACE INTO node_state(node, scope, ok, checks, ok_checks, changed, ts, "
                         "down_sent, w_checks, w_ok) VALUES (?,?,?,?,?,?,?,?,?,?)",
                         ("de:443", scope, ok, 9, 5, 0, ts or time.time(), down_sent, 9.0, 5.0))
            conn.executemany("INSERT OR REPLACE INTO scope_agents(scope, agent_id, ts, net) VALUES (?,?,?,?)",
                             [(scope, "a%d" % i, time.time(), net) for i, net in enumerate(nets)])

    def after_pause(self, sent, **place):
        later = time.time() + srv.FLAP_MUTE + 120
        self.place(ts=later - 60, **place)
        srv.flush_alert_digest(later)
        self.assertTrue(srv.flush_alert_digest(later + srv.ALERT_BATCH_WAIT + 1))
        return sent[-1]

    def test_flap_then_dead_says_still_down_after_the_pause(self):
        sent = self.sent_texts()
        self.place()
        srv.notify([self.down(flips=5)], "R · Op", "a", 2)
        self.assertTrue(flush_alerts())
        text = self.after_pause(sent)
        self.assertIn(srv.t("🔴 %s %s так и не отвечает после перебоев: %s %s").split(":")[0] % (srv.t("узел"),
                                                                                              "de:443"), text)
        with srv.db() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM alert_last WHERE key LIKE 'mute:%'").fetchone()[0], 0)
            self.assertIsNotNone(conn.execute("SELECT down_sent FROM node_state").fetchone()[0])

    def test_flap_then_back_says_responding_again(self):
        sent = self.sent_texts()
        self.place(down_sent=time.time())
        srv.notify([self.down(flips=5)], "R · Op", "a", 2)
        self.assertTrue(flush_alerts())
        self.assertIn("(теперь отвечает везде)", self.after_pause(sent, ok=1, down_sent=time.time()))

    def test_flap_in_one_place_leaves_other_places_alerting(self):
        self.place()
        self.place("R · Op2")
        srv.notify([self.down(flips=5)], "R · Op", "a", 2)
        srv.notify([self.down(scope="R · Op2")], "R · Op2", "b", 2)
        with srv.db() as conn:
            keys = sorted(row[0] for row in conn.execute("SELECT key FROM alert_pending"))
        self.assertEqual(keys, ["de:443|R · Op2", "flap:de:443|R · Op"])

    def test_flap_in_a_single_witness_place_is_put_off_not_dropped(self):
        self.place(nets=("1.1.1.0/24",))
        srv.notify([self.down(flips=5)], "R · Op", "a", 1)
        self.assertEqual(self.count("alert_pending"), 0)
        later = time.time() + srv.FLAP_MUTE + 120
        self.place(ts=later - 60, nets=("1.1.1.0/24",))
        srv.flush_alert_digest(later)
        with srv.db() as conn:
            row = conn.execute("SELECT key, ok, note, witnesses FROM alert_pending").fetchone()
        self.assertEqual(tuple(row), ("de:443|R · Op", 0, srv.FLAP_END, 1))

    def test_down_elsewhere_goes_out_once_the_node_is_up_everywhere(self):
        sent = self.sent_texts()
        self.place()
        srv.notify([self.down()], "R · Op", "a", 2)
        self.assertTrue(flush_alerts())
        self.place(ok=1, down_sent=time.time())
        srv.notify([self.down(ok=True)], "R · Op", "a", 2)
        self.assertTrue(flush_alerts())
        self.assertIn("(теперь отвечает везде)", sent[1])
        self.place("R · Op2")
        srv.notify([self.down(scope="R · Op2")], "R · Op2", "b", 2)
        self.assertTrue(flush_alerts())
        self.assertIn("R · Op2", sent[2])

    def test_telegram_refusal_and_hidden_lines_are_in_history(self):
        srv.notify([self.down()], "R · Op")
        refuse = telegram_refusal(400, "Bad Request: can't parse entities")
        with mock.patch.dict(os.environ, {"TG_BOT_TOKEN": "1:x", "TG_ADMIN": "1"}), \
                mock.patch.object(srv, "telegram_send", TELEGRAM_SEND), \
                mock.patch.object(srv.urllib.request, "urlopen", lambda *a, **k: refuse()):
            self.assertFalse(flush_alerts())
        history = self.client.get("/v1/admin/alerts", headers=ADMIN).json()["alerts"]
        self.assertEqual(len(history), 1)
        self.assertTrue(history[0]["text"].endswith(srv.t("(в Telegram не ушло)")), history)

    def test_numbers_and_places_read_naturally(self):
        sent = self.sent_texts()
        self.place()
        self.place("R · Op2", ok=1)
        srv.notify([self.down()], "R · Op", "a", 2)
        self.assertTrue(flush_alerts())
        self.assertIn(srv.t("(не отвечает сейчас: мест %d из %d)") % (1, 2), sent[0])

    def test_english_dates_and_carriers(self):
        old, srv.LANG = srv.LANG, "en"
        try:
            moment = datetime.datetime(2026, 10, 1, 1, 25, tzinfo=datetime.timezone.utc).timestamp()
            self.assertEqual(srv._utc(moment), "Oct 1 01:25")
            self.assertEqual(srv._scope_label("Москва · МТС"), "Moscow · MTS")
            self.assertEqual(srv._scope_label("Москва · Wi-Fi · Ростелеком"), "Moscow · Wi-Fi · Rostelecom")
            self.assertEqual(srv._scope_label("Москва · Мой Оператор"), "Moscow · Moy Operator")
            self.assertEqual(srv.t("было %d дн. назад") % 3, "happened 3 days ago")
        finally:
            srv.LANG = old
        self.assertEqual(srv._utc(moment), "01.10 01:25")
        self.assertEqual(srv._scope_label("Москва · МТС"), "Москва · МТС")

    def test_database_warning_gives_the_command(self):
        sent = self.sent_texts()
        with mock.patch.object(srv, "db_used_bytes", return_value=int(0.9 * srv.db_limit_bytes())):
            self.assertTrue(srv.flush_alert_digest())
        self.assertIn("VPNAGENT_MAX_DB_MB=6144 | sudo tee -a /opt/vpnagent/env", sent[0])

    def test_migration_waits_for_region_table_and_keeps_the_larger_flips(self):
        now = time.time()
        with srv.db() as conn:
            conn.executemany("INSERT INTO node_state(node, scope, ok, checks, ok_checks, changed, ts, flips) "
                             "VALUES (?,?,?,?,?,?,?,?)",
                             [("de:443", "Krasnodar Krai · Tele2", 0, 10, 4, now, now, 2),
                              ("de:443", "Краснодарский край · Tele2", 1, 5, 5, now, now - 9, 1)])
            conn.execute("INSERT INTO alert_last(key, ts) VALUES ('mute:de:443|Krasnodar Krai · Tele2', ?)", (now,))
            conn.execute("PRAGMA user_version = 2")
        with mock.patch.dict(srv._regions, {}, clear=True):
            srv.init_db()
            with srv.db() as conn:
                self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], 2)
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM node_state").fetchone()[0], 2)
        srv.init_db()
        with srv.db() as conn:
            self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], 3)
            self.assertEqual([tuple(r) for r in conn.execute("SELECT scope, flips, checks FROM node_state")],
                             [("Краснодарский край · Tele2", 2, 15)])
            self.assertEqual([r[0] for r in conn.execute("SELECT key FROM alert_last")],
                             ["mute:de:443|Краснодарский край · Tele2"])

    def test_old_node_wide_pause_still_honoured_and_ends_with_a_verdict(self):
        sent = self.sent_texts()
        self.place()
        with srv.db() as conn:
            conn.execute("INSERT INTO alert_last(key, ts) VALUES ('mute:de:443', ?)", (time.time(),))
        srv.notify([self.down()], "R · Op", "a", 2)
        self.assertEqual(self.count("alert_pending"), 0)
        self.assertIn("так и не отвечает", self.after_pause(sent))

    def test_pause_goes_on_quietly_while_the_place_still_flaps(self):
        sent = self.sent_texts()
        self.place()
        srv.notify([self.down(flips=5)], "R · Op", "a", 2)
        srv.notify([self.down(scope="R · Op2", flips=5)], "R · Op2", "b", 2)
        self.assertTrue(flush_alerts())
        self.assertEqual(len(sent), 1)
        srv.notify([self.down(scope="R · Op3", flips=5)], "R · Op3", "c", 2)
        self.assertEqual(self.count("alert_pending"), 0)
        later = time.time() + srv.FLAP_MUTE + 120
        self.place(ts=later - 60)
        with srv.db() as conn:
            conn.execute("UPDATE node_state SET changed=?", (later - 600,))
        self.assertFalse(srv.flush_alert_digest(later + srv.ALERT_BATCH_WAIT + 1))
        with srv.db() as conn:
            self.assertTrue(srv._muted(conn, "de:443", "R · Op", later + srv.ALERT_BATCH_WAIT + 1))


class Round8OpsTest(unittest.TestCase):
    """Круг 8, эксплуатация: мигание не путается с двумя падениями, редкие места, гонка отправки, место в базе,
    сироты, места «?», запасное место мобильного агента."""

    setUp = ServerTest.setUp
    tearDown = ServerTest.tearDown
    down = Round7Test.down
    sent_texts = Round7Test.sent_texts
    count = HardeningTest.count
    place = Round8Test.place
    direct_report = Round5Test.direct_report

    def test_two_real_outages_a_day_are_not_flapping(self):
        self.place()
        srv.notify([self.down(flips=4, day_rate=0.5)], "R · Op", "a", 2)
        srv.notify([self.down(scope="R · Op2", flips=6, day_rate=0.9)], "R · Op2", "b", 2)
        with srv.db() as conn:
            keys = sorted(row[0] for row in conn.execute("SELECT key FROM alert_pending"))
            self.assertFalse(srv._muted(conn, "de:443", "R · Op2", time.time()))
        self.assertEqual(keys, ["de:443|R · Op", "de:443|R · Op2"])

    def test_rare_place_needs_two_agents_or_four_in_a_row(self):
        def run(agents):
            with srv.db() as conn:
                conn.execute("DELETE FROM node_state")
                out = []
                for ok, agent in [(True, "a1")] * 4 + [(False, name) for name in agents]:
                    events = srv.update_trends(conn, "R · Op", {"de:443": {"ok": ok}}, {}, None, "", agent)
                    out += [event["ok"] for event in events]
                    conn.execute("UPDATE node_state SET recent='[]'")
            return out

        self.assertEqual(run(["a1", "a1", "a1"]), [])
        self.assertEqual(run(["a1", "a1", "a1", "a1"]), [False])

    def test_two_agents_confirm_a_down_in_a_quiet_place(self):
        with srv.db() as conn:
            for ok, agent in [(True, "a1")] * 3 + [(False, "a1"), (False, "b2"), (False, "b2")]:
                if agent == "a1":
                    conn.execute("UPDATE node_state SET recent='[]'")
                events = srv.update_trends(conn, "R · Op", {"de:443": {"ok": ok}}, {}, None, "", agent)
            self.assertEqual([event["ok"] for event in events], [False])

    def test_recovery_while_the_down_was_being_sent_is_not_lost(self):
        self.place()
        srv.notify([self.down()], "R · Op", "a", 2, "1.1.1.0/24")

        def send(text):
            self.place(ok=1)
            srv.notify([self.down(ok=True)], "R · Op", "b", 2, "2.2.2.0/24")
            return True

        srv.telegram_send = send
        self.assertTrue(flush_alerts())
        with srv.db() as conn:
            rows = [tuple(row) for row in conn.execute("SELECT key, ok FROM alert_pending")]
            self.assertIsNotNone(conn.execute("SELECT down_sent FROM node_state").fetchone()[0])
        self.assertEqual(rows, [("de:443|R · Op", 1)])

    def test_database_warns_once_then_again_only_after_it_shrinks(self):
        sent = self.sent_texts()
        limit = srv.db_limit_bytes()
        with mock.patch.object(srv, "db_used_bytes", return_value=int(0.85 * limit)):
            self.assertTrue(srv.flush_alert_digest())
            self.assertFalse(srv.flush_alert_digest(time.time() + 3 * 86400))
        with mock.patch.object(srv, "db_used_bytes", return_value=int(0.75 * limit)):
            self.assertFalse(srv.flush_alert_digest(time.time() + 4 * 86400))
        with mock.patch.object(srv, "db_used_bytes", return_value=int(0.5 * limit)):
            self.assertFalse(srv.flush_alert_digest(time.time() + 5 * 86400))
        with mock.patch.object(srv, "db_used_bytes", return_value=int(0.85 * limit)):
            self.assertTrue(srv.flush_alert_digest(time.time() + 6 * 86400))
        self.assertEqual(len(sent), 2)

    def test_database_says_when_old_reports_are_already_going(self):
        sent = self.sent_texts()
        srv._evicted[0] = time.time()
        with mock.patch.object(srv, "db_used_bytes", return_value=srv.db_limit_bytes()):
            self.assertTrue(srv.flush_alert_digest())
            self.assertFalse(srv.flush_alert_digest(time.time() + 3600))
        self.assertIn("уже удаляются", sent[0])

    def test_place_nobody_checks_forgets_its_down(self):
        self.place(ts=time.time() - srv.ORPHAN_AFTER - 60, down_sent=time.time() - 3 * 86400)
        srv.flush_alert_digest()
        with srv.db() as conn:
            self.assertIsNone(conn.execute("SELECT down_sent FROM node_state").fetchone()[0])

    def test_unknown_places_with_open_downs_removed_on_start(self):
        self.place("? · MTS", down_sent=time.time())
        self.place("? · Tele2")
        srv.init_db()
        srv.init_db()
        with srv.db() as conn:
            self.assertEqual([row[0] for row in conn.execute("SELECT scope FROM node_state")], ["? · Tele2"])

    def test_mobile_report_without_geo_placed_from_the_agents_own_history(self):
        season(AGENT)
        places = [{"region": "Москва", "city": "Москва"}, {"region": "Тверская область", "city": "Тверь"}]
        srv.geo_lookup = lambda ip, **_: places.pop(0) if places else {}
        mts = {"type": "cellular", "operator": "MTS"}
        tele2 = {"type": "cellular", "operator": "Tele2"}
        self.direct_report(AGENT, {"de:443": {"ok": True}}, "31.173.80.9", network=mts)
        self.direct_report(AGENT, {"de:443": {"ok": True}}, "31.173.90.9", network=tele2)
        self.direct_report(AGENT, {"de:443": {"ok": True}}, "31.173.70.9", network=mts)
        reports = self.client.get("/v1/admin/reports", headers=ADMIN).json()["reports"]
        self.assertEqual([r["region"] for r in reports][0], "Москва")

    def test_known_flapper_goes_quiet_sooner_in_other_places(self):
        self.place()
        self.place("R · Op2")
        srv.notify([self.down(flips=5)], "R · Op", "a", 2)
        srv.notify([self.down(scope="R · Op2", flips=2, day_rate=0.5)], "R · Op2", "b", 2)
        self.place("R · Op3", ok=1, down_sent=time.time() - 14 * 3600)
        srv.notify([self.down(scope="R · Op3", ok=True, flips=2, day_rate=0.5, held=14 * 3600)], "R · Op3", "c", 2)
        with srv.db() as conn:
            self.assertTrue(srv._muted(conn, "de:443", "R · Op2", time.time()))
            self.assertFalse(srv._muted(conn, "de:443", "R · Op3", time.time()))
            keys = sorted(row[0] for row in conn.execute("SELECT key FROM alert_pending"))
        self.assertEqual(keys, ["de:443|R · Op3", "flap:de:443|R · Op", "flap:de:443|R · Op2"])

    def test_single_witness_flap_does_not_quiet_real_places(self):
        self.place(nets=("1.1.1.0/24",))
        self.place("R · Op2")
        srv.notify([self.down(flips=5)], "R · Op", "a", 1)
        srv.notify([self.down(scope="R · Op2", flips=2, day_rate=0.5)], "R · Op2", "b", 2)
        with srv.db() as conn:
            self.assertFalse(srv._muted(conn, "de:443", "R · Op2", time.time()))
            keys = sorted(row[0] for row in conn.execute("SELECT key FROM alert_pending"))
        self.assertEqual(keys, ["de:443|R · Op2"])

    def test_places_coming_back_one_by_one_share_one_line(self):
        sent = self.sent_texts()
        for scope in ("R · Op", "R · Op2", "R · Op3"):
            self.place(scope, ok=1, down_sent=time.time())
        self.place("R · Op3", ok=0, down_sent=time.time())
        srv.notify([self.down(ok=True)], "R · Op", "a", 2)
        self.assertTrue(flush_alerts())
        srv.notify([self.down(scope="R · Op2", ok=True)], "R · Op2", "b", 2)
        self.assertFalse(flush_alerts())
        self.place("R · Op3", ok=1, down_sent=time.time())
        srv.notify([self.down(scope="R · Op3", ok=True)], "R · Op3", "c", 2)
        self.assertTrue(flush_alerts(time.time() + 60))
        self.assertIn("R · Op2, R · Op3", sent[1])
        self.assertIn("(теперь отвечает везде)", sent[1])

    def test_pause_goes_on_while_the_day_is_still_mixed(self):
        self.place()
        srv.notify([self.down(flips=5)], "R · Op", "a", 2)
        self.assertTrue(flush_alerts())
        later = time.time() + srv.FLAP_MUTE + 120
        self.place(ts=later - 60)
        with srv.db() as conn:
            conn.execute("UPDATE node_state SET d_ok=5, d_checks=10")
        srv.flush_alert_digest(later)
        with srv.db() as conn:
            self.assertTrue(srv._muted(conn, "de:443", "R · Op", later))
        self.assertEqual(self.count("alert_pending"), 0)


class Round10ServerTest(unittest.TestCase):
    """Круг 10, надёжность: ipinfo висит, диск кончается, SQLite «disk is full», корень сайта."""

    setUp = ServerTest.setUp
    tearDown = ServerTest.tearDown
    report = ServerTest.report
    sent_texts = Round7Test.sent_texts

    def test_ipinfo_three_failures_pause_it_for_ten_minutes(self):
        timeouts = []

        def hang(*_args, **kwargs):
            timeouts.append(kwargs.get("timeout"))
            raise TimeoutError("timed out")

        srv._geo_day.clear()
        with mock.patch.object(srv.urllib.request, "urlopen", hang):
            for net in range(6):
                self.assertEqual(GEO_LOOKUP("93.184.%d.1" % net), {})
            self.assertEqual(timeouts, [srv.GEO_TIMEOUT] * srv.GEO_FAILS)
            self.assertLessEqual(srv.GEO_TIMEOUT, 3)
            self.assertTrue(srv._geo_breaker.paused())
            self.assertFalse(srv._geo_breaker.paused(time.time() + srv.GEO_PAUSE + 1))
            srv._geo_breaker.until = time.time() - 1
            self.assertEqual(GEO_LOOKUP("93.184.10.1"), {})
        self.assertEqual(len(timeouts), srv.GEO_FAILS + 1)

    def test_ipinfo_success_resets_the_failure_count(self):
        answers = [TimeoutError(), TimeoutError(), io.BytesIO(b'{"city": "X"}'), TimeoutError(), TimeoutError()]

        def reply(*_args, **_kwargs):
            answer = answers.pop(0)
            if isinstance(answer, Exception):
                raise answer
            return answer

        srv._geo_day.clear()
        with mock.patch.object(srv.urllib.request, "urlopen", reply):
            for net in range(5):
                GEO_LOOKUP("93.185.%d.1" % net)
        self.assertFalse(srv._geo_breaker.paused())
        self.assertEqual(answers, [])

    def test_report_is_stored_without_geo_while_ipinfo_is_paused(self):
        srv.geo_lookup = GEO_LOOKUP
        srv._geo_breaker.until = time.time() + srv.GEO_PAUSE
        with mock.patch.object(srv.urllib.request, "urlopen") as opened, \
                mock.patch.object(srv, "client_ip", return_value="93.184.20.1"):
            self.assertEqual(self.report().status_code, 200)
        self.assertEqual(opened.call_count, 0)
        self.assertEqual(len(self.client.get("/v1/admin/reports", headers=ADMIN).json()["reports"]), 1)

    def test_low_disk_refuses_reports_logs_once_and_alerts_once_a_day(self):
        sent = self.sent_texts()
        low = mock.Mock(free=srv.DISK_MIN_FREE - 1)
        with mock.patch.object(srv.shutil, "disk_usage", return_value=low), \
                mock.patch("builtins.print") as printed:
            for _ in range(3):
                self.assertEqual(self.report().status_code, 507)
            self.assertEqual(self.client.get("/v1/config").status_code, 200)
            now = time.time()
            self.assertTrue(srv.check_disk(now))
            self.assertFalse(srv.check_disk(now + 60))
            self.assertFalse(srv.check_disk(now + srv.DISK_ALERT_EVERY - 60))
            disk_lines = [call for call in printed.call_args_list if "disk" in str(call)]
            self.assertTrue(srv.check_disk(now + srv.DISK_ALERT_EVERY + 1))
        self.assertEqual(len(disk_lines), 1, disk_lines)
        self.assertEqual(len(sent), 2)
        self.assertIn(str(srv.DISK_MIN_FREE >> 20), sent[0])
        errors = [e for e in self.client.get("/v1/admin/errors", headers=ADMIN).json()["errors"] if e["kind"] == "disk"]
        self.assertEqual(len(errors), 2)
        self.assertEqual(self.report().status_code, 200)
        self.assertFalse(srv.check_disk(time.time()))

    def test_disk_alert_survives_a_database_that_cannot_write(self):
        sent = self.sent_texts()
        now = time.time()
        full = srv.sqlite3.OperationalError("database or disk is full")
        with mock.patch.object(srv.shutil, "disk_usage", return_value=mock.Mock(free=1)), \
                mock.patch("builtins.print"), mock.patch.object(srv, "db", side_effect=full):
            self.assertTrue(srv.check_disk(now))
            self.assertFalse(srv.check_disk(now + 120))
        self.assertEqual(len(sent), 1)

    def test_sqlite_full_is_507_and_other_sqlite_errors_stay_500(self):
        sent = self.sent_texts()
        full = srv.sqlite3.OperationalError("database or disk is full")
        with mock.patch.object(srv, "_handle_report", side_effect=full), mock.patch("builtins.print"):
            self.assertEqual(self.report().status_code, 507)
            self.assertEqual(self.report().status_code, 507)
        self.assertTrue(srv.check_disk(time.time()))
        self.assertEqual(len(sent), 1)
        client = TestClient(srv.app, raise_server_exceptions=False)
        with mock.patch.object(srv, "_handle_report", side_effect=srv.sqlite3.OperationalError("no such table: x")):
            self.assertEqual(client.post("/v1/report", json={"agent_id": AGENT}).status_code, 500)

    def test_root_redirects_to_admin(self):
        answer = self.client.get("/", follow_redirects=False)
        self.assertEqual(answer.status_code, 302)
        self.assertEqual(answer.headers["location"], "/admin")


class Round13TlsTest(unittest.TestCase):
    """Круг 13: /health говорит, поднят ли TLS-порт; кто из агентов ходит по https; бэкап ключа TLS; тревога,
    когда TLS-порт не поднялся."""

    setUp = ServerTest.setUp
    tearDown = ServerTest.tearDown
    report = ServerTest.report
    sent_texts = Round7Test.sent_texts

    def tls_files(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        key = ec.generate_private_key(ec.SECP256R1())
        key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption())
        cert_pem = b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
        paths = []
        for name, data in (("cert.pem", cert_pem), ("key.pem", key_pem)):
            path = os.path.join(self.tmp, name)
            with open(path, "wb") as handle:
                handle.write(data)
            paths.append(path)
        saved = dict(srv.TLS_STATE)
        self.addCleanup(srv.TLS_STATE.update, saved)
        srv.TLS_STATE.update(cert=paths[0], key=paths[1])
        return cert_pem, key_pem

    def test_health_reports_tls_without_the_pin(self):
        saved = dict(srv.TLS_STATE)
        self.addCleanup(srv.TLS_STATE.update, saved)
        srv.TLS_STATE["on"] = False
        self.assertIs(self.client.get("/health").json()["tls"], False)
        srv.TLS_STATE["on"] = True
        answer = self.client.get("/health").json()
        self.assertIs(answer["tls"], True)
        self.assertNotIn("sha256/", json.dumps(answer))

    def test_https_poll_and_report_mark_the_agent(self):
        self.assertEqual(self.report().status_code, 200)
        agents = self.client.get("/v1/admin/agents", headers=ADMIN).json()["agents"]
        self.assertIsNone(agents[0]["last_tls"])
        self.assertFalse(agents[0]["https"])
        secure = TestClient(srv.app, base_url="https://testserver")
        self.assertEqual(secure.post("/v1/report", json={"agent_id": AGENT, "app_version": "0.12.11",
                                                         "results": {"de:443": {"ok": True}}}).status_code, 200)
        agents = self.client.get("/v1/admin/agents", headers=ADMIN).json()["agents"]
        self.assertIsNotNone(agents[0]["last_tls"])
        self.assertTrue(agents[0]["https"])
        with srv.db() as conn:
            conn.execute("UPDATE agents SET last_tls=NULL")
        self.assertEqual(secure.get("/v1/poll?agent_id=%s" % AGENT).status_code, 200)
        agents = self.client.get("/v1/admin/agents", headers=ADMIN).json()["agents"]
        self.assertTrue(agents[0]["https"])
        with srv.db() as conn:
            conn.execute("UPDATE agents SET last_tls=last_seen - ?", (srv.TLS_SEEN_WINDOW + 60,))
        agents = self.client.get("/v1/admin/agents", headers=ADMIN).json()["agents"]
        self.assertFalse(agents[0]["https"])

    def test_http_poll_does_not_mark_https(self):
        self.report()
        self.assertEqual(self.client.get("/v1/poll?agent_id=%s" % AGENT).status_code, 200)
        with srv.db() as conn:
            self.assertIsNone(conn.execute("SELECT last_tls FROM agents").fetchone()[0])

    def test_tls_backup_is_a_private_tar_with_both_files(self):
        cert_pem, key_pem = self.tls_files()
        self.assertTrue(srv.tls_backup_due())
        self.assertTrue(srv.backup_tls())
        self.assertFalse(srv.tls_backup_due())
        name = "tls-%s.tar" % time.strftime("%Y%m%d")
        path = os.path.join(srv.BACKUP_DIR, name)
        if os.name == "posix":
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        with srv.tarfile.open(path) as archive:
            self.assertEqual(sorted(archive.getnames()), ["cert.pem", "key.pem"])
            self.assertTrue(all(member.isfile() for member in archive.getmembers()))
            self.assertEqual(archive.extractfile("cert.pem").read(), cert_pem)
            self.assertEqual(archive.extractfile("key.pem").read(), key_pem)
        self.assertEqual(os.listdir(srv.BACKUP_DIR), [name])

    def test_tls_backup_rotates_and_skips_without_tls(self):
        srv.TLS_STATE.update(cert="", key="")
        self.assertFalse(srv.tls_backup_due())
        os.makedirs(srv.BACKUP_DIR)
        day = srv.datetime.date(2026, 9, 28)
        for back in range(40):
            stamp = (day - srv.datetime.timedelta(days=back)).strftime("%Y%m%d")
            with open(os.path.join(srv.BACKUP_DIR, "tls-%s.tar" % stamp), "w") as handle:
                handle.write("x")
        with open(os.path.join(srv.BACKUP_DIR, "tls-20260928.tar.tmp"), "w") as handle:
            handle.write("x")
        srv.rotate_backups()
        names = [n for n in os.listdir(srv.BACKUP_DIR) if n.endswith(".tar")]
        self.assertEqual(len(names), srv.BACKUP_DAILY + srv.BACKUP_WEEKLY)
        self.assertTrue(srv.BACKUP_LEFTOVER_RE.match("tls-20260928.tar.tmp"))

    def test_unreadable_tls_file_is_logged_not_raised(self):
        self.tls_files()
        os.remove(srv.TLS_STATE["key"])
        with mock.patch("builtins.print"):
            self.assertFalse(srv.backup_tls())
        errors = self.client.get("/v1/admin/errors", headers=ADMIN).json()["errors"]
        self.assertTrue(any(e["kind"] == "backup" and "tls" in e["text"] for e in errors))

    def test_tls_down_alerts_once_a_day_and_logs(self):
        sent = self.sent_texts()
        self.addCleanup(setattr, srv, "telegram_send", TELEGRAM_SEND)
        now = time.time()
        with mock.patch("builtins.print"):
            self.assertTrue(srv.tls_down("TLS is off: [Errno 13] <denied>", now))
            self.assertFalse(srv.tls_down("TLS is off: again", now + 600))
            self.assertTrue(srv.tls_down("TLS is off: next day", now + srv.TLS_ALERT_EVERY + 1))
        self.assertEqual(len(sent), 2)
        self.assertIn("&lt;denied&gt;", sent[0])
        self.assertFalse(srv.TLS_STATE["on"])
        errors = self.client.get("/v1/admin/errors", headers=ADMIN).json()["errors"]
        self.assertTrue(any(e["kind"] == "tls" for e in errors))
        alerts = self.client.get("/v1/admin/alerts", headers=ADMIN).json()
        self.assertIn("tls_down", json.dumps(alerts))
