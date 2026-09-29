"""Клиент API Remnawave против поддельной панели: старые (uuid) и новые (числовой id) версии."""
import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from stand import remnawave, storage, subscription  # noqa: E402

TOKEN = "test-token"
VLESS = ("vless://11111111-2222-3333-4444-555555555555@203.0.113.7:443?type=tcp&security=reality"
         "&pbk=PUBKEY&fp=chrome&sni=example.com&sid=abcd12&flow=xtls-rprx-vision#Germany")


class FakePanel(BaseHTTPRequestHandler):
    """Минимальная панель: сквады, создание/удаление пользователя, подписка."""
    numeric_ids = False
    users = {}
    calls = []

    def log_message(self, *_args):
        pass

    def reply(self, code, payload):
        body = json.dumps(payload).encode() if not isinstance(payload, bytes) else payload
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def authorized(self):
        if self.headers.get("Authorization") != "Bearer %s" % TOKEN:
            self.reply(401, {"message": "Unauthorized"})
            return False
        return True

    def do_GET(self):  # noqa: N802
        FakePanel.calls.append(("GET", self.path))
        if self.path.startswith("/api/sub/"):
            return self.reply(200, VLESS.encode())
        if not self.authorized():
            return None
        if self.path == "/api/internal-squads":
            return self.reply(200, {"response": {"internalSquads": [{"uuid": "sq-1", "name": "Default"}]}})
        return self.reply(404, {"message": "not found"})

    def do_POST(self):  # noqa: N802
        FakePanel.calls.append(("POST", self.path))
        if not self.authorized():
            return None
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        ident = len(FakePanel.users) + 100
        user = {"shortUuid": "short%d" % ident, "username": body["username"],
                "subscriptionUrl": "http://127.0.0.1:%d/api/sub/short%d" % (self.server.server_port, ident)}
        if FakePanel.numeric_ids:
            user["id"] = ident
        else:
            user["uuid"] = "uuid-%d" % ident
        FakePanel.users[str(user.get("id") or user.get("uuid"))] = body
        return self.reply(201, {"response": user})

    def do_DELETE(self):  # noqa: N802
        FakePanel.calls.append(("DELETE", self.path))
        if not self.authorized():
            return None
        ident = self.path.rsplit("/", 1)[-1]
        if FakePanel.users.pop(ident, None) is None:
            return self.reply(400, {"message": "no such user %s" % ident})
        return self.reply(200, {"response": {"isDeleted": True}})


class RemnawaveTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), FakePanel)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.url = "http://127.0.0.1:%d" % cls.server.server_port

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        FakePanel.users, FakePanel.calls, FakePanel.numeric_ids = {}, [], False

    def panel_config(self, token=TOKEN):
        return {"url": self.url, "token": token}

    def test_squads(self):
        self.assertEqual(subscription.list_squads(self.panel_config()), ["Default"])

    def test_full_cycle_old_panel_with_uuid(self):
        targets, release = subscription.from_panel(self.panel_config(), "Default", only_443=False)
        self.assertEqual([t["address"] for t in targets], ["203.0.113.7"])
        self.assertEqual(len(FakePanel.users), 1)
        release()
        self.assertEqual(FakePanel.users, {})

    def test_full_cycle_new_panel_with_numeric_id(self):
        FakePanel.numeric_ids = True
        targets, release = subscription.from_panel(self.panel_config(), "Default", only_443=False)
        self.assertEqual(len(targets), 1)
        release()
        self.assertEqual(FakePanel.users, {})
        self.assertIn(("DELETE", "/api/users/100"), FakePanel.calls)

    def test_agent_user_is_kept_and_limited(self):
        _targets, release = subscription.from_panel(self.panel_config(), "Default", only_443=False, limit=(500, 7))
        release()
        self.assertEqual(len(FakePanel.users), 1)
        body = next(iter(FakePanel.users.values()))
        self.assertEqual(body["trafficLimitBytes"], 500 * 1024 * 1024)
        self.assertTrue(body["username"].startswith("vpnagent_"))
        self.assertIsNotNone(subscription.LAST_AGENT_USER["expire"])

    def test_agent_user_keeps_window_subscription(self):
        old = subscription.LAST_RAW
        try:
            subscription.LAST_RAW = b"window run"
            _targets, release = subscription.from_panel(self.panel_config(), "Default", only_443=False,
                                                        limit=(500, 7))
            self.assertEqual(subscription.LAST_RAW, b"window run")
            self.assertTrue(release.raw)
            _targets, release = subscription.from_panel(self.panel_config(), "Default", only_443=False)
            self.assertEqual(subscription.LAST_RAW, release.raw)
            release()
        finally:
            subscription.LAST_RAW = old

    def test_wrong_token_explained(self):
        with self.assertRaises(remnawave.PanelError) as ctx:
            subscription.list_squads(self.panel_config("wrong"))
        self.assertIn("токен", str(ctx.exception))

    def test_unknown_squad_lists_existing(self):
        with self.assertRaises(remnawave.PanelError) as ctx:
            subscription.from_panel(self.panel_config(), "Nope")
        self.assertIn("Default", str(ctx.exception))
        self.assertEqual(FakePanel.users, {})

    def test_token_with_newline_rejected_early(self):
        with self.assertRaises(remnawave.PanelError):
            remnawave.Panel(self.url, "abc\ndef")

    def test_user_id_both_formats(self):
        self.assertEqual(remnawave.user_id({"uuid": "u-1"}), "u-1")
        self.assertEqual(remnawave.user_id({"id": 45423}), "45423")
        self.assertIsNone(remnawave.user_id({}))


    def test_release_carries_its_own_agent_user(self):
        _t1, first = subscription.from_panel(self.panel_config(), "Default", only_443=False, limit=(500, 7))
        _t2, second = subscription.from_panel(self.panel_config(), "Default", only_443=False, limit=(500, 7))
        self.assertNotEqual(first.agent_user["uuid"], second.agent_user["uuid"])
        self.assertEqual(subscription.LAST_AGENT_USER, second.agent_user)
        _t3, window = subscription.from_panel(self.panel_config(), "Default", only_443=False)
        self.assertIsNone(window.agent_user)
        window()

    def test_agent_user_removed_when_subscription_empty(self):
        with mock.patch.object(subscription, "parse_any", return_value=[]):
            with self.assertRaises(ValueError):
                subscription.from_panel(self.panel_config(), "Default", only_443=False, limit=(500, 7))
        self.assertEqual(FakePanel.users, {})

    def test_subscription_link_must_be_http(self):
        panel = remnawave.Panel.from_config(self.panel_config())
        for url in ("file:///etc/passwd", "ftp://x/y"):
            with self.assertRaises(remnawave.PanelError):
                panel.fetch_subscription(url)

class ConnectionsStorageTest(unittest.TestCase):
    def setUp(self):
        self.saved = storage.CONNECTIONS_PATH
        storage.CONNECTIONS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_connections_test.json")

    def tearDown(self):
        if os.path.exists(storage.CONNECTIONS_PATH):
            os.remove(storage.CONNECTIONS_PATH)
        storage.CONNECTIONS_PATH = self.saved

    def test_roundtrip_and_defaults(self):
        self.assertEqual(storage.load_connections(), {"panels": {}, "probe": {}})
        storage.save_connections({"panels": {"p": {"url": "u", "token": "t"}}, "probe": {"host": "h"}})
        data = storage.load_connections()
        self.assertEqual(data["panels"]["p"]["token"], "t")
        self.assertTrue(storage.has_probe(data))
        self.assertFalse(storage.has_probe({"probe": {}}))


if __name__ == "__main__":
    unittest.main()
