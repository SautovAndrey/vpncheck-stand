"""Токены панели и сервера агентов не уходят на чужой хост при редиректе."""
import http.server
import json
import os
import sys
import threading
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from stand import agentapi, safehttp  # noqa: E402
from stand.remnawave import Panel  # noqa: E402


def serve(handler):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class Echo(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"headers": {k.lower(): v for k, v in self.headers.items()}, "path": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class SafeRedirectTest(unittest.TestCase):
    def setUp(self):
        self.other = serve(Echo)
        other_port = self.other.server_address[1]

        class Redirect(Echo):
            def do_GET(self):
                if self.path.startswith("/away"):
                    self.send_response(302)
                    self.send_header("Location", "http://127.0.0.1:%d/landed" % other_port)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                elif self.path.startswith("/near"):
                    self.send_response(302)
                    self.send_header("Location", "/landed")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                else:
                    Echo.do_GET(self)

        self.home = serve(Redirect)
        self.base = "http://127.0.0.1:%d" % self.home.server_address[1]

    def tearDown(self):
        for server in (self.home, self.other):
            server.shutdown()
            server.server_close()

    def fetch(self, path, headers):
        request = urllib.request.Request(self.base + path, headers=headers)
        with safehttp.urlopen(request, timeout=10) as response:
            return json.load(response)

    def test_same_origin_keeps_token(self):
        answer = self.fetch("/near", {"X-Admin-Token": "secret", "Authorization": "Bearer t"})
        self.assertEqual(answer["path"], "/landed")
        self.assertEqual(answer["headers"]["x-admin-token"], "secret")
        self.assertEqual(answer["headers"]["authorization"], "Bearer t")

    def test_other_host_gets_no_secrets(self):
        answer = self.fetch("/away", {"X-Admin-Token": "secret", "Authorization": "Bearer t",
                                      "X-Proxy-Secret": "s", "User-Agent": "vpncheck-stand"})
        self.assertEqual(answer["path"], "/landed")
        for name in ("x-admin-token", "authorization", "x-proxy-secret"):
            self.assertNotIn(name, answer["headers"])
        self.assertEqual(answer["headers"]["user-agent"], "vpncheck-stand")

    def test_clients_use_safe_opener(self):
        server = agentapi.AgentServer(self.base + "/away", "secret")
        answer = server._request("GET", "")
        self.assertNotIn("x-admin-token", answer["headers"])
        panel = Panel(self.base, "token", headers={"X-Proxy-Secret": "s"})
        answer = panel.api("GET", "/away")
        self.assertNotIn("authorization", answer["headers"])
        self.assertNotIn("x-proxy-secret", answer["headers"])

    def test_https_to_http_refused(self):
        handler = safehttp.SafeRedirect()
        request = urllib.request.Request("https://panel.example/api", headers={"Authorization": "Bearer t"})
        with self.assertRaises(urllib.error.HTTPError):
            handler.redirect_request(request, None, 302, "Found", {}, "http://panel.example/api")


if __name__ == "__main__":
    unittest.main()
