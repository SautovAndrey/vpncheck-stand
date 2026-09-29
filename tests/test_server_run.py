"""server/run.py: настоящий uvicorn на свободном порту - таймер недописанного запроса, предел заголовков и
соединений с адреса, keepalive, закрытие после 413 и обрыв посреди тела без трейсбека."""
import asyncio
import base64
import contextlib
import datetime
import hashlib
import json
import os
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "server"))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

import app as srv  # noqa: E402
import run  # noqa: E402
from stand import agentapi  # noqa: E402

TIMEOUT = 1.0
AGENT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def make_cert(folder):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650)).sign(key, hashes.SHA256()))
    cert_path, key_path = os.path.join(folder, "cert.pem"), os.path.join(folder, "key.pem")
    with open(cert_path, "wb") as handle:
        handle.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as handle:
        handle.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    return cert_path, key_path


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def openssl_pin(cert_path):
    openssl = shutil.which("openssl")
    if not openssl:
        return None
    pubkey = subprocess.run([openssl, "x509", "-in", cert_path, "-pubkey", "-noout"], capture_output=True,
                            check=True).stdout
    der = subprocess.run([openssl, "pkey", "-pubin", "-outform", "der"], input=pubkey, capture_output=True,
                         check=True).stdout
    digest = subprocess.run([openssl, "dgst", "-sha256", "-binary"], input=der, capture_output=True,
                            check=True).stdout
    return "sha256/" + subprocess.run([openssl, "base64", "-A"], input=digest, capture_output=True,
                                      check=True).stdout.decode().strip()


def closed_within(sock, seconds):
    sock.settimeout(seconds)
    deadline = time.monotonic() + seconds
    try:
        while time.monotonic() < deadline:
            if sock.recv(65536) == b"":
                return True
    except (ConnectionError, OSError) as exc:
        return not isinstance(exc, socket.timeout)
    return False


class RunServerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="vpncheck-run-")
        cls.saved = {name: getattr(srv, name) for name in ("DB_PATH", "STATE_PATH", "FILES_DIR", "BACKUP_DIR",
                                                           "ADMIN_TOKEN", "geo_lookup")}
        srv.DB_PATH = os.path.join(cls.tmp, "agents.db")
        srv.STATE_PATH = os.path.join(cls.tmp, "state.json")
        srv.FILES_DIR = os.path.join(cls.tmp, "files")
        srv.BACKUP_DIR = os.path.join(cls.tmp, "backups")
        srv.ADMIN_TOKEN = "testtoken"
        srv.geo_lookup = lambda ip, **_: {}

        async def slow():
            await asyncio.sleep(TIMEOUT * 2.5)
            return {"ok": True}

        srv.app.add_api_route("/__slow", slow)
        cls.patch = mock.patch.object(run, "REQUEST_TIMEOUT", TIMEOUT)
        cls.patch.start()
        cls.cert, cls.key = make_cert(cls.tmp)
        cls.tls_port = free_port()
        cls.server, cls.sock = run.build(["--host", "127.0.0.1", "--port", "0", "--log-level", "warning",
                                          "--tls-port", str(cls.tls_port), "--tls-cert", cls.cert,
                                          "--tls-key", cls.key])
        cls.port = cls.sock.getsockname()[1]
        cls.thread = threading.Thread(target=cls.server.run, kwargs={"sockets": [cls.sock]}, daemon=True)
        cls.thread.start()
        deadline = time.monotonic() + 20
        while not cls.server.started and time.monotonic() < deadline:
            time.sleep(0.05)
        assert cls.server.started

    @classmethod
    def tearDownClass(cls):
        cls.server.should_exit = True
        cls.thread.join(10)
        cls.patch.stop()
        srv.app.router.routes[:] = [route for route in srv.app.router.routes if getattr(route, "path", "") != "/__slow"]
        for name, value in cls.saved.items():
            setattr(srv, name, value)
        shutil.rmtree(cls.tmp, True)

    def connect(self):
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=10)
        self.addCleanup(sock.close)
        return sock

    def ask(self, data, sock=None):
        sock = sock or self.connect()
        sock.sendall(data)
        sock.settimeout(10)
        answer = b""
        while b"\r\n\r\n" not in answer:
            chunk = sock.recv(65536)
            if not chunk:
                break
            answer += chunk
        return answer.split(b"\r\n", 1)[0].decode("latin-1"), sock

    def connect_tls(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection(("127.0.0.1", self.tls_port), timeout=10)
        self.addCleanup(raw.close)
        sock = context.wrap_socket(raw)
        self.addCleanup(sock.close)
        return sock

    def test_tls_port_serves_the_same_app_with_the_pinned_key(self):
        sock = self.connect_tls()
        self.assertGreaterEqual(sock.version(), "TLSv1.2")
        pin = agentapi.spki_pin(sock.getpeercert(binary_form=True))
        with open(self.cert, "rb") as handle:
            self.assertEqual(pin, agentapi.spki_pin(handle.read()))
        expected = openssl_pin(self.cert)
        if expected:
            self.assertEqual(pin, expected)
        status, _ = self.ask(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n", sock)
        self.assertIn(" 200 ", status)
        status, _ = self.ask(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n")
        self.assertIn(" 200 ", status)

    def test_tls_silent_connection_is_closed(self):
        self.assertTrue(closed_within(self.connect_tls(), TIMEOUT * 4))

    def test_stand_client_checks_the_pin(self):
        with open(self.cert, "rb") as handle:
            pin = agentapi.spki_pin(handle.read())
        base = "http://127.0.0.1:%d" % self.port
        good = agentapi.AgentServer(base, "testtoken", tls={"port": self.tls_port, "pin": pin})
        self.assertEqual(good.base, "https://127.0.0.1:%d" % self.tls_port)
        self.assertTrue(good.health()["ok"])
        wrong = "sha256/" + base64.b64encode(hashlib.sha256(b"other").digest()).decode()
        bad = agentapi.AgentServer(base, "testtoken", tls={"port": self.tls_port, "pin": wrong})
        with self.assertRaisesRegex(RuntimeError, "сертификат сервера не совпадает"):
            bad.health()

    def test_broken_certificate_leaves_plain_http(self):
        server, sock = run.build(["--host", "127.0.0.1", "--port", "0", "--tls-port", str(free_port()),
                                  "--tls-cert", os.path.join(self.tmp, "missing.pem"), "--tls-key", self.key])
        sock.close()
        self.assertIsNone(server.tls)
        self.assertTrue(server.tls_error)
        self.assertEqual(server.tls_files[1], os.path.abspath(self.key))
        down = []
        with mock.patch.object(srv, "tls_down", side_effect=down.append):
            server.tls_failed(server.tls_error)
            deadline = time.monotonic() + 5
            while not down and time.monotonic() < deadline:
                time.sleep(0.02)
        self.assertIn("plain HTTP only", down[0])

    def test_broken_tls_port_raises_the_alert_on_startup_and_health_says_no_tls(self):
        busy = socket.socket()
        busy.bind(("127.0.0.1", 0))
        busy.listen()
        self.addCleanup(busy.close)
        down = []
        with mock.patch.object(srv, "tls_down", side_effect=down.append):
            server, sock = run.build(["--host", "127.0.0.1", "--port", "0", "--log-level", "warning",
                                      "--tls-port", str(busy.getsockname()[1]), "--tls-cert", self.cert,
                                      "--tls-key", self.key])
            port = sock.getsockname()[1]
            thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
            thread.start()
            try:
                deadline = time.monotonic() + 20
                while not (server.started and down) and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertTrue(down)
                self.assertIn("plain HTTP only", down[0])
                srv._health["ts"] = 0.0
                with socket.create_connection(("127.0.0.1", port), timeout=10) as plain:
                    status, _ = self.ask(b"GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", plain)
                    self.assertIn(" 200 ", status)
                self.assertFalse(srv.TLS_STATE["on"])
            finally:
                server.should_exit = True
                thread.join(10)
                srv.TLS_STATE["on"] = True

    def test_health_says_tls_when_the_port_is_up(self):
        self.assertTrue(srv.TLS_STATE["on"])
        self.assertEqual(srv.TLS_STATE["key"], os.path.abspath(self.key))
        sock = self.connect_tls()
        sock.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        answer = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            answer += chunk
        self.assertIs(json.loads(answer.split(b"\r\n\r\n", 1)[1])["tls"], True)

    def test_pending_tls_handshakes_count_against_the_address_cap(self):
        with mock.patch.object(run, "LOOPBACK", ()), mock.patch.object(run, "MAX_CONN_PER_IP", 3):
            raw = []
            for _ in range(5):
                sock = socket.create_connection(("127.0.0.1", self.tls_port), timeout=10)
                self.addCleanup(sock.close)
                raw.append(sock)
            self.assertTrue(closed_within(raw[3], 2))
            self.assertTrue(closed_within(raw[4], 2))
            self.assertEqual(run.GuardedProtocol.per_ip, {"127.0.0.1": 3})
            for sock in raw[:3]:
                sock.close()
            deadline = time.monotonic() + 3
            while run.GuardedProtocol.per_ip and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertEqual(run.GuardedProtocol.per_ip, {})
            secure = self.connect_tls()
            status, _ = self.ask(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n", secure)
            self.assertIn(" 200 ", status)
            self.assertEqual(run.GuardedProtocol.per_ip, {"127.0.0.1": 1})
            others = [self.connect_tls() for _ in range(2)]
            extra = socket.create_connection(("127.0.0.1", self.tls_port), timeout=10)
            self.addCleanup(extra.close)
            self.assertTrue(closed_within(extra, 2))
            for sock in [secure] + others:
                sock.close()
            deadline = time.monotonic() + 3
            while run.GuardedProtocol.per_ip and time.monotonic() < deadline:
                time.sleep(0.05)
        self.assertEqual(run.GuardedProtocol.per_ip, {})

    def test_failed_handshake_frees_the_slot(self):
        with mock.patch.object(run, "LOOPBACK", ()):
            sock = socket.create_connection(("127.0.0.1", self.tls_port), timeout=10)
            self.addCleanup(sock.close)
            sock.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            self.assertTrue(closed_within(sock, 3))
            deadline = time.monotonic() + 3
            while run.GuardedProtocol.per_ip and time.monotonic() < deadline:
                time.sleep(0.05)
        self.assertEqual(run.GuardedProtocol.per_ip, {})

    def test_request_sent_together_with_the_handshake_is_served(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        tls = context.wrap_bio(incoming, outgoing)
        raw = socket.create_connection(("127.0.0.1", self.tls_port), timeout=10)
        self.addCleanup(raw.close)
        while True:
            try:
                tls.do_handshake()
                break
            except ssl.SSLWantReadError:
                raw.sendall(outgoing.read())
                incoming.write(raw.recv(65536))
        tls.write(b"GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        raw.sendall(outgoing.read())
        answer = b""
        while b"\r\n\r\n" not in answer:
            data = raw.recv(65536)
            if not data:
                break
            incoming.write(data)
            with contextlib.suppress(ssl.SSLWantReadError):
                while True:
                    piece = tls.read(65536)
                    if not piece:
                        break
                    answer += piece
        self.assertIn(b" 200 ", answer.split(b"\r\n", 1)[0])

    def test_complete_requests_pass_and_sockets_have_keepalive(self):
        status, sock = self.ask(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n")
        self.assertIn(" 200 ", status)
        status, _ = self.ask(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n", sock)
        self.assertIn(" 200 ", status)
        self.assertEqual(self.sock.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE) != 0, True)
        if hasattr(socket, "TCP_KEEPIDLE") and sys.platform.startswith("linux"):
            self.assertEqual(self.sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE), run.KEEPALIVE_IDLE)

    def test_silent_and_unfinished_connections_are_closed(self):
        silent = self.connect()
        half_head = self.connect()
        half_head.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\n")
        half_body = self.connect()
        half_body.sendall(b"POST /v1/location HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
                          b"Content-Length: 100\r\n\r\n{\"agent_id\"")
        for sock in (silent, half_head, half_body):
            self.assertTrue(closed_within(sock, TIMEOUT * 4))

    def test_byte_by_byte_headers_do_not_keep_the_connection(self):
        sock = self.connect()
        line = b"GET /health HTTP/1.1\r\nHost: x\r\nX-Pad: " + b"a" * 200
        started = time.monotonic()
        closed = False
        for byte in line:
            try:
                sock.sendall(bytes([byte]))
            except OSError:
                closed = True
                break
            time.sleep(0.05)
            if time.monotonic() - started > TIMEOUT * 4:
                break
        self.assertTrue(closed or closed_within(sock, TIMEOUT * 2))

    def test_long_running_complete_request_is_not_cut(self):
        status, _ = self.ask(b"GET /__slow HTTP/1.1\r\nHost: x\r\n\r\n")
        self.assertIn(" 200 ", status)

    def test_pipelined_request_behind_a_long_one_is_not_cut(self):
        sock = self.connect()
        sock.sendall(b"GET /__slow HTTP/1.1\r\nHost: x\r\n\r\n")
        time.sleep(TIMEOUT * 0.5)
        sock.sendall(b"GET /health HTTP/1.1\r\n")
        status, _ = self.ask(b"", sock)
        self.assertIn(" 200 ", status)

    def test_peer_key_groups_ipv6_by_64(self):
        self.assertEqual(run.peer_key("2001:db8:1:2::5"), run.peer_key("2001:db8:1:2:ffff::9"))
        self.assertNotEqual(run.peer_key("2001:db8:1:2::5"), run.peer_key("2001:db8:1:3::5"))
        self.assertEqual(run.peer_key("::ffff:203.0.113.7"), "203.0.113.7")
        self.assertEqual(run.peer_key("203.0.113.7"), "203.0.113.7")

    def test_headers_over_64_kb_get_431(self):
        status, _ = self.ask(b"GET /health HTTP/1.1\r\nHost: x\r\nX-Big: " + b"a" * 60000 + b"\r\n\r\n")
        self.assertIn(" 200 ", status)
        sock = self.connect()
        try:
            sock.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\nX-Big: " + b"a" * (run.MAX_HEAD_BYTES + 10) + b"\r\n\r\n")
        except OSError:
            pass
        status, _ = self.ask(b"", sock)
        self.assertIn(" 431 ", status)
        self.assertTrue(closed_within(sock, 2))

    def test_connections_per_address_are_capped(self):
        with mock.patch.object(run, "LOOPBACK", ()), mock.patch.object(run, "MAX_CONN_PER_IP", 3):
            socks = [self.connect() for _ in range(4)]
            self.assertTrue(closed_within(socks[3], 2))
            status, _ = self.ask(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n", socks[0])
            self.assertIn(" 200 ", status)
            for sock in socks:
                sock.close()
            time.sleep(0.3)
        self.assertEqual(run.GuardedProtocol.per_ip, {})

    def test_chunked_body_over_the_limit_gets_413_and_close(self):
        chunk = b"a" * 8192
        status, sock = self.ask(b"POST /v1/location HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
                                + b"%x\r\n%s\r\n" % (len(chunk), chunk))
        self.assertIn(" 413 ", status)
        self.assertTrue(closed_within(sock, 2))

    def test_disconnect_mid_body_is_one_line_without_traceback(self):
        body = json.dumps({"agent_id": AGENT, "results": {}}).encode()
        with mock.patch("builtins.print") as printed, self.assertNoLogs("uvicorn.error", level="ERROR"):
            sock = self.connect()
            sock.sendall(b"POST /v1/report HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
                         b"Content-Length: %d\r\n\r\n" % (len(body) + 100) + body)
            time.sleep(0.2)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            sock.close()
            deadline = time.monotonic() + 5
            while not printed.call_count and time.monotonic() < deadline:
                time.sleep(0.05)
        lines = [str(call) for call in printed.call_args_list]
        self.assertEqual(len(lines), 1, lines)
        self.assertIn("disconnected mid-request", lines[0])


if __name__ == "__main__":
    unittest.main()
