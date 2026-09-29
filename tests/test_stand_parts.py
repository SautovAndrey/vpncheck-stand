"""Части стенда без телефона и сети: переводчик сетевых ошибок, выгрузка APK потоком, узлы с цепочкой
dialerProxy для агентов, проверка узлов через xray телефона с поддельным adb, загрузка узлов и потоки run_check."""
import json
import os
import shutil
import socket
import ssl
import sys
import tempfile
import unittest
import urllib.error
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import run_check  # noqa: E402
from stand import agentapi, dcprobe, errors, multiphone, xray  # noqa: E402
from stand.remnawave import PanelError  # noqa: E402

FRAGMENT = {"tag": "fragment", "protocol": "freedom", "settings": {"fragment": {"packets": "tlshello"}}}


class ExplainTest(unittest.TestCase):
    def test_kinds(self):
        cases = [
            (urllib.error.URLError(ssl.SSLError(1, "[SSL: UNEXPECTED_EOF_WHILE_READING] EOF")), "HTTPS"),
            (urllib.error.URLError(ConnectionRefusedError(10061, "refused")), "отклонено"),
            (urllib.error.URLError(socket.gaierror(11001, "getaddrinfo failed")), "адрес не найден"),
            (RuntimeError('HTTP 401 /v1/admin/agents: {"detail":"нет доступа"}'), "токен"),
            ("<urlopen error timed out>", "8"),
            (socket.timeout("timed out"), "нет ответа за 8 с"),
            (PanelError("панель не пустила (HTTP 401): проверьте API-токен"), "API-токен панели"),
            ("the panel refused (HTTP 401): check the API token", "API-токен панели"),
        ]
        for error, part in cases:
            self.assertIn(part, errors.explain(error, timeout=8), error)

    def test_http_status_decides_not_the_body(self):
        self.assertEqual(errors.kind(RuntimeError('HTTP 400 /v1/admin/state: {"detail": "tls only"}')), "")
        self.assertEqual(errors.kind(RuntimeError('HTTP 401 /v1/admin/state: {"detail": "ssl"}')), "token")
        self.assertEqual(errors.kind(urllib.error.HTTPError("http://x", 502, "tls proxy", {}, None)), "")

    def test_unknown_is_empty(self):
        self.assertEqual(errors.explain(ValueError("подписка пуста")), "")
        self.assertEqual(errors.explain(""), "")


class UploadTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "agent.apk")
        with open(self.path, "wb") as handle:
            handle.write(b"PK" + b"x" * (3 * agentapi.UPLOAD_CHUNK + 5))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_streams_multipart_with_length(self):
        sent = {}

        def fake_open(request, timeout=30):
            chunks = list(request.data)
            sent["body"] = b"".join(chunks)
            sent["chunks"] = max(len(chunk) for chunk in chunks)
            sent["length"] = int(request.get_header("Content-length"))
            response = mock.MagicMock()
            response.__enter__.return_value = response
            response.read.return_value = b'{"ok": true}'
            return response

        server = agentapi.AgentServer("https://example.invalid", "token")
        with mock.patch.object(agentapi.safehttp, "urlopen", side_effect=fake_open), \
                mock.patch.object(agentapi.json, "load", return_value={"ok": True}):
            self.assertEqual(server.upload(self.path), {"ok": True})
        self.assertEqual(sent["length"], len(sent["body"]))
        self.assertLessEqual(sent["chunks"], agentapi.UPLOAD_CHUNK)
        self.assertIn(b'filename="agent.apk"', sent["body"])
        with open(self.path, "rb") as handle:
            self.assertIn(handle.read(), sent["body"])

    def test_too_big_refused_before_reading(self):
        server = agentapi.AgentServer("https://example.invalid", "token")
        with mock.patch.object(agentapi.os.path, "getsize", return_value=agentapi.MAX_UPLOAD_BYTES + 1), \
                mock.patch.object(agentapi.safehttp, "urlopen") as opened, \
                self.assertRaises(RuntimeError):
            server.upload(self.path)
        opened.assert_not_called()

    def test_nodes_carry_extra_outbounds(self):
        server = agentapi.AgentServer("https://example.invalid", "token")
        targets = [{"key": "a:443", "location": "DE", "outbound": {"tag": "proxy"}, "extra_outbounds": [FRAGMENT]},
                   {"key": "b:443", "location": "DE", "outbound": {"tag": "proxy"}}]
        with mock.patch.object(server, "set_state", side_effect=lambda **patch: patch) as sent:
            server.set_nodes(targets)
        nodes = sent.call_args.kwargs["nodes"]
        self.assertEqual(nodes[0]["extra_outbounds"], [FRAGMENT])
        self.assertNotIn("extra_outbounds", nodes[1])


class PhoneXrayTest(unittest.TestCase):
    def setUp(self):
        self.adb = mock.Mock()
        self.phone = xray.PhoneXray(self.adb)
        patcher = mock.patch.object(xray.time, "sleep")
        patcher.start()
        self.addCleanup(patcher.stop)

    def configs(self):
        return [json.loads(call.kwargs["input_text"]) for call in self.adb.run.call_args_list
                if call.kwargs.get("input_text")]

    def test_check_targets_with_chain_and_retry(self):
        targets = [{"key": "a:443", "outbound": {"tag": "proxy"}, "extra_outbounds": [FRAGMENT]},
                   {"key": "b:443", "outbound": {"tag": "proxy"}}]
        answers = {}

        def exit_ip(port, timeout=15, url=xray.IP_URL):
            answers[port] = answers.get(port, 0) + 1
            return "1.2.3.4" if port in (xray.CHECK_PORT, xray.NET_PORT) or port >= xray.RETRY_PORT else ""

        seen = []
        with mock.patch.object(xray, "exit_ip_via_socks", side_effect=exit_ip), \
                mock.patch.object(xray, "latency_via_socks", return_value=120):
            results = self.phone.check_targets(targets, on_result=lambda key, value: seen.append((key, value)))
        self.assertEqual(results["a:443"], {"exit_ip": "1.2.3.4", "latency": 120})
        self.assertEqual(results["b:443"]["exit_ip"], "1.2.3.4")
        self.assertIn(("b:443", {"exit_ip": "", "latency": None, "retrying": True}), seen)
        first = self.configs()[0]
        self.assertEqual([item.get("tag") for item in first["outbounds"]], ["proxy", "fragment", "direct"])

    def run_with_net(self, targets, net_answers, back=("", False), retry_ok=None, whitelist=False,
                     reachable=False, stop=None, batch=4):
        """Все узлы молчат в первом проходе; прямой интернет на NET_PORT отвечает по net_answers (ipify, запасной
        сервис молчит), ожидание сети возвращает back, retry_ok(номер попытки, порт) - ответ узла в перепроверке."""
        net = iter(net_answers)
        attempts = {"n": 0}

        def exit_ip(port, timeout=15, url=xray.IP_URL):
            if port == xray.NET_PORT:
                return next(net, "") if url == xray.IP_URL else ""
            if port >= xray.RETRY_PORT:
                return (retry_ok or (lambda _n, _p: ""))(attempts["n"], port)
            return ""

        seen = []
        original = self.phone._check_chunk

        def counted(chunk, base_port, *args, **kwargs):
            if base_port == xray.RETRY_PORT:
                attempts["n"] += 1
            return original(chunk, base_port, *args, **kwargs)

        with mock.patch.object(xray, "exit_ip_via_socks", side_effect=exit_ip), \
                mock.patch.object(xray, "latency_via_socks", return_value=150), \
                mock.patch.object(xray, "whitelist_reachable", return_value=reachable), \
                mock.patch.object(self.phone, "wait_for_internet", return_value=back) as waited, \
                mock.patch.object(self.phone, "_check_chunk", side_effect=counted):
            results = self.phone.check_targets(targets, on_result=lambda key, value: seen.append((key, value)),
                                               whitelist=whitelist, should_stop=stop, batch=batch)
        return results, seen, waited, attempts["n"]

    def targets(self, count):
        return [{"key": "n%d:443" % i, "outbound": {"tag": "proxy"}} for i in range(count)]

    def test_net_lost_during_retry_is_unchecked_not_dead(self):
        results, seen, waited, attempts = self.run_with_net(self.targets(6), ["198.51.100.7", ""])
        self.assertEqual(waited.call_count, 1)
        self.assertEqual(attempts, 1)
        for i in range(6):
            self.assertEqual(results["n%d:443" % i], xray.UNCHECKED_NET)
        final = [value for _key, value in seen if not value.get("retrying")]
        self.assertEqual(len(final), 6)
        self.assertTrue(all(value.get("unchecked") == "net" for value in final))

    def test_net_lost_before_retry_skips_retry(self):
        results, _seen, waited, attempts = self.run_with_net(self.targets(3), [""])
        self.assertEqual(waited.call_count, 1)
        self.assertEqual(attempts, 0)
        self.assertTrue(all(value.get("unchecked") == "net" for value in results.values()))

    def test_net_back_repeats_batch(self):
        results, _seen, waited, attempts = self.run_with_net(
            self.targets(2), ["198.51.100.7", ""], back=("198.51.100.7", False),
            retry_ok=lambda attempt, _port: "203.0.113.4" if attempt >= 2 else "")
        self.assertEqual(waited.call_count, 1)
        self.assertEqual(attempts, 2)
        self.assertEqual(results["n0:443"], {"exit_ip": "203.0.113.4", "latency": 150})
        self.assertEqual(results["n1:443"]["exit_ip"], "203.0.113.4")

    def test_dead_with_net_up_stays_dead(self):
        results, seen, waited, _attempts = self.run_with_net(self.targets(5), ["198.51.100.7"] * 5)
        waited.assert_not_called()
        self.assertTrue(all(value == {"exit_ip": "", "latency": None} for value in results.values()))
        self.assertFalse(any(value.get("unchecked") for _key, value in seen))

    def test_whitelist_net_counts_ru_site(self):
        results, _seen, waited, _attempts = self.run_with_net(self.targets(2), [""] * 5, whitelist=True,
                                                              reachable=True)
        waited.assert_not_called()
        self.assertFalse(any(value.get("unchecked") for value in results.values()))

    def test_stop_during_retry_leaves_rest_unchecked_not_dead(self):
        stopped = {"v": False}
        original = self.phone._check_chunk

        def check(chunk, base_port, *args, **kwargs):
            out = original(chunk, base_port, *args, **kwargs)
            if base_port == xray.RETRY_PORT:
                stopped["v"] = True
            return out

        with mock.patch.object(xray, "exit_ip_via_socks",
                               side_effect=lambda port, timeout=15, url=xray.IP_URL:
                               "198.51.100.7" if port == xray.NET_PORT else ""), \
                mock.patch.object(xray, "whitelist_reachable", return_value=False), \
                mock.patch.object(self.phone, "_check_chunk", side_effect=check):
            results = self.phone.check_targets(self.targets(8), should_stop=lambda: stopped["v"])
        self.assertEqual([results["n%d:443" % i] for i in range(4)], [xray.UNCHECKED_STOP] * 4)
        self.assertEqual([results["n%d:443" % i] for i in range(4, 8)], [xray.UNCHECKED_STOP] * 4)
        run = {"modes": [{"id": "sim1", "kind": "sim", "results": results},
                         {"id": "dc", "kind": "dc", "results": {key: {"exit_ip": "", "latency": None}
                                                               for key in results}}],
               "targets": [{"key": key, "location": "X"} for key in results], "stopped": True}
        self.assertEqual(dcprobe.dead_everywhere(run), [])

    def test_stop_after_first_pass_marks_unconfirmed_as_stopped(self):
        results, seen, waited, attempts = self.run_with_net(self.targets(3), ["198.51.100.7"],
                                                            stop=iter([False, True, True, True]).__next__)
        self.assertEqual(attempts, 0)
        waited.assert_not_called()
        self.assertEqual(set(results), {"n0:443", "n1:443", "n2:443"})
        self.assertTrue(all(value == xray.UNCHECKED_STOP for value in results.values()))
        self.assertIn(("n0:443", xray.UNCHECKED_STOP), seen)

    def test_node_answered_in_batch_proves_the_network(self):
        with mock.patch.object(self.phone, "net_ok", wraps=self.phone.net_ok) as net_ok:
            results, _seen, waited, _attempts = self.run_with_net(
                self.targets(4), ["198.51.100.7"], retry_ok=lambda _n, port: "203.0.113.4"
                if port == xray.RETRY_PORT else "")
        self.assertEqual(net_ok.call_count, 1)
        waited.assert_not_called()
        self.assertEqual(results["n0:443"]["exit_ip"], "203.0.113.4")
        self.assertEqual([results["n%d:443" % i] for i in (1, 2, 3)], [{"exit_ip": "", "latency": None}] * 3)

    def test_net_rechecked_on_next_batch_after_failed_wait(self):
        results, _seen, waited, attempts = self.run_with_net(
            self.targets(4), ["198.51.100.7", "", "198.51.100.7", "198.51.100.7"], batch=2)
        self.assertEqual(waited.call_count, 1)
        self.assertEqual(attempts, 2)
        self.assertEqual([results["n0:443"], results["n1:443"]], [xray.UNCHECKED_NET] * 2)
        self.assertEqual([results["n2:443"], results["n3:443"]], [{"exit_ip": "", "latency": None}] * 2)

    def test_net_ok_survives_one_echo_service_miss(self):
        answers = {xray.IP_URLS[0]: "", xray.IP_URLS[1]: "198.51.100.7"}
        with mock.patch.object(xray, "exit_ip_via_socks", side_effect=lambda port, timeout=15, url=xray.IP_URL:
                               answers[url]), \
                mock.patch.object(xray, "whitelist_reachable", return_value=False) as reachable:
            self.assertTrue(self.phone.net_ok())
        reachable.assert_not_called()
        self.assertNotEqual(xray.IP_URLS[0].split("/")[2], xray.IP_URLS[1].split("/")[2])

    def test_whitelist_column_checks_ru_site_and_sim_falling_into_whitelist_is_logged(self):
        with mock.patch.object(xray, "exit_ip_via_socks", return_value=""), \
                mock.patch.object(xray, "whitelist_reachable", return_value=True):
            self.assertTrue(self.phone.net_ok(whitelist=True))
            self.assertFalse(self.phone.net_ok())
        self.assertTrue(self.phone.whitelisted_now)
        logs = []
        self.phone.log = logs.append
        with mock.patch.object(self.phone, "wait_for_internet", return_value=("", True)):
            self.assertFalse(self.phone.net_back())
        self.assertIn("белые списки", logs[0])
        self.assertIn("белых списках", logs[-1])
        self.assertFalse(any("пропал интернет" in line or "не вернулся" in line for line in logs))

    def test_latency_timeout_is_none_not_twelve_seconds(self):
        with mock.patch.object(xray, "curl_status", return_value=(28, "000 12.004512")):
            self.assertIsNone(xray.latency_via_socks(10810, timeout=12))
        with mock.patch.object(xray, "curl_status", return_value=(0, "204 0.321")):
            self.assertEqual(xray.latency_via_socks(10810, timeout=12), 321)
        with mock.patch.object(xray, "curl_status", return_value=(0, "000 0.100")):
            self.assertIsNone(xray.latency_via_socks(10810, timeout=12))

    def test_latency_timeout_marks_node_slow(self):
        with mock.patch.object(xray, "exit_ip_via_socks", return_value="198.51.100.3"), \
                mock.patch.object(xray, "curl_status", return_value=(28, "000 12.004512")):
            results = self.phone.check_targets(self.targets(1))
        self.assertEqual(results["n0:443"], {"exit_ip": "198.51.100.3", "latency": None, "slow": True})

    def test_site_timeout_after_headers_is_slow(self):
        target = {"key": "site", "site_url": "https://example.com/"}
        with mock.patch.object(xray, "curl_status", return_value=(28, "200 12.001")):
            results = self.phone.check_targets([target])
        self.assertEqual(results["site"], {"exit_ip": "HTTP 200", "latency": None, "slow": True})

    def test_wait_for_internet_until_ip(self):
        with mock.patch.object(xray, "exit_ip_via_socks", side_effect=["", "", "5.6.7.8"]), \
                mock.patch.object(xray, "whitelist_reachable", return_value=False):
            self.assertEqual(self.phone.wait_for_internet(timeout=60), ("5.6.7.8", False))
        self.assertEqual(self.configs()[0]["outbounds"], [{"protocol": "freedom", "tag": "direct"}])

    def test_wait_for_internet_whitelist_only(self):
        clock = iter(range(0, 1000, 20))
        with mock.patch.object(xray, "exit_ip_via_socks", return_value=""), \
                mock.patch.object(xray, "whitelist_reachable", return_value=True), \
                mock.patch.object(xray.time, "time", side_effect=lambda: next(clock)):
            self.assertEqual(self.phone.wait_for_internet(timeout=60), ("", True))


class Signal:
    def __init__(self):
        self.slots = []

    def connect(self, slot):
        self.slots.append(slot)

    def emit(self, *args):
        for slot in self.slots:
            slot(*args)


class FakeWorker:
    def __init__(self, job):
        self.job = job
        self.log, self.node_result, self.run_finished = Signal(), Signal(), Signal()

    def start(self):
        self.log.emit("старт %s" % self.job.tag)
        self.run_finished.emit({"modes": [{"id": mode.id} for mode in self.job.modes], "targets": []})

    def wait(self, _ms):
        return True

    def isRunning(self):
        return False

    def stop(self):
        pass


class RunCheckTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def args(self, **values):
        base = {"url": None, "file": None, "title": None, "panel": None, "squad": None, "ports": None,
                "location": None}
        base.update(values)
        return mock.Mock(**base)

    def test_load_targets_from_file_with_filters(self):
        path = os.path.join(self.tmp, "sub.txt")
        uuid = "11111111-2222-3333-4444-555555555555"
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(["vless://%s@a.example:443?security=tls#Germany" % uuid,
                                    "vless://%s@b.example:2053?security=tls#Germany" % uuid,
                                    "vless://%s@c.example:443?security=tls#Finland" % uuid]))
        args = self.args(file=path, location="germ")
        targets, _release = run_check.load_targets(args, {"panels": {}}, only_443=False)
        self.assertEqual(sorted(target["key"] for target in targets), ["a.example:443", "b.example:2053"])
        self.assertEqual((args.panel, args.squad), ("file", "sub.txt"))
        args = self.args(file=path, ports="2053")
        targets, _release = run_check.load_targets(args, {"panels": {}}, only_443=False)
        self.assertEqual([target["key"] for target in targets], ["b.example:2053"])

    def test_load_targets_missing_file_exits(self):
        with self.assertRaises(SystemExit):
            run_check.load_targets(self.args(file=os.path.join(self.tmp, "none.txt")), {"panels": {}}, True)

    def test_run_leased_uses_shared_worker_factory(self):
        from PySide6.QtCore import QCoreApplication
        QCoreApplication.instance() or QCoreApplication([])
        mode = mock.Mock(id="dc", kind="dc")
        job = mock.Mock(serial="", tag=multiphone.DC_TAG, modes=[mode], shift=0, mode_targets={})
        app = mock.Mock()
        made = []

        def factory(job, targets, settings, connections, adb=None, raw=None):
            made.append((job, adb, raw))
            return FakeWorker(job)

        with mock.patch.object(run_check.multiphone, "make_worker", side_effect=factory), \
                mock.patch.object(run_check.multiphone, "merge_runs", side_effect=lambda runs, targets: runs):
            result, workers = run_check._run_leased(app, [job], [], {}, {}, b"RAW")
        self.assertEqual(made, [(job, None, b"RAW")])
        self.assertEqual(result[0]["phone_tag"], "")
        app.quit.assert_called_once()
        self.assertEqual(len(workers), 1)
