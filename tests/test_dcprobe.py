"""Диагноз мёртвых узлов: кого проверять и какой вердикт ставить."""
import base64
import json
import os
import shutil
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from stand import dcprobe, storage  # noqa: E402

TARGETS = [{"key": "a.example:443", "location": "DE"}, {"key": "b.example:443", "location": "PL"}]


def run_with(*modes):
    return {"targets": TARGETS, "modes": list(modes)}


def column(kind, alive, **extra):
    results = {t["key"]: {"exit_ip": "1.1.1.1" if t["key"] in alive else ""} for t in TARGETS}
    return dict({"id": kind, "kind": kind, "results": results, "error": ""}, **extra)


class DeadEverywhereTest(unittest.TestCase):
    def test_dead_in_all_columns_including_dc(self):
        run = run_with(column("dc", {"a.example:443"}), column("sim", set()))
        self.assertEqual([t["key"] for t in dcprobe.dead_everywhere(run)], ["b.example:443"])

    def test_alive_somewhere_is_not_a_candidate(self):
        run = run_with(column("dc", set()), column("sim", {"b.example:443"}))
        self.assertEqual([t["key"] for t in dcprobe.dead_everywhere(run)], ["a.example:443"])

    def test_no_dc_column_no_diagnosis(self):
        self.assertEqual(dcprobe.dead_everywhere(run_with(column("sim", set()))), [])

    def test_whitelisted_and_failed_columns_ignored(self):
        run = run_with(column("dc", set()), column("sim", {"a.example:443"}, whitelist=True),
                       dict(column("wifi", {"b.example:443"}), error="нет сети"))
        self.assertEqual(len(dcprobe.dead_everywhere(run)), 2)


    def test_unchecked_by_lost_network_is_not_diagnosed(self):
        sim = column("sim", set())
        sim["results"]["a.example:443"] = {"exit_ip": "", "latency": None, "unchecked": "net"}
        run = run_with(column("dc", set()), sim)
        self.assertEqual([t["key"] for t in dcprobe.dead_everywhere(run)], ["b.example:443"])

    def test_probe_script_drops_latency_of_timed_out_curl(self):
        self.assertIn('timed.stdout.strip() if timed.returncode == 0 else ""', dcprobe.PROBE_SCRIPT)


class VerdictTest(unittest.TestCase):
    def test_tcp_blocked(self):
        text, detail = dcprobe.verdict({"ip": "203.0.113.5", "tcp": "timeout", "tls": ""})
        self.assertEqual(text, "не достучаться из РФ")
        self.assertIn("203.0.113.5", detail)

    def test_handshake_torn(self):
        self.assertEqual(dcprobe.verdict({"tcp": "ok", "tls": "reset"})[0], "рвут рукопожатие")

    def test_network_fine_vpn_not(self):
        self.assertEqual(dcprobe.verdict({"tcp": "ok", "tls": "ok"})[0], "ключ или DPI")

    def test_dns(self):
        self.assertEqual(dcprobe.verdict({"tcp": "dns: gaierror"})[0], "имя не разрешается")


class FakeKey:
    def __init__(self, blob):
        self.blob = blob

    def get_name(self):
        return "ssh-ed25519"

    def get_base64(self):
        return self.blob


def fake_paramiko(server_key):
    """paramiko без сети: connect() лишь спрашивает политику о ключе сервера, как настоящий."""
    closed = []

    class SSHClient:
        def set_missing_host_key_policy(self, policy):
            self.policy = policy

        def connect(self, hostname, **_kwargs):
            self.policy.missing_host_key(self, hostname, FakeKey(server_key))

        def close(self):
            closed.append(True)

    return types.SimpleNamespace(SSHClient=SSHClient, closed=closed)


class HostKeyTofuTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="vpncheck-test-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        patcher = mock.patch.object(storage, "CONNECTIONS_PATH", os.path.join(self.tmp, "connections.json"))
        patcher.start()
        self.addCleanup(patcher.stop)
        storage.save_connections({"panels": {}, "probe": {"host": "203.0.113.10", "port": 22, "user": "root"}})

    def connect(self, spec, server_key):
        fake = fake_paramiko(server_key)
        with mock.patch.dict(sys.modules, {"paramiko": fake}):
            dcprobe.connect(spec)
        return fake

    def test_first_login_remembers_key_in_connections(self):
        spec = storage.load_connections()["probe"]
        self.connect(spec, "AAAA1")
        self.assertEqual(spec["host_key"], "ssh-ed25519 AAAA1")
        with open(storage.CONNECTIONS_PATH, encoding="utf-8") as handle:
            self.assertEqual(json.load(handle)["probe"]["host_key"], "ssh-ed25519 AAAA1")

    def test_same_key_passes(self):
        spec = dict(storage.load_connections()["probe"], host_key="ssh-ed25519 AAAA1")
        self.connect(spec, "AAAA1")
        self.assertEqual(spec["host_key"], "ssh-ed25519 AAAA1")

    def test_changed_key_refused(self):
        spec = dict(storage.load_connections()["probe"], host_key="ssh-ed25519 AAAA1")
        fake = fake_paramiko("EVIL")
        with mock.patch.dict(sys.modules, {"paramiko": fake}):
            with self.assertRaises(dcprobe.HostKeyMismatch) as caught:
                dcprobe.connect(spec)
        self.assertIn("203.0.113.10", str(caught.exception))
        self.assertTrue(fake.closed)
        self.assertEqual(spec["host_key"], "ssh-ed25519 AAAA1")
        self.assertNotIn("host_key", storage.load_connections()["probe"])

    def test_other_server_not_written_to_connections(self):
        spec = {"host": "198.51.100.7", "port": 22}
        self.connect(spec, "BBBB")
        self.assertEqual(spec["host_key"], "ssh-ed25519 BBBB")
        self.assertNotIn("host_key", storage.load_connections()["probe"])

    def test_mismatch_is_probe_error(self):
        self.assertTrue(issubclass(dcprobe.HostKeyMismatch, dcprobe.ProbeError))


class ProbeRunTest(unittest.TestCase):
    """Прогон на пробнике: стоп прерывает ожидание, после любого исхода скрипт и файлы убираются."""

    def run_probe(self, outputs, should_stop=None):
        commands = []

        def fake_run(_client, command, timeout=180, data=None):
            commands.append(command)
            if command.startswith("cat /tmp/vpncheck_out_"):
                return (outputs.pop(0) if outputs else ""), "", 0
            return "", "", 0

        client = mock.Mock()
        with mock.patch.object(dcprobe, "connect", return_value=client), \
                mock.patch.object(dcprobe, "ensure_xray", return_value="/x/xray"), \
                mock.patch.object(dcprobe, "run", side_effect=fake_run), \
                mock.patch.object(dcprobe.time, "sleep"):
            try:
                return dcprobe.probe({"host": "h"}, [{"key": "a:443", "outbound": {}}], 4, 5,
                                     should_stop=should_stop), commands
            finally:
                client.close.assert_called()

    def test_result_and_cleanup(self):
        result, commands = self.run_probe(['VPNCHECK_RESULT {"a:443": {"exit_ip": "1.2.3.4"}}'])
        self.assertEqual(result["a:443"]["exit_ip"], "1.2.3.4")
        self.assertIn("pkill", commands[-1])

    def test_stop_interrupts_and_cleans_up(self):
        commands = []

        def spy(_client, command, timeout=180, data=None):
            commands.append(command)
            return "", "", 0

        with mock.patch.object(dcprobe, "connect", return_value=mock.Mock()), \
                mock.patch.object(dcprobe, "ensure_xray", return_value="/x/xray"), \
                mock.patch.object(dcprobe, "run", side_effect=spy), \
                mock.patch.object(dcprobe.time, "sleep"):
            with self.assertRaises(dcprobe.ProbeError):
                dcprobe.probe({"host": "h"}, [{"key": "a:443", "outbound": {}}], should_stop=lambda: True)
        self.assertFalse(any(command.startswith("cat ") for command in commands))
        run_id = commands[0].split("vpncheck_targets_")[1].split(".json")[0]
        self.assertEqual(commands[-1], dcprobe.cleanup_command(run_id))

    def test_cleanup_does_not_kill_itself_and_ports_are_free(self):
        command = dcprobe.cleanup_command("123")
        self.assertNotIn("pkill -f /tmp", command)
        self.assertIn("[/]tmp/vpncheck_probe_123", command)
        self.assertNotIn("40000", dcprobe.PROBE_SCRIPT)
        compile(dcprobe.PROBE_SCRIPT, "probe", "exec")


    def test_probe_script_retries_dead_xray_and_cleans_up(self):
        import subprocess
        folder = tempfile.mkdtemp(prefix="vpncheck-test-").replace("\\", "/")
        self.addCleanup(shutil.rmtree, folder, True)
        script = dcprobe.PROBE_SCRIPT.replace("/tmp/", folder + "/")
        script_path = folder + "/vpncheck_probe_77.py"
        with open(script_path, "w", encoding="utf-8") as handle:
            handle.write(script)
        with open(folder + "/vpncheck_targets_77.json", "w", encoding="utf-8") as handle:
            json.dump([{"key": "a:443", "outbound": {"protocol": "vless"}}], handle)
        stale = folder + "/vpncheck_out_1.txt"
        open(stale, "w").close()
        os.utime(stale, (time.time() - 7 * 3600,) * 2)
        env = dict(os.environ, VPNCHECK_RUN="77", VPNCHECK_XRAY=sys.executable)
        out = subprocess.run([sys.executable, script_path, "4", "0"], env=env, capture_output=True, text=True,
                             timeout=60)
        self.assertIn('VPNCHECK_RESULT {}', out.stdout, out.stderr)
        self.assertEqual(os.listdir(folder), [])

    def test_probe_files_created_private(self):
        self.assertIn("os.umask(0o077)", dcprobe.PROBE_SCRIPT)
        commands = []

        def spy(_client, command, timeout=180, data=None):
            commands.append(command)
            return "VPNCHECK_RESULT {}", "", 0

        with mock.patch.object(dcprobe, "connect", return_value=mock.Mock()), \
                mock.patch.object(dcprobe, "ensure_xray", return_value="/x/xray"), \
                mock.patch.object(dcprobe, "run", side_effect=spy), \
                mock.patch.object(dcprobe.time, "sleep"):
            dcprobe.probe({"host": "h"}, [{"key": "a:443", "outbound": {}}])
        for command in commands:
            if "> /tmp/" in command:
                self.assertTrue(command.startswith("umask 077;"), command)


class DiagnoseCommandTest(unittest.TestCase):
    def test_no_script_file_on_probe_and_quoted_install(self):
        commands = []
        client = mock.Mock()

        def fake_run(_client, command, timeout=180, data=None):
            commands.append(command)
            return 'VPNCHECK_RESULT {"a:443": {"ip": "1.2.3.4"}}', "", 0

        with mock.patch.object(dcprobe, "connect", return_value=client), \
                mock.patch.object(dcprobe, "run", side_effect=fake_run):
            result = dcprobe.diagnose({"host": "h"}, [{"key": "a:443", "address": "a", "port": 443}])
        self.assertEqual(result, {"a:443": {"ip": "1.2.3.4"}})
        self.assertNotIn("/tmp/", commands[0])
        script = commands[0].split()[-1]
        self.assertEqual(base64.b64decode(script).decode(), dcprobe.DIAGNOSE_SCRIPT)

    def test_xray_version_and_path_are_quoted(self):
        commands = []

        def fake_run(_client, command, timeout=180):
            commands.append(command)
            return ("ok" if "base64" in command or "command -v" in command else ""), "", 0

        with mock.patch.object(dcprobe, "run", side_effect=fake_run):
            dcprobe.ensure_xray(mock.Mock(), {"xray_version": "1;touch /tmp/x"})
        self.assertTrue(any("'1;touch /tmp/x'" in command for command in commands), commands)
        self.assertFalse(any(" 1;touch" in command for command in commands))


if __name__ == "__main__":
    unittest.main()


class SavedRunDiagnoseTest(unittest.TestCase):
    """Круг 5: «Почему мёртв» по сохранённому и склеенному прогону - без address/port у целей, с дублями и сайтами."""

    def test_merged_run_with_duplicates_and_site(self):
        from stand import multiphone, subscription
        node = {"location": "DE", "key": "1.2.3.4:443", "address": "1.2.3.4", "port": 443, "outbound": {}}
        targets = subscription.dedupe_keys([dict(node, sni="a.com"), dict(node, sni="b.com")])
        targets += subscription.site_targets([{"url": "https://youtube.com", "name": "YouTube"}])
        runs = [{"modes": [{"id": "dc", "kind": "dc", "error": "",
                            "results": {t["key"]: {"exit_ip": ""} for t in targets if not t.get("site_url")}}]},
                {"modes": [{"id": "sim1", "kind": "sim", "error": "", "ip": "5.5.5.5",
                            "results": {t["key"]: {"exit_ip": ""} for t in targets}}]}]
        run = multiphone.merge_runs(runs, targets)
        for target in run["targets"]:
            target.pop("address", None)
            target.pop("port", None)
            target.pop("site_url", None)
        dead = dcprobe.dead_everywhere(run)
        self.assertEqual([t["key"] for t in dead], ["1.2.3.4:443 · a.com", "1.2.3.4:443 · b.com"])
        sent = []

        def fake_run(_client, _command, _timeout, data=None):
            sent.extend(json.loads(data))
            return "VPNCHECK_RESULT {}", "", 0
        with mock.patch.object(dcprobe, "connect"), mock.patch.object(dcprobe, "run", fake_run):
            dcprobe.diagnose({"host": "x"}, dead + [{"key": "🌐 YouTube"}, {"key": "garbage"}])
        self.assertEqual([(n["address"], n["port"], n["sni"]) for n in sent],
                         [("1.2.3.4", 443, "a.com"), ("1.2.3.4", 443, "b.com")])

    def test_node_address_from_key_forms(self):
        self.assertEqual(dcprobe.node_address({"key": "2001:db8::1:443"}), ("2001:db8::1", 443))
        self.assertEqual(dcprobe.node_address({"key": "de.example:8443 · 2"}), ("de.example", 8443))
        self.assertEqual(dcprobe.node_address({"key": "x", "address": "a.example", "port": "443"}), ("a.example", 443))
        self.assertIsNone(dcprobe.node_address({"key": "🌐 YouTube"}))

    def test_probe_script_accepts_only_an_ip_from_ipify(self):
        self.assertIn('"curl", "-s", "-f"', dcprobe.PROBE_SCRIPT)
        self.assertIn("ipaddress.ip_address(ip)", dcprobe.PROBE_SCRIPT)
