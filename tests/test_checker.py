"""Движок прогона без телефона: возврат сети, стоп колонки ДЦ, подписка для геомаршрута, метка ДЦ в журнале."""
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from stand import checker, dcprobe, i18n, runlock, storage, subscription  # noqa: E402
from stand.checker import CheckWorker, Mode  # noqa: E402
from stand.phone import PhoneState  # noqa: E402


class Recorder:
    """Телефон/xray-заглушка: любой вызов метода записывается в calls."""

    def __init__(self, **answers):
        self.calls = []
        self.answers = answers

    def __getattr__(self, name):
        def method(*args, **_kwargs):
            self.calls.append((name,) + args)
            return self.answers.get(name)
        return method


def worker(**kwargs):
    return CheckWorker([], [], mock.Mock(serial="S1"), {}, **kwargs)


class RestoreTest(unittest.TestCase):
    def test_mobile_data_and_airplane_returned(self):
        phone, xray = Recorder(), Recorder()
        original = PhoneState(connected=True, wifi_on=True, mobile_data_on=False, airplane=False, data_sub_id=-1)
        worker().restore(phone, xray, original)
        self.assertIn(("set_mobile_data", False), phone.calls)
        self.assertIn(("set_airplane", False), phone.calls)
        self.assertIn(("set_wifi", True), phone.calls)

    def test_airplane_mode_returned_last(self):
        phone, xray = Recorder(), Recorder()
        worker().restore(phone, xray, PhoneState(connected=True, airplane=True, data_sub_id=2))
        self.assertEqual(phone.calls[-1], ("set_airplane", True))
        self.assertNotIn(("set_airplane", False), phone.calls)

    def test_restore_is_not_cut_short_by_stop(self):
        phone, xray = Recorder(), Recorder()
        phone.should_stop = xray.should_stop = lambda: True
        original = PhoneState(connected=True, data_sub_id=3)
        run = worker()
        run.stop()
        run.restore(phone, xray, original)
        self.assertFalse(phone.should_stop())
        self.assertIn(("set_data_sim", 3), phone.calls)


class DcStopTest(unittest.TestCase):
    def test_probe_gets_stop_flag(self):
        seen = {}

        def fake_probe(spec, nodes, batch, wait, log=None, should_stop=None):
            seen["stop"] = should_stop
            return {}

        run = worker(connections={"probe": {"host": "h"}})
        run.targets = [{"key": "a:443", "location": "DE", "outbound": {}}]
        with mock.patch.object(dcprobe, "probe", fake_probe):
            run.run_dc(Mode("dc", "dc", "ДЦ"))
        self.assertFalse(seen["stop"]())
        run.stop()
        self.assertTrue(seen["stop"]())


class NetDropTest(unittest.TestCase):
    def test_dc_latency_timeout_is_slow(self):
        run = worker(connections={"probe": {"host": "h"}})
        run.targets = [{"key": "a:443", "location": "DE", "outbound": {}},
                       {"key": "b:443", "location": "DE", "outbound": {}}]
        answer = {"a:443": {"exit_ip": "198.51.100.1", "latency": ""},
                  "b:443": {"exit_ip": "198.51.100.2", "latency": "0.250"}}
        with mock.patch.object(dcprobe, "probe", lambda *_a, **_k: dict(answer)):
            results = run.run_dc(Mode("dc", "dc", "ДЦ"))
        self.assertEqual(results["a:443"], {"exit_ip": "198.51.100.1", "latency": None, "slow": True})
        self.assertEqual(results["b:443"], {"exit_ip": "198.51.100.2", "latency": 250})

    def test_phone_mode_reports_unchecked(self):
        run = worker()
        run.targets = [{"key": "a:443", "location": "DE"}, {"key": "b:443", "location": "DE"}]
        logs, calls = [], {}
        run.log.connect(logs.append)

        class Xray:
            def wait_for_internet(self, timeout=45):
                return "", True

            def check_targets(self, targets, **kwargs):
                calls.update(kwargs)
                return {"a:443": {"exit_ip": "", "latency": None, "unchecked": "net"},
                        "b:443": {"exit_ip": "198.51.100.1", "latency": 90}}

        run.settings = {"whitelist_mode": "check"}
        ip, results = run.run_phone_mode(Mode("wifi", "wifi", "Wi-Fi"), Recorder(wait_transport=True), Xray())
        self.assertEqual(ip, checker.WHITELIST_IP)
        self.assertTrue(calls["whitelist"])
        self.assertEqual(checker.unchecked_count(results), 1)
        self.assertTrue(any("Wi-Fi: не проверено 1 (пропала сеть телефона)" in line for line in logs))

    def test_unchecked_note_names_the_reason(self):
        net = {"exit_ip": "", "latency": None, "unchecked": "net"}
        stop = {"exit_ip": "", "latency": None, "unchecked": "stop"}
        self.assertEqual(checker.unchecked_note({"a": {"exit_ip": "1.2.3.4"}}), "")
        self.assertEqual(checker.unchecked_note({"a": net}), "не проверено 1 (пропала сеть телефона)")
        self.assertEqual(checker.unchecked_note({"a": stop, "b": stop}), "не проверено 2 (прогон остановлен)")
        self.assertEqual(checker.unchecked_note({"a": net, "b": stop}),
                         "не проверено 2 (пропала сеть телефона - 1, прогон остановлен - 1)")


class GeoRawTest(unittest.TestCase):
    def test_own_subscription_not_last_raw(self):
        run = worker(raw=b"MINE")
        run.targets = [{"key": "a:443", "location": "DE", "address": "a", "port": 443}]
        record = {"modes": [{"kind": "sim", "results": {"a:443": {"exit_ip": "198.51.100.1"}}}]}
        xray = Recorder(ensure_geodata=True, direct_ip=("203.0.113.5", False))
        used = []
        with mock.patch.object(subscription, "LAST_RAW", b"OTHER"), \
                mock.patch.object(subscription, "full_config_for", lambda raw, *_: used.append(raw)):
            run.geo_probe(xray, record)
        self.assertEqual(used, [b"MINE"])


class StopInWaitsTest(unittest.TestCase):
    """Стоп обрывает долгие ожидания телефона и xray, а не ждёт их таймаута."""

    def test_phone_waits_return_at_once(self):
        from stand.phone import PhoneControl
        adb = mock.Mock()
        adb.shell.return_value = ""
        phone = PhoneControl(adb, should_stop=lambda: True)
        with mock.patch("stand.phone.time.sleep", side_effect=AssertionError("ждёт")):
            self.assertFalse(phone.wait_transport("wifi", timeout=600))
            self.assertFalse(phone.wait_active_sub(1, timeout=600))
            self.assertFalse(phone.set_data_sim(1, verify_seconds=600))
        self.assertFalse(any("MANAGE_ALL_SIM" in str(call) for call in adb.shell.call_args_list))

    def test_xray_wait_for_internet_stops(self):
        from stand.xray import PhoneXray
        xray = PhoneXray(mock.Mock(), should_stop=lambda: True)
        with mock.patch("stand.xray.time.sleep"), \
                mock.patch("stand.xray.exit_ip_via_socks", side_effect=AssertionError("ждёт")):
            self.assertEqual(xray.wait_for_internet(timeout=600), ("", False))


class ConsoleStopTest(unittest.TestCase):
    def test_ctrl_c_stops_workers(self):
        import signal

        import run_check
        workers = [mock.Mock(), mock.Mock()]
        previous = signal.getsignal(signal.SIGINT)
        try:
            run_check.stop_workers(workers)
            self.assertIs(signal.getsignal(signal.SIGINT), signal.SIG_DFL)
        finally:
            signal.signal(signal.SIGINT, previous)
        for item in workers:
            item.stop.assert_called_once()


class TagTest(unittest.TestCase):
    def test_dc_tag_translated_in_log(self):
        lines = []
        run = worker(tag="ДЦ")
        run.log.connect(lines.append)
        old = i18n.language()
        i18n.set_language("en")
        try:
            run.emit_log("x")
        finally:
            i18n.set_language(old)
        self.assertIn("[DC] x", lines[0])

    def test_mode_error_kind_translated(self):
        recorded = []
        run = CheckWorker([], [Mode("dc", "dc", "ДЦ Москва")], mock.Mock(serial="S1"), {})
        with mock.patch.object(checker.errorlog, "record", lambda kind, exc: recorded.append(kind)), \
                mock.patch.object(run, "run_dc", side_effect=RuntimeError("boom")):
            old = i18n.language()
            i18n.set_language("en")
            try:
                run.run()
            finally:
                i18n.set_language(old)
        self.assertEqual(recorded, ["mode:ДЦ Москва"])


class RunTargetsTest(unittest.TestCase):
    """Сохранённый прогон помнит адрес, порт и сайт узла - «Почему мёртв» работает и по нему."""

    def test_run_target_keeps_address_port_site(self):
        target = {"location": "NL", "key": "a:443", "sni": "x.com", "address": "a", "port": 443,
                  "site_url": "https://x.com/", "outbound": {"big": True}}
        self.assertEqual(checker.run_target(target), {"location": "NL", "key": "a:443", "sni": "x.com",
                                                      "address": "a", "port": 443, "site_url": "https://x.com/"})
        self.assertEqual(checker.run_target({"location": "L", "key": "k"}), {"location": "L", "key": "k", "sni": None})

    def test_saved_run_has_targets_with_address(self):
        target = {"location": "NL", "key": "a:443", "address": "a", "port": 443, "site_url": "https://x.com/"}
        run = CheckWorker([target], [Mode("dc", "dc", "ДЦ")], mock.Mock(serial="S1"), {})
        finished = []
        run.run_finished.connect(finished.append)
        with mock.patch.object(run, "run_dc", return_value={}):
            run.run()
        self.assertEqual(finished[0]["targets"][0]["address"], "a")
        self.assertEqual(finished[0]["targets"][0]["port"], 443)
        self.assertEqual(finished[0]["targets"][0]["site_url"], "https://x.com/")
        self.assertNotIn("outbound", finished[0]["targets"][0])


class RunFinishTest(unittest.TestCase):
    """Падение при возврате сети не оставляет окно в «идёт проверка»: run_finished приходит, лок телефона снят."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="vpncheck-test-")
        self.old_dir = storage.APP_DIR
        storage.APP_DIR = self.tmp

    def tearDown(self):
        runlock.release("S1")
        storage.APP_DIR = self.old_dir
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_run_finished_when_restore_raises(self):
        class Phone:
            def __init__(self, *_args, **_kwargs):
                self.should_stop = None

            def read_state(self):
                return PhoneState(connected=True, serial="S1")

            def auto_wifi(self):
                return False

        class Xray:
            def __init__(self, *_args, **_kwargs):
                self.should_stop = None

            def ensure_installed(self):
                raise RuntimeError("boom in run")

            def stop_all(self):
                raise ValueError("boom in restore")

        run = CheckWorker([], [Mode("sim1", "sim", "x", 1)], mock.Mock(serial="S1"), {"restore_network": True})
        finished, logs = [], []
        run.run_finished.connect(finished.append)
        run.log.connect(logs.append)
        with mock.patch.object(checker, "PhoneControl", Phone), mock.patch.object(checker, "PhoneXray", Xray):
            with mock.patch.object(checker.errorlog, "record"):
                run.run()
        self.assertEqual(len(finished), 1)
        self.assertEqual(runlock.holder("S1"), 0)
        self.assertTrue(runlock.acquire("S1"))
        self.assertTrue(any("boom in restore" in line for line in logs))

    def test_busy_phone_finishes_once(self):
        run = CheckWorker([], [Mode("sim1", "sim", "x", 1)], mock.Mock(serial="S1"), {})
        finished = []
        run.run_finished.connect(finished.append)
        with mock.patch.object(checker.runlock, "acquire", return_value=False):
            with mock.patch.object(checker.runlock, "holder", return_value=4321):
                run.run()
        self.assertEqual(len(finished), 1)


if __name__ == "__main__":
    unittest.main()
