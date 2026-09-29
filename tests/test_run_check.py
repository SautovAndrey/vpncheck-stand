"""run_check: выбор сетей --modes (слот, оператор, @телефон), --list-modes, склейка --merge и таблица в консоли."""
import io
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import run_check  # noqa: E402
from stand import multiphone, storage  # noqa: E402
from stand.phone import PhoneState, Sim  # noqa: E402


def phone(serial, tag, *sims, ssid="HomeNet"):
    state = PhoneState(connected=True, model="SM-" + tag, wifi_ssid=ssid,
                       sims=[Sim(sub_id=sub, slot=slot, name=name) for sub, slot, name in sims])
    return {"serial": serial, "index": 0, "tag": tag, "model": state.model, "state": state}


def all_modes(phones, has_dc="ДЦ · Москва"):
    return [m for _, group in multiphone.mode_groups(phones, has_dc) for m in group]


ONE = [phone("R58A", "A075F", (3, 0, "МегаФон"), (5, 1, "Beeline"))]
TWO = [phone("R58A", "A075F", (3, 0, "MegaFon"), (4, 1, "MTS RUS")),
       phone("R58B", "A175F", (1, 0, "MTS RUS"), ssid="Other")]


def ids(tokens, phones=ONE):
    return [m.id for m in multiphone.resolve_modes(tokens, all_modes(phones), phones)[0]]


class ResolveModesTest(unittest.TestCase):
    def test_slot_number_not_sub_id(self):
        self.assertEqual(ids(["sim1"]), ["sim3"])
        self.assertEqual(ids([" SIM2 ", "dc"]), ["dc", "sim5"])

    def test_old_sub_id_still_works(self):
        self.assertEqual(ids(["sim5"]), ["sim5"])

    def test_carrier_name_any_case_and_script(self):
        self.assertEqual(ids(["билайн"]), ["sim5"])
        self.assertEqual(ids(["megafon"]), ["sim3"])
        self.assertEqual(ids(["BEELINE", "wifi"]), ["sim5", "wifi"])

    def test_slot_is_saved_with_mode(self):
        mode = all_modes(ONE)[1]
        self.assertEqual((mode.to_dict()["slot"], mode.to_dict()["sub_id"]), (0, 3))

    def test_unknown_token_lists_what_exists(self):
        with self.assertRaises(ValueError) as caught:
            ids(["sim4", "tele2"])
        text = str(caught.exception)
        self.assertIn("sim4, tele2", text)
        self.assertIn("sim1 (МегаФон, слот 1)", text)
        self.assertIn("sim2 (Beeline, слот 2)", text)
        self.assertIn("dc (ДЦ · Москва)", text)

    def test_two_phones_slot_means_each_phone(self):
        self.assertEqual(ids(["sim1"], TWO), ["sim3@R58A", "sim1@R58B"])
        self.assertEqual(ids(["sim1@a175f"], TWO), ["sim1@R58B"])
        self.assertEqual(ids(["wifi@R58B"], TWO), ["wifi@R58B"])

    def test_two_phones_same_carrier_one_per_phone(self):
        self.assertEqual(ids(["mts"], TWO), ["sim4@R58A", "sim1@R58B"])
        self.assertEqual(ids(["мтс@A075F"], TWO), ["sim4@R58A"])

    def test_ambiguous_carrier_on_one_phone(self):
        twin = [phone("R58A", "A075F", (1, 0, "MTS RUS"), (2, 1, "MTS Business"))]
        with self.assertRaises(ValueError) as caught:
            ids(["mts"], twin)
        self.assertIn("sim1 (MTS RUS, слот 1)", str(caught.exception))
        self.assertEqual(ids(["mts business"], twin), ["sim2"])

    def test_full_column_id_accepted(self):
        self.assertEqual(ids(["sim4@R58A"], TWO), ["sim4@R58A"])

    def test_unknown_phone(self):
        with self.assertRaises(ValueError):
            ids(["sim1@nothere"], TWO)


class BuildModesTest(unittest.TestCase):
    def test_prints_choice_and_exits_with_list(self):
        out = io.StringIO()
        with redirect_stdout(out):
            modes = run_check.build_modes(["sim2"], ONE, "ДЦ")
        self.assertEqual([m.id for m in modes], ["sim5"])
        self.assertIn("sim2 -> Beeline (слот 2)", out.getvalue())
        with self.assertRaises(SystemExit) as caught, redirect_stdout(io.StringIO()):
            run_check.build_modes(["sim9"], ONE, "ДЦ")
        self.assertIn("нет таких сетей: sim9", str(caught.exception.code))

    def test_no_filter_gives_all(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual([m.id for m in run_check.build_modes(None, ONE, "")], ["sim3", "sim5", "wifi"])

    def test_list_modes(self):
        out = io.StringIO()
        with redirect_stdout(out):
            run_check.list_modes(TWO, "ДЦ")
        text = out.getvalue()
        self.assertIn("sim2@A075F (MTS RUS · A075F, слот 2)", text)
        self.assertIn("wifi@A175F", text)
        out = io.StringIO()
        with redirect_stdout(out):
            run_check.list_modes([], "")
        self.assertIn("сетей нет", out.getvalue())

    def test_main_list_modes_needs_no_panel(self):
        out = io.StringIO()
        with mock.patch.object(sys, "argv", ["run_check.py", "--list-modes"]), \
                mock.patch.object(run_check, "connected_phones", return_value=ONE), \
                mock.patch.object(run_check.storage, "load_settings", return_value={}), \
                mock.patch.object(run_check.storage, "load_connections", return_value={"panels": {}}), \
                mock.patch.object(run_check, "load_targets") as load, redirect_stdout(out):
            run_check.main()
        load.assert_not_called()
        self.assertIn("sim1 (МегаФон, слот 1)", out.getvalue())


def saved_run(started, modes, targets=("k1",)):
    return {"started": started, "finished": started, "panel": "p", "squad": "s",
            "targets": [{"location": "L", "key": key} for key in targets],
            "modes": [{"id": mode, "label": mode, "results": {"k1": {"exit_ip": "1.1.1.1", "latency": 50}}}
                      for mode in modes]}


class MergeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="vpncheck-test-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        patch = mock.patch.object(storage, "RUNS_DIR", os.path.join(self.tmp, "runs"))
        patch.start()
        self.addCleanup(patch.stop)

    def test_old_file_kept_until_new_saved(self):
        old_path = storage.save_run(saved_run("2026-09-28 10:00:00", ["sim1", "wifi"]))
        merged, replaced = run_check.merge_into_previous(saved_run("2026-09-28 12:00:00", ["wifi", "dc"]))
        self.assertEqual(replaced, old_path)
        self.assertTrue(os.path.exists(old_path))
        self.assertEqual([m["id"] for m in merged["modes"]], ["sim1", "wifi", "dc"])
        self.assertEqual(merged["merged_from"], "2026-09-28 10:00:00")

    def test_other_day_not_merged(self):
        storage.save_run(saved_run("2026-09-27 10:00:00", ["sim1"]))
        run = saved_run("2026-09-28 12:00:00", ["wifi"])
        self.assertEqual(run_check.merge_into_previous(run), (run, None))

    def test_print_table(self):
        run = saved_run("2026-09-28 12:00:00", ["wifi"], targets=("k1", "k2"))
        run["modes"].append({"id": "sim1", "label": "MTS", "results": {}, "error": "нет сети"})
        out = io.StringIO()
        with redirect_stdout(out):
            run_check.print_table(run)
        text = out.getvalue()
        self.assertIn("● 50 мс", text)
        self.assertIn("✕ мёртв", text)
        self.assertIn("? нет сети", text)

    def test_unchecked_and_slow_in_console(self):
        run = saved_run("2026-09-28 12:00:00", ["sim1"], targets=("k1", "k2", "k3"))
        run["modes"][0]["results"] = {
            "k1": {"exit_ip": "", "latency": None, "unchecked": "net"},
            "k2": {"exit_ip": "198.51.100.2", "latency": None, "slow": True},
            "k3": {"exit_ip": "", "latency": None}}
        out = io.StringIO()
        with redirect_stdout(out):
            run_check.print_table(run)
            run_check.print_node_result("sim1", "k2", run["modes"][0]["results"]["k2"])
            run_check.print_node_result("sim1", "k1", run["modes"][0]["results"]["k1"])
        text = out.getvalue()
        self.assertEqual(text.count("? нет сети"), 2)
        self.assertEqual(text.count("● медленно"), 2)
        self.assertNotIn("None", text)
        self.assertIn("живых 1 из 3", text)
        self.assertIn("не проверено 1 (пропала сеть телефона)", text)
        storage.save_run(run)
        self.assertIn("1/3 ?1", storage.list_runs()[0]["label"])

    def test_stopped_before_recheck_in_console(self):
        run = saved_run("2026-09-28 12:00:00", ["sim1"], targets=("k1", "k2"))
        run["modes"][0]["results"] = {"k1": {"exit_ip": "", "latency": None, "unchecked": "stop"},
                                      "k2": {"exit_ip": "", "latency": None}}
        out = io.StringIO()
        with redirect_stdout(out):
            run_check.print_table(run)
        text = out.getvalue()
        self.assertIn("? остановлен", text)
        self.assertEqual(text.count("✕ мёртв"), 1)
        self.assertIn("не проверено 1 (прогон остановлен)", text)


if __name__ == "__main__":
    unittest.main()
