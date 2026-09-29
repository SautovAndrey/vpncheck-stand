"""Несколько телефонов: имена, сети с приставками, раскладка по потокам и склейка отчёта."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from stand import multiphone  # noqa: E402
from stand.checker import Mode  # noqa: E402
from stand.phone import PhoneState, Sim  # noqa: E402
from stand.xray import port_shift  # noqa: E402


def state(*sims, ssid="HomeNet"):
    return PhoneState(connected=True, model="SM-A075F", wifi_ssid=ssid,
                      sims=[Sim(sub_id=sub, slot=i, name=name) for i, (sub, name) in enumerate(sims)])


def phones(*serials):
    return [{"serial": s, "index": i, "tag": "T%d" % i, "model": "", "state": None} for i, s in enumerate(serials)]


class TagTest(unittest.TestCase):
    def test_samsung_prefix_dropped(self):
        self.assertEqual(multiphone.phone_tag("SM-A075F", "R58X1234ABC"), "A075F")

    def test_same_model_gets_serial_tail(self):
        self.assertEqual(multiphone.phone_tag("SM-A075F", "R58X12XXABCD", taken=["A075F"]), "A075F·ABCD")

    def test_no_model_falls_back_to_serial(self):
        self.assertEqual(multiphone.phone_tag("", "R58X1234ABC"), "1234ABC"[-6:])


class ModesTest(unittest.TestCase):
    def test_single_phone_keeps_old_ids(self):
        ids = [m.id for m in multiphone.phone_modes(state((1, "MegaFon"), (2, "MTS RUS")))]
        self.assertEqual(ids, ["sim1", "sim2", "wifi"])

    def test_multi_phone_ids_never_collide(self):
        a = multiphone.phone_modes(state((1, "MegaFon")), tag="A075F", serial="AAA", multi=True)
        b = multiphone.phone_modes(state((1, "Beeline")), tag="A175F", serial="BBB", multi=True)
        ids = [m.id for m in a + b]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(a[0].label, "MegaFon · A075F")
        self.assertEqual(multiphone.split_mode_id(b[0].id), ("sim1", "BBB"))

    def test_disconnected_phone_has_no_modes(self):
        self.assertEqual(multiphone.phone_modes(PhoneState(connected=False)), [])


def two(ssid_a="HomeNet", ssid_b="HomeNet"):
    return [{"serial": "AAA", "index": 0, "tag": "A075F", "state": state((1, "MegaFon"), ssid=ssid_a)},
            {"serial": "BBB", "index": 1, "tag": "A175F", "state": state((1, "MTS"), ssid=ssid_b)}]


def targets(n):
    return [{"location": "L", "key": "k%d" % i} for i in range(n)]


class SharedWifiTest(unittest.TestCase):
    def test_same_point_gives_one_shared_column(self):
        groups = multiphone.mode_groups(two(), has_dc=True)
        ids = [m.id for _, group in groups for m in group]
        self.assertEqual(ids, ["dc", "wifi@AAA+BBB", "sim1@AAA", "sim1@BBB"])
        self.assertEqual(multiphone.mode_serials("wifi@AAA+BBB"), ["AAA", "BBB"])

    def test_different_points_keep_own_wifi(self):
        ids = [m.id for _, group in multiphone.mode_groups(two("HomeNet", "MTS-Router"), False) for m in group]
        self.assertEqual(ids, ["sim1@AAA", "wifi@AAA", "sim1@BBB", "wifi@BBB"])

    def test_single_phone_unchanged(self):
        ids = [m.id for _, group in multiphone.mode_groups(two()[:1], True) for m in group]
        self.assertEqual(ids, ["dc", "sim1", "wifi"])

    def test_shared_column_split_evenly_and_completely(self):
        phones = two()
        modes = [m for _, group in multiphone.mode_groups(phones, True) for m in group]
        nodes = targets(7)
        jobs = multiphone.plan(modes, phones, nodes)
        a, b = jobs[1], jobs[2]
        part_a, part_b = a.mode_targets["wifi@AAA+BBB"], b.mode_targets["wifi@AAA+BBB"]
        self.assertLessEqual(abs(len(part_a) - len(part_b)), 1)
        self.assertEqual({t["key"] for t in part_a} & {t["key"] for t in part_b}, set())
        self.assertEqual({t["key"] for t in part_a + part_b}, {t["key"] for t in nodes})
        self.assertNotIn("sim1@AAA", a.mode_targets)
        self.assertEqual([m.id for m in a.modes], ["wifi@AAA+BBB", "sim1@AAA"])

    def test_owner_gone_other_takes_everything(self):
        modes = [multiphone.shared_wifi_mode("HomeNet", ["AAA", "BBB"])]
        jobs = multiphone.plan(modes, two()[:1], targets(4))
        self.assertEqual(len(jobs), 1)
        self.assertNotIn("wifi@AAA+BBB", jobs[0].mode_targets)

    def test_phone_without_share_gets_no_shared_column(self):
        three = two() + [{"serial": "CCC", "index": 2, "tag": "A055F", "state": state((1, "T2"))}]
        modes = [multiphone.shared_wifi_mode("HomeNet", ["AAA", "BBB", "CCC"])]
        jobs = multiphone.plan(modes, three, targets(2))
        self.assertEqual([j.serial for j in jobs], ["AAA", "BBB"])
        self.assertEqual(sum(len(j.mode_targets["wifi@AAA+BBB+CCC"]) for j in jobs), 2)


class PortWindowTest(unittest.TestCase):
    """Окно портов - по серийнику среди всех телефонов на кабеле: окно и консоль на разных телефонах не совпадают."""

    def test_same_serial_same_window_in_any_process(self):
        cable = ["BBB", "AAA", "CCC"]
        window = multiphone.assign_port_windows(phones("AAA", "BBB", "CCC"), cable)
        console = multiphone.assign_port_windows(phones("CCC"), cable)
        by_serial = {p["serial"]: p["index"] for p in window}
        self.assertEqual(by_serial, {"AAA": 0, "BBB": 1, "CCC": 2})
        self.assertEqual(console[0]["index"], 2)
        jobs = multiphone.plan(multiphone.phone_modes(state((1, "MTS"))), console)
        self.assertEqual(jobs[0].shift, port_shift(2))

    def test_unknown_serial_still_gets_a_window(self):
        self.assertEqual(multiphone.assign_port_windows(phones("ZZZ"), ["AAA"])[0]["index"], 1)


class MergeSharedTest(unittest.TestCase):
    def run_part(self, tag, results, error="", ip="203.0.113.25"):
        return {"phone_tag": tag, "modes": [{"id": "wifi@AAA+BBB", "kind": "wifi", "label": "Wi-Fi",
                                              "ip": ip, "error": error, "results": results}]}

    def test_parts_become_one_column(self):
        merged = multiphone.merge_runs([self.run_part("A", {"k0": {"exit_ip": "1"}}),
                                        self.run_part("B", {"k1": {"exit_ip": ""}})], targets(2))
        self.assertEqual(len(merged["modes"]), 1)
        self.assertEqual(set(merged["modes"][0]["results"]), {"k0", "k1"})
        self.assertEqual(merged["modes"][0]["parts"], 2)

    def test_unchecked_and_slow_survive_merge(self):
        unchecked = {"exit_ip": "", "latency": None, "unchecked": "net"}
        slow = {"exit_ip": "198.51.100.2", "latency": None, "slow": True}
        merged = multiphone.merge_runs([self.run_part("A", {"k0": unchecked}),
                                        self.run_part("B", {"k1": slow})], targets(2))
        self.assertEqual(merged["modes"][0]["results"], {"k0": unchecked, "k1": slow})

    def test_one_part_failed_column_stays(self):
        merged = multiphone.merge_runs([self.run_part("A", {"k0": {"exit_ip": "1"}}),
                                        self.run_part("B", {}, error="нет интернета")], targets(2))
        column = merged["modes"][0]
        self.assertEqual(column["error"], "")
        self.assertEqual(column["partial_error"], "нет интернета")

    def test_all_parts_failed_column_is_error(self):
        merged = multiphone.merge_runs([self.run_part("A", {}, error="x"), self.run_part("B", {}, error="y")],
                                       targets(2))
        self.assertEqual(merged["modes"][0]["error"], "x; y")


class PlanTest(unittest.TestCase):
    def test_dc_gets_own_thread_and_phones_split(self):
        modes = [Mode("dc", "dc", "ДЦ")] + \
            multiphone.phone_modes(state((1, "MegaFon")), tag="T0", serial="AAA", multi=True) + \
            multiphone.phone_modes(state((1, "MTS")), tag="T1", serial="BBB", multi=True)
        jobs = multiphone.plan(modes, phones("AAA", "BBB"))
        self.assertEqual([j[0] for j in jobs], [None, "AAA", "BBB"])
        self.assertEqual([m.kind for m in jobs[0][3]], ["dc"])
        self.assertEqual(len(jobs[1][3]), 2)
        self.assertEqual(jobs[1][1], port_shift(0))
        self.assertEqual(jobs[2][1], port_shift(1))
        self.assertNotEqual(jobs[1][1], jobs[2][1])

    def test_single_phone_plain_ids_go_to_it(self):
        modes = multiphone.phone_modes(state((1, "MegaFon")))
        jobs = multiphone.plan(modes, phones("AAA"))
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0][0], "AAA")
        self.assertEqual(jobs[0][2], "")

    def test_unchecked_phone_gets_no_thread(self):
        modes = multiphone.phone_modes(state((1, "MegaFon")), tag="T0", serial="AAA", multi=True)
        jobs = multiphone.plan(modes, phones("AAA", "BBB"))
        self.assertEqual([j[0] for j in jobs], ["AAA"])


class MergeTest(unittest.TestCase):
    def test_columns_in_plan_order_and_times_span(self):
        targets = [{"location": "DE", "key": "k1"}]
        runs = [
            {"started": "2026-09-24 10:00:00", "finished": "2026-09-24 10:05:00", "modes": [{"id": "dc"}]},
            {"started": "2026-09-24 10:00:01", "finished": "2026-09-24 10:20:00", "phone_tag": "A075F",
             "modes": [{"id": "sim1@AAA"}], "geo": {"available": True, "verdict": "ok A"}},
            None,
            {"started": "2026-09-24 10:00:02", "finished": "2026-09-24 10:15:00", "phone_tag": "A175F",
             "modes": [{"id": "sim1@BBB"}], "geo": {"available": True, "verdict": "ok B"}},
        ]
        merged = multiphone.merge_runs(runs, targets)
        self.assertEqual([m["id"] for m in merged["modes"]], ["dc", "sim1@AAA", "sim1@BBB"])
        self.assertEqual(merged["started"], "2026-09-24 10:00:00")
        self.assertEqual(merged["finished"], "2026-09-24 10:20:00")
        self.assertEqual(merged["geo"]["verdict"], "ok A")
        self.assertEqual(set(merged["geo_by_phone"]), {"A075F", "A175F"})
        self.assertEqual(merged["phones"], ["A075F", "A175F"])


if __name__ == "__main__":
    unittest.main()
