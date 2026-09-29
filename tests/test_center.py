"""Центр: в карту идут только числа, коды ошибок - словами, надёжные цифры, выкладка не больше лимита."""
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from stand import multiphone  # noqa: E402
from stand.ui import center, mapscheme  # noqa: E402


class CenterHelpersTest(unittest.TestCase):
    def test_coordinates_only_finite_numbers(self):
        self.assertEqual(center.agent_point({"lat": "55.7", "lon": 37.6}), (55.7, 37.6))
        for bad in ("0);fetch('file:///C:/x');(0", "nan", "inf", None, True, 200, [1]):
            self.assertIsNone(center.agent_point({"lat": 55, "lon": bad}), bad)

    def test_error_kind_codes_and_modes(self):
        self.assertEqual(center.error_kind("check"), "проверка")
        self.assertEqual(center.error_kind("core-start"), "ядро проверки не запустилось")
        self.assertEqual(center.error_kind("cmd-diag"), "команда diag")
        self.assertEqual(center.error_kind("mode:MTS RUS"), "режим MTS RUS")
        self.assertEqual(center.error_kind("режим ДЦ"), "режим ДЦ")
        self.assertEqual(center.error_kind("crash"), "падение")
        for kind, name in (("link", "канал: связь"), ("update", "обновление"), ("push-token", "push-токен"),
                           ("report-deferred", "отчёт отложен"), ("core-direct", "ядро не вышло в интернет"),
                           ("core-exit", "ядро упало на узле")):
            self.assertEqual(center.error_kind(kind), name)
        self.assertEqual(center.error_kind("что-то новое"), "что-то новое")

    def test_fleet_zero_skips_untrusted(self):
        now = time.time()
        agents = [{"total": 5, "alive": 0, "last_seen": now} for _ in range(3)]
        self.assertEqual(center.fleet_zero(agents, now=now), 3)
        agents[0]["last_trusted"] = False
        self.assertEqual(center.fleet_zero(agents, now=now), 0)

    def test_pick_spread_keeps_every_location(self):
        targets = [{"location": "A", "key": "a%d" % i} for i in range(400)] + [{"location": "B", "key": "b1"}]
        picked = center.pick_spread(targets, 300)
        self.assertEqual(len(picked), 300)
        self.assertIn("b1", {target["key"] for target in picked})

    def test_status_words(self):
        now = time.time()
        self.assertEqual(center.agent_status({"online": True, "last_seen": now}, now)[0], "● онлайн сейчас")
        self.assertEqual(center.agent_status({"last_seen": now - 3600}, now)[0], "● на связи")
        self.assertEqual(center.agent_status({"last_seen": now - 86400}, now)[0], "● молчит")
        self.assertEqual(center.agent_status({"last_seen": now - 30 * 86400}, now)[0], "● не выходит")

    def test_asset_path_stays_inside_assets(self):
        self.assertTrue(mapscheme.asset_path("/map.html"))
        self.assertTrue(mapscheme.asset_path("/leaflet/leaflet.js"))
        for bad in ("/../center.py", "/..%2F..%2Fstorage.py", "/make_icon.py", "/../../../Windows/win.ini", "", "/"):
            self.assertIsNone(mapscheme.asset_path(bad), bad)


class DcLabelTest(unittest.TestCase):
    def test_label_with_place(self):
        self.assertEqual(multiphone.dc_label({"probe": {"host": "x", "place": "Москва"}}), "ДЦ · Москва")
        self.assertEqual(multiphone.dc_label({"probe": {"host": "x"}}), "ДЦ")
        groups = multiphone.mode_groups([], "ДЦ · Франкфурт")
        self.assertEqual(groups[0][1][0].label, "ДЦ · Франкфурт")
        self.assertEqual(multiphone.mode_groups([], True)[0][1][0].label, "ДЦ")


if __name__ == "__main__":
    unittest.main()
