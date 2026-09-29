"""Регионы и города агентов на языке интерфейса."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from stand import i18n, places  # noqa: E402


class PlacesTest(unittest.TestCase):
    def tearDown(self):
        i18n.set_language("ru")

    def test_region_both_ways(self):
        i18n.set_language("en")
        self.assertEqual(places.region("Свердловская область"), "Sverdlovsk Oblast")
        self.assertEqual(places.region("Республика Северная Осетия — Алания"), "North Ossetia-Alania")
        self.assertEqual(places.region("Moscow Oblast"), "Moscow Oblast")
        self.assertEqual(places.region("Moscow"), "Moscow")
        i18n.set_language("ru")
        self.assertEqual(places.region("Sverdlovsk Oblast"), "Свердловская область")
        self.assertEqual(places.region("Altai Krai"), "Алтайский край")
        self.assertEqual(places.region("Khanty-Mansiysk Autonomous Okrug"), "Ханты-Мансийский автономный округ - Югра")

    def test_unknown_and_city(self):
        i18n.set_language("en")
        self.assertEqual(places.region("Zaporizhzhia"), "Zaporizhzhia")
        self.assertEqual(places.city("Нижний Новгород"), "Nizhny Novgorod")
        self.assertEqual(places.city("Ростов-на-Дону"), "Rostov-on-Don")
        self.assertEqual(places.city("Тверь"), "Tver")
        self.assertEqual(places.describe({"city": "Москва", "region": "Москва"}), "Moscow")
        i18n.set_language("ru")
        self.assertEqual(places.city("Нижний Новгород"), "Нижний Новгород")
        self.assertEqual(places.describe({"city": "Москва", "region": "Moscow City"}), "Москва")


if __name__ == "__main__":
    unittest.main()
