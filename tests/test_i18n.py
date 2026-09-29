"""Переводы интерфейса: всё переведено, подстановки %s/%d в переводе те же, что в оригинале."""
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from stand import i18n  # noqa: E402
from tools import i18n_check  # noqa: E402

PLACEHOLDER = re.compile(r"%(?:\([a-z_]+\))?[-+ 0#]*\d*(?:\.\d+)?[sdfrx%]")


class I18nTest(unittest.TestCase):
    def test_everything_translated(self):
        self.assertEqual(i18n_check.main(), 0, "есть строки без перевода - см. вывод tools/i18n_check.py")

    def test_placeholders_match(self):
        for ru, en in i18n.load_table("en").items():
            self.assertEqual(sorted(PLACEHOLDER.findall(ru)), sorted(PLACEHOLDER.findall(en)), ru)

    def test_switch(self):
        try:
            i18n.set_language("en")
            self.assertEqual(i18n.t("такой строки нет"), "такой строки нет")
            i18n.set_language("ru")
            self.assertEqual(i18n.t("Настройки"), "Настройки")
        finally:
            i18n.set_language("ru")


if __name__ == "__main__":
    unittest.main()
