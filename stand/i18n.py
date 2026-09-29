"""Два языка интерфейса: русский (исходный) и английский.

Тексты пишутся в коде по-русски и оборачиваются в t():

    label = QLabel(t("Телефон не подключён"))
    log(t("проверено %d из %d") % (done, total))     # подстановки - после t(), ключ остаётся шаблоном

Английские переводы лежат в stand/locale/en/*.json - словари {русский текст: английский}. Файлов
несколько, чтобы переводы разных окон не мешали друг другу; при загрузке они сливаются. Нет
перевода - показываем русский текст, программа не ломается.

Язык выбирается в «Настройках» (auto / ru / en) и применяется после перезапуска: многие тексты
собираются один раз при создании окна. auto - русский, если система русская, иначе английский.
Переменная окружения VPNCHECK_LANG перекрывает настройку (удобно для тестов и снимков экрана).
"""
import glob
import json
import locale
import os

LANGUAGES = (("auto", "Как в системе / System"), ("ru", "Русский"), ("en", "English"))
LOCALE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "locale")

_lang = None
_table = {}


def system_language():
    """ru, если система русская (Windows отдаёт Russian_Russia, Linux/mac - ru_RU), иначе en."""
    for getter in (lambda: locale.getlocale()[0], lambda: os.environ.get("LANG"), _qt_locale):
        try:
            name = (getter() or "").lower()
        except Exception:
            name = ""
        if name:
            return "ru" if name.startswith(("ru", "russian")) else "en"
    return "en"


def _qt_locale():
    from PySide6.QtCore import QLocale
    return QLocale.system().name()


def load_table(lang):
    table = {}
    for path in sorted(glob.glob(os.path.join(LOCALE_DIR, lang, "*.json"))):
        with open(path, encoding="utf-8") as handle:
            table.update({k: v for k, v in json.load(handle).items() if v})
    return table


def set_language(lang):
    """ru / en / auto. Звать до создания окон; без вызова язык берётся из настроек при первом t()."""
    global _lang, _table
    if lang not in ("ru", "en"):
        lang = system_language()
    _lang = lang
    _table = load_table(lang) if lang != "ru" else {}


def language():
    if _lang is None:
        wanted = os.environ.get("VPNCHECK_LANG")
        if not wanted:
            from .storage import load_settings
            wanted = load_settings().get("language", "auto")
        set_language(wanted)
    return _lang


def t(text):
    """Перевод строки интерфейса. Ключ - русский текст как он написан в коде."""
    if language() == "ru":
        return text
    return _table.get(text, text)
