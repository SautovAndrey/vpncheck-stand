"""Названия регионов и городов агентов на языке интерфейса.

Агенты присылают место как получится: геокодер телефона - по-русски, определение по IP - по-английски
и в разных написаниях. Регион узнаётся по таблице REGIONS из regions.json (русское название, английское,
другие написания; тот же файл сервер агентов читает, чтобы привести регион к одному виду) и показывается
на языке интерфейса; город в английском интерфейсе пишется латиницей.
Нераспознанное показывается как пришло (в английском - латиницей).
"""
import json
import os
import re

from . import i18n

REGIONS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "regions.json")


def _read_regions(path=REGIONS_PATH):
    """Таблица регионов из regions.json - тот же файл читает сервер агентов: [(по-русски, по-английски,
    «другое; написание»)]."""
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return []
    return [(item["ru"], item["en"], "; ".join(item.get("aliases") or [])) for item in data
            if isinstance(item, dict) and item.get("ru") and item.get("en")]


REGIONS = _read_regions()
NOISE = re.compile(r"\b(republic|of|the|region|autonomous|республика|автономный|автономная|г|город|city)\b")
KINDS = ((re.compile(r"\b(oblast|область)\b"), "obl"), (re.compile(r"\b(krai|kray|край)\b"), "kray"),
         (re.compile(r"\b(okrug|округ)\b"), "okrug"))
TRANSLIT = dict(zip("абвгдеёжзийклмнопрстуфхцчшщъыьэюя",
                    ["a", "b", "v", "g", "d", "e", "e", "zh", "z", "i", "y", "k", "l", "m", "n", "o", "p", "r",
                     "s", "t", "u", "f", "kh", "ts", "ch", "sh", "shch", "", "y", "", "e", "yu", "ya"], strict=True))

CITY_REGIONS = ("Москва", "Санкт-Петербург", "Севастополь")
CITIES = {
    "Москва": "Moscow", "Санкт-Петербург": "Saint Petersburg", "Нижний Новгород": "Nizhny Novgorod",
    "Ростов-на-Дону": "Rostov-on-Don", "Екатеринбург": "Yekaterinburg", "Нижний Тагил": "Nizhny Tagil",
    "Великий Новгород": "Veliky Novgorod", "Орёл": "Oryol", "Ельец": "Yelets", "Ессентуки": "Yessentuki",
}

_index = None
_cities = None


def _key(name):
    text = (name or "").lower().replace("ё", "е").replace("'", "")
    text = re.sub(r"[-—–_,.()]", " ", text)
    for pattern, kind in KINDS:
        text = pattern.sub(kind, text)
    return " ".join(NOISE.sub(" ", text).split())


def _kind(key):
    last = key.rsplit(" ", 1)[-1]
    return last if last in ("obl", "kray", "okrug") else ""


def _load():
    global _index
    if _index is None:
        _index = {}
        for name_ru, name_en, aliases in REGIONS:
            kind = _kind(_key(name_en))
            for variant in [name_ru, name_en] + [a.strip() for a in aliases.split(";") if a.strip()]:
                key = _key(variant)
                _index.setdefault(key, (name_ru, name_en))
                if kind and not _kind(key):
                    _index.setdefault(key + " " + kind, (name_ru, name_en))
    return _index


def transliterate(text):
    out = []
    for char in text or "":
        low = char.lower()
        if low in TRANSLIT:
            latin = TRANSLIT[low]
            out.append(latin.capitalize() if char != low and latin else latin)
        else:
            out.append(char)
    return "".join(out).replace("—", "-")


def region(name):
    """Регион на языке интерфейса."""
    if not name:
        return ""
    pair = _load().get(_key(name))
    english = i18n.language() == "en"
    if pair:
        return pair[1] if english else pair[0]
    return transliterate(name) if english else name


def _city_index():
    global _cities
    if _cities is None:
        _cities = {}
        for name_ru, name_en in CITIES.items():
            for variant in (name_ru, name_en):
                _cities.setdefault(_key(variant), (name_ru, name_en))
    return _cities


def city(name):
    """Город: в английском интерфейсе - латиницей; крупные города и города-регионы - по таблице."""
    if not name:
        return ""
    english = i18n.language() == "en"
    pair = _city_index().get(_key(name))
    if pair is None:
        pair = _load().get(_key(name))
        if pair and pair[0] not in CITY_REGIONS:
            pair = None
    if pair:
        return pair[1] if english else pair[0]
    return transliterate(name) if english else name


def describe(item):
    """«Город, регион» из записи агента или отчёта; регион, совпадающий с городом, не повторяется."""
    town, area = city(item.get("city")), region(item.get("region"))
    if town and area and town.lower() == area.lower():
        area = ""
    return ", ".join(part for part in (town, area) if part)
