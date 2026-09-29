"""Приёмник данных агентов VPNCheck: отдаёт агентам список узлов и манифест обновлений, принимает отчёты.

Запуск: ADMIN_TOKEN=... python run.py --host 0.0.0.0 --port 8787 (или uvicorn app:app - без защит run.py)
Язык: VPNCHECK_LANG=ru (по умолчанию) или en - тексты ошибок и тревог Telegram, читается при старте.
Данные: agents.db (SQLite), state.json, backups/ и files/ (APK, ядро) - в каталоге VPNAGENT_DATA
(по умолчанию рядом с файлом, как в прежних установках).
"""
import asyncio
import contextlib
import datetime
import gzip
import hmac
import html
import io
import ipaddress
import json
import math
import os
import re
import shutil
import sqlite3
import tarfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import OrderedDict, deque
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from starlette.middleware.gzip import GZipMiddleware
from starlette.requests import ClientDisconnect

import fcm

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("VPNAGENT_DATA") or HERE
DB_PATH = os.path.join(DATA_DIR, "agents.db")
FILES_DIR = os.path.join(DATA_DIR, "files")
STATE_PATH = os.path.join(DATA_DIR, "state.json")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")
MAX_REPORT_BYTES = 256 * 1024
MAX_UPLOAD_BYTES = 120 * 1024 * 1024
MAX_RESULTS = 500
AGENT_ID_RE = re.compile(r"^[0-9a-fA-F-]{8,64}$")
RATE_WINDOW, RATE_LIMIT = 60.0, 120
TRUSTED_PROXIES = {"127.0.0.1", "::1"}

LANG = os.environ.get("VPNCHECK_LANG", "ru").strip().lower()
EN = {
    "нет доступа": "access denied",
    "слишком часто": "too many requests",
    "нужен agent_id": "agent_id required",
    "нужен text": "text required",
    "нужен agent_id и action из: %s": "agent_id and action required, one of: %s",
    "для %s нужен text": "%s requires text",
    "не JSON": "not JSON",
    "координаты": "coordinates",
    "координаты вне диапазона": "coordinates out of range",
    "слишком большой отчёт": "report too large",
    "слишком большой запрос": "request too large",
    "слишком много опросов с этого адреса": "too many polls from this address",
    "агент неизвестен серверу": "agent unknown to the server",
    "база сервера переполнена": "server database is full",
    "слишком много новых агентов с этого адреса": "too many new agents from this address",
    "не объект": "not an object",
    "%s: только https": "%s: https only",
    "location_round: число от %d до %d": "location_round: a number from %d to %d",
    "nodes: список до 300": "nodes: list of up to 300",
    "nodes: неверные extra_outbounds у узла %s": "nodes: invalid extra_outbounds for node %s",
    "имя файла: только буквы, цифры, точка, дефис": "file name: letters, digits, dot and hyphen only",
    "файл больше %d МБ": "file larger than %d MB",
    "APK ещё не выложен": "APK not uploaded yet",
    "сайт": "site",
    "узел": "node",
    "🔴 %s %s перестал отвечать: %s %s": "🔴 %s %s stopped responding: %s %s",
    "🔴 %s %s так и не отвечает после перебоев: %s %s": "🔴 %s %s is still down after working on and off: %s %s",
    "(не отвечает в единственном месте, где его проверяют)": "(down in the only place it is checked from)",
    "(не отвечает сейчас: мест %d из %d)": "(places down now: %d of %d)",
    "🟢 %s %s снова отвечает: %s (ещё не отвечает: мест %d из %d)":
        "🟢 %s %s is responding again: %s (still down: %d of %d places)",
    "🟢 %s %s снова отвечает: %s (теперь отвечает везде)": "🟢 %s %s is responding again: %s (now up everywhere)",
    "%s %s работает с перебоями: %s - отвечал в %d%% проверок за сутки, %s. Пока перебои не кончатся (не меньше "
    "суток), тревог по нему там не будет, потом придёт итог.":
        "%s %s works on and off: %s - up in %d%% of checks in the last 24 h, %s. No alerts for it there until it "
        "settles down (at least 24 h), then you'll get the outcome.",
    "во всех местах": "in all places",
    "сейчас не отвечает": "down now",
    "сейчас отвечает": "up now",
    "сейчас не отвечает: мест %d из %d": "down now: %d of %d places",
    "было %d ч назад": "happened %d h ago",
    "было %d дн. назад": "happened %d days ago",
    "…и ещё %d": "…and %d more",
    "…и ещё %d - все тревоги: стенд → Агенты → Центр управления агентами → Стабильность":
        "…and %d more - all alerts: stand → Agents → Agent control center → Stability",
    "(в Telegram не ушло)": "(not delivered to Telegram)",
    "🔴 %s %s не отвечал: %s, %s - %s UTC": "🔴 %s %s was down: %s, %s - %s UTC",
    "🟡 %s %s работал с перебоями: %s": "🟡 %s %s worked on and off: %s",
    "<b>VPNCheck</b> ⚠ За 3 часа ни один агент не достучался ни до одного узла (агенты из %d разных сетей). "
    "Операторы так не режут - скорее всего, истекла учётка узлов агентов, узлы сменились в панели или панель "
    "недоступна. Перевыложите узлы: стенд → Агенты → Центр управления агентами → Узлы и обновления.":
        "<b>VPNCheck</b> ⚠ In the last 3 hours no agent reached any node (agents on %d different networks). "
        "Carriers don't block like that - most likely the agents' node account expired, the nodes changed in the "
        "panel, or the panel is down. Re-publish the nodes: stand → Agents → Agent control center → Nodes and "
        "updates.",
    "<b>VPNCheck</b> ⚠ Учётка узлов агентов %s истекает %s UTC (осталось дней: %d) - после этого агенты не смогут "
    "подключаться к узлам. Перевыложите узлы: стенд → Агенты → Центр управления агентами → Узлы и обновления.":
        "<b>VPNCheck</b> ⚠ The agents' node account %s expires on %s UTC (days left: %d) - after that agents can't "
        "connect to the nodes. Re-publish the nodes: stand → Agents → Agent control center → Nodes and updates.",
    "<b>VPNCheck</b> ⛔ Учётка узлов агентов %s истекла %s - агенты не могут подключиться к узлам, проверки стоят. "
    "Перевыложите узлы (стенд заведёт новую учётку на 30 дней): стенд → Агенты → Центр управления агентами → Узлы "
    "и обновления.":
        "<b>VPNCheck</b> ⛔ The agents' node account %s expired %s - agents can't connect to the nodes, checks have "
        "stopped. Re-publish the nodes (the stand creates a new 30-day account): stand → Agents → Agent control "
        "center → Nodes and updates.",
    "<b>VPNCheck</b> ⚠ База сервера заполнена на %d%% (%d из %d МБ) - скоро начнут удаляться самые старые отчёты. "
    "Поднимите предел: %s (или освободите диск).":
        "<b>VPNCheck</b> ⚠ The server database is %d%% full (%d of %d MB) - the oldest reports will soon start being "
        "deleted. Raise the limit: %s (or free up disk space).",
    "<b>VPNCheck</b> ⚠ База сервера на пределе (%d МБ) - самые старые отчёты уже удаляются, хранятся последние %d "
    "дн. Поднимите предел: %s (или освободите диск).":
        "<b>VPNCheck</b> ⚠ The server database is at its limit (%d MB) - the oldest reports are already being "
        "deleted, the last %d days are kept. Raise the limit: %s (or free up disk space).",
    "Telegram: %s - проверьте TG_BOT_TOKEN / TG_ADMIN и что вы написали боту /start":
        "Telegram: %s - check TG_BOT_TOKEN / TG_ADMIN and that you sent /start to the bot",
    "Telegram не принял сообщение, тревоги выброшены: %s": "Telegram refused the message, alerts dropped: %s",
    "nodes: узел %s отклонён (%s)": "nodes: node %s refused (%s)",
    "бэкап пропущен: свободно %d МБ, нужно %d МБ": "backup skipped: %d MB free, %d MB needed",
    "на диске сервера мало места": "the server is low on disk space",
    "на диске сервера свободно %d МБ (нужно не меньше %d МБ) - отчёты агентов отклоняются (507)":
        "%d MB free on the server disk (at least %d MB needed) - agent reports are refused (507)",
    "<b>VPNCheck</b> ⚠ На диске сервера свободно %d МБ (нужно не меньше %d МБ) - отчёты агентов не принимаются, "
    "пока не освободится место. Освободите диск: старые копии в %s, журналы - journalctl --vacuum-size=100M.":
        "<b>VPNCheck</b> ⚠ %d MB free on the server disk (at least %d MB needed) - agent reports are refused until "
        "space is freed. Free up the disk: old backups in %s, logs - journalctl --vacuum-size=100M.",
    "<b>VPNCheck</b> ⚠ TLS-порт сервера не поднялся: %s. Агенты 0.12.9+ с закреплённым ключом не выйдут на "
    "связь, пока его не вернут: journalctl -u vpnagent -n 50, затем python server/deploy.py.":
        "<b>VPNCheck</b> ⚠ The server TLS port did not start: %s. Agents 0.12.9+ with a pinned key stay silent "
        "until it is back: journalctl -u vpnagent -n 50, then python server/deploy.py.",
}


def t(text: str) -> str:
    """Перевод строки для людей; при ru (по умолчанию) возвращает её как есть."""
    return EN.get(text, text) if LANG == "en" else text


REGION_FILES = (os.path.join(HERE, "regions.json"), os.path.join(os.path.dirname(HERE), "stand", "regions.json"))
REGION_NOISE = re.compile(r"\b(republic|of|the|region|autonomous|республика|автономный|автономная|г|город|city)\b")
REGION_KINDS = ((re.compile(r"\b(oblast|область)\b"), "obl"), (re.compile(r"\b(krai|kray|край)\b"), "kray"),
                (re.compile(r"\b(okrug|округ)\b"), "okrug"))
_regions: dict[str, tuple[str, str]] = {}


def _region_key(name: str) -> str:
    """Ключ сравнения названий региона - как places._key у стенда."""
    text = (name or "").lower().replace("ё", "е").replace("'", "")
    text = re.sub(r"[-—–_,.()]", " ", text)
    for pattern, kind in REGION_KINDS:
        text = pattern.sub(kind, text)
    return " ".join(REGION_NOISE.sub(" ", text).split())


def _region_kind(key: str) -> str:
    last = key.rsplit(" ", 1)[-1]
    return last if last in ("obl", "kray", "okrug") else ""


def load_regions(paths=REGION_FILES) -> dict:
    """Таблица регионов (regions.json - тот же файл, что у стенда в stand/places.py): ключ написания ->
    (по-русски, по-английски). Нет файла - регионы остаются как пришли."""
    index: dict[str, tuple[str, str]] = {}
    for path in paths:
        try:
            with open(path, encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            continue
        for item in data if isinstance(data, list) else []:
            if not isinstance(item, dict) or not item.get("ru") or not item.get("en"):
                continue
            pair = (str(item["ru"]), str(item["en"]))
            kind = _region_kind(_region_key(pair[1]))
            for variant in [pair[0], pair[1]] + [str(a) for a in item.get("aliases") or []]:
                key = _region_key(variant)
                index.setdefault(key, pair)
                if kind and not _region_kind(key):
                    index.setdefault(key + " " + kind, pair)
        break
    _regions.clear()
    _regions.update(index)
    return index


def canonical_region(name: str) -> str:
    """Регион одним (русским) названием: ipinfo пишет «Krasnodar Krai», телефон - «Краснодарский край»,
    иначе одно место делится на две колонки матрицы и на два счёта свидетелей. Незнакомое - как есть."""
    pair = _regions.get(_region_key(name)) if name else None
    return pair[0] if pair else (name or "")


load_regions()
TRANSLIT = dict(zip("абвгдеёжзийклмнопрстуфхцчшщъыьэюя",
                    ["a", "b", "v", "g", "d", "e", "e", "zh", "z", "i", "y", "k", "l", "m", "n", "o", "p", "r",
                     "s", "t", "u", "f", "kh", "ts", "ch", "sh", "shch", "", "y", "", "e", "yu", "ya"], strict=True))
PLACE_WORDS = {"автономный округ": "Autonomous Okrug", "автономная область": "Autonomous Oblast",
               "область": "Oblast", "край": "Krai", "Республика": "Republic"}


def place_name(text: str) -> str:
    """Регион или город из отчёта на языке сервера. Регион сервер уже привёл к русскому названию по таблице
    регионов (canonical_region); при en - английское название из той же таблицы, незнакомое - латиницей.
    При ru - как есть."""
    if LANG != "en" or not text:
        return text
    pair = _regions.get(_region_key(text))
    if pair:
        return pair[1]
    for word, english in PLACE_WORDS.items():
        text = text.replace(word, english)
    return _latin(text)


def _latin(text: str) -> str:
    out = []
    for char in text:
        low = char.lower()
        latin = TRANSLIT.get(low)
        if latin is None:
            out.append(char)
        else:
            out.append(latin.capitalize() if char != low and latin else latin)
    return "".join(out)


RATE_MAX_KEYS = 20000


def rate_key(ip: str) -> str:
    """Ключ лимита: IPv4 как есть, IPv6 - по сети /64 (у одного абонента их целая сеть)."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if address.version == 6:
        if address.ipv4_mapped is not None:
            return str(address.ipv4_mapped)
        return str(ipaddress.ip_network("%s/64" % address, strict=False))
    return str(address)


def rate_key_wide(ip: str) -> str:
    """Ключ суточных квот и лимита новых агентов: IPv4 как есть, IPv6 - по сети /48 (столько выдают одному
    клиенту, и перебор /64 внутри неё не обходит квоту)."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if address.version == 6 and address.ipv4_mapped is None:
        return str(ipaddress.ip_network("%s/48" % address, strict=False))
    return rate_key(ip)


def net_key(ip: str) -> str:
    """Сеть адреса: IPv4 - /24, IPv6 - /48. Свидетели места и кэш гео считаются по сетям: мобильный адрес
    меняется каждый отчёт, а десяток agent_id с одного адреса - один свидетель."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return ip or ""
    if address.version == 6 and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return str(ipaddress.ip_network("%s/%d" % (address, 24 if address.version == 4 else 48), strict=False))


def pair_key(agent_id: str, ip: str) -> str:
    """Ключ лимитов «на агента»: agent_id вместе с адресом - чужой agent_id со своего адреса не выжигает
    лимиты настоящего агента."""
    return "%s|%s" % (agent_id, rate_key(ip) if ip else "")


class RateTable:
    """Скользящее окно на ключ. Ключи упорядочены по последнему обращению: при переполнении
    вытесняются самые давние за O(1), без сортировки всей таблицы под замком."""

    def __init__(self, limit: int, window: float = RATE_WINDOW, max_keys: int | None = None):
        self.limit, self.window, self.max_keys = limit, window, max_keys
        self.buckets: OrderedDict[str, deque] = OrderedDict()
        self.lock = threading.Lock()

    def clear(self):
        with self.lock:
            self.buckets.clear()

    def __len__(self):
        return len(self.buckets)

    def hit(self, key: str, now: float | None = None) -> bool:
        """True - лимит исчерпан (отметку не ставим), False - пропускаем и запоминаем."""
        now = time.time() if now is None else now
        limit_keys = self.max_keys or RATE_MAX_KEYS
        with self.lock:
            bucket = self.buckets.get(key)
            if bucket is None:
                while len(self.buckets) >= limit_keys:
                    self.buckets.popitem(last=False)
                bucket = self.buckets[key] = deque()
            else:
                self.buckets.move_to_end(key)
            while bucket and now - bucket[0] > self.window:
                bucket.popleft()
            if len(bucket) >= self.limit:
                return True
            bucket.append(now)
        return False


_rate = RateTable(RATE_LIMIT)
REPORTS_PER_AGENT, REPORTS_PER_IP = 6, 30
WRITES_PER_AGENT, WRITES_PER_IP = 20, 60
_report_agents = RateTable(REPORTS_PER_AGENT)
_report_ips = RateTable(REPORTS_PER_IP)
_write_agents = RateTable(WRITES_PER_AGENT)
_write_ips = RateTable(WRITES_PER_IP)


NEW_AGENTS_PER_IP = 20
NEW_AGENTS_WINDOW = 24 * 3600


class NewAgentTable:
    """Сколько разных НОВЫХ agent_id пришло с одного адреса (IPv6 - сеть /48) за окно: agent_id выдумывает
    кто угодно, и без этого лимит «на агента» ничего не стоит. Уже впущенный id с того же адреса - не новый."""

    def __init__(self, limit: int = NEW_AGENTS_PER_IP, window: float = NEW_AGENTS_WINDOW):
        self.limit, self.window = limit, window
        self.seen: OrderedDict[str, dict[str, float]] = OrderedDict()
        self.lock = threading.Lock()

    def clear(self):
        with self.lock:
            self.seen.clear()

    def admit(self, key: str, agent_id: str, now: float | None = None, commit: bool = True) -> bool:
        """True - впустить. commit=False - только проверить, не запоминая agent_id."""
        now = time.time() if now is None else now
        with self.lock:
            ids = self.seen.get(key)
            if ids is None:
                while len(self.seen) >= RATE_MAX_KEYS:
                    self.seen.popitem(last=False)
                ids = self.seen[key] = {}
            else:
                self.seen.move_to_end(key)
            for old in [aid for aid, ts in ids.items() if now - ts > self.window]:
                del ids[old]
            if agent_id in ids:
                return True
            if len(ids) >= self.limit:
                return False
            if commit:
                ids[agent_id] = now
            return True


_new_agents = NewAgentTable()


def rate_limited(ip: str) -> bool:
    return _rate.hit(rate_key(ip))


def limit_writes(agent_id: str, ip: str, report: bool = False):
    """Жёсткий лимит записи в базу: отдельно на агента (вместе с его адресом) и на адрес - иначе один источник
    за минуты раздувает базу мусорными отчётами и ошибками."""
    agents, ips = (_report_agents, _report_ips) if report else (_write_agents, _write_ips)
    if agents.hit(pair_key(agent_id, ip)) or (ip and ips.hit(rate_key(ip))):
        raise HTTPException(status_code=429, detail=t("слишком часто"))


def admit_agent(agent_id: str, ip: str, commit: bool = True) -> str:
    """Неизвестный серверу agent_id с этого адреса - не больше NEW_AGENTS_PER_IP новых в сутки (429).
    commit=False - только проверить; запомнить (_new_agents.admit по возвращённому ключу) - когда агент заведён.
    Возвращает ключ адреса ("" - проверять не нужно)."""
    if not ip or agent_known(agent_id):
        return ""
    key = rate_key_wide(ip)
    if not _new_agents.admit(key, agent_id, commit=commit):
        raise HTTPException(status_code=429, detail=t("слишком много новых агентов с этого адреса"))
    return key


def agent_known(agent_id: str) -> bool:
    if agent_id in _known_agents:
        return True
    try:
        with db() as conn:
            known = conn.execute("SELECT 1 FROM agents WHERE agent_id=?", (agent_id,)).fetchone() is not None
    except sqlite3.OperationalError:
        return False
    if known and len(_known_agents) < RATE_MAX_KEYS:
        _known_agents.add(agent_id)
    return known


MAX_DB_MB = 2048
DB_SIZE_TTL = 30.0
_db_size = {"ts": 0.0, "bytes": 0}
_db_size_lock = threading.Lock()


def db_used_bytes(now: float | None = None) -> int:
    """Занятое место базы (без свободных страниц) плюс WAL; пересчёт не чаще раза в DB_SIZE_TTL."""
    now = time.time() if now is None else now
    with _db_size_lock:
        if now - _db_size["ts"] < DB_SIZE_TTL:
            return _db_size["bytes"]
        _db_size["ts"] = now
    used = 0
    try:
        with contextlib.closing(sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT)) as conn:
            pages = conn.execute("PRAGMA page_count").fetchone()[0]
            free = conn.execute("PRAGMA freelist_count").fetchone()[0]
            size = conn.execute("PRAGMA page_size").fetchone()[0]
        used = (pages - free) * size
        with contextlib.suppress(OSError):
            used += os.path.getsize(DB_PATH + "-wal")
    except sqlite3.Error:
        used = 0
    with _db_size_lock:
        _db_size["bytes"] = used
    return used


EVICT_BATCH = 2000
_evict_lock = threading.Lock()
_evicted = [0.0]


EVICT_AGENT_SHARE = 10


def _evict_reports(conn, now) -> int:
    """Пачка отчётов на вытеснение: сначала агентов младше AGENT_TRUST_AGE (завести новый agent_id может кто
    угодно), и только если таких нет - самые старые по всей базе, но у одного агента не больше
    1/EVICT_AGENT_SHARE его отчётов за проход: история самого активного агента не стирается целиком."""
    removed = conn.execute("DELETE FROM reports WHERE id IN (SELECT id FROM reports WHERE agent_id IN "
                           "(SELECT agent_id FROM agents WHERE first_seen > ?) ORDER BY id LIMIT ?)",
                           (now - AGENT_TRUST_AGE, EVICT_BATCH)).rowcount
    if removed:
        return removed
    counts = dict(conn.execute("SELECT agent_id, COUNT(*) FROM reports GROUP BY agent_id").fetchall())
    taken: dict[str, int] = {}
    victims = []
    for report_id, agent_id in conn.execute("SELECT id, agent_id FROM reports ORDER BY ts LIMIT ?",
                                            (EVICT_BATCH * EVICT_AGENT_SHARE,)).fetchall():
        if taken.get(agent_id, 0) >= max(1, counts.get(agent_id, 0) // EVICT_AGENT_SHARE):
            continue
        taken[agent_id] = taken.get(agent_id, 0) + 1
        victims.append((report_id,))
        if len(victims) >= EVICT_BATCH:
            break
    conn.executemany("DELETE FROM reports WHERE id=?", victims)
    return len(victims)


def evict_oldest() -> int:
    """Освободить место: отчёты (см. _evict_reports), самые старые результаты команд и ошибки пачкой.
    Возвращает число удалённых строк; чистка уже идёт в другом потоке - -1 без ожидания."""
    if not _evict_lock.acquire(blocking=False):
        return -1
    try:
        with db() as conn:
            removed = _evict_reports(conn, time.time())
        if removed:
            _evicted[0] = time.time()
        for table, batch in (("results", EVICT_BATCH // 4), ("errors", EVICT_BATCH // 4)):
            with db() as conn:
                removed += conn.execute("DELETE FROM %s WHERE id IN (SELECT id FROM %s ORDER BY id LIMIT %d)"
                                        % (table, table, batch)).rowcount
        with contextlib.suppress(sqlite3.Error):
            with contextlib.closing(sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT)) as conn:
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        with _db_size_lock:
            _db_size["ts"] = 0.0
        return removed
    except sqlite3.Error:
        return 0
    finally:
        _evict_lock.release()


DISK_MIN_FREE = 200 * 1024 * 1024
DISK_ALERT_EVERY = 86400
DISK_FULL_RECENT = 600
_disk = {"low": False, "told": 0.0, "alerted": 0.0, "full_seen": 0.0, "free": None}
_disk_lock = threading.Lock()


def disk_free_bytes():
    try:
        return shutil.disk_usage(os.path.dirname(os.path.abspath(DB_PATH))).free
    except OSError:
        return None


def disk_trouble(free, now=None):
    """Диск кончается или SQLite ответил «database or disk is full»: одна строка в журнал сервера на случай
    (повтор - не раньше чем через DISK_ALERT_EVERY или после того, как место вернулось)."""
    now = time.time() if now is None else now
    with _disk_lock:
        if now - _disk["told"] < DISK_ALERT_EVERY:
            return
        _disk["told"] = now
    free_mb = -1 if free is None else free >> 20
    server_error("disk", t("на диске сервера свободно %d МБ (нужно не меньше %d МБ) - отчёты агентов отклоняются "
                           "(507)") % (free_mb, DISK_MIN_FREE >> 20))


def disk_low(now=None) -> bool:
    """Свободно меньше DISK_MIN_FREE на диске базы: отчёты - 507, в журнал и в Telegram - по разу."""
    free = disk_free_bytes()
    low = free is not None and free < DISK_MIN_FREE
    with _disk_lock:
        _disk["free"] = free
        changed = low != _disk["low"]
        _disk["low"] = low
        if changed and not low:
            _disk["told"] = 0.0
    if low:
        disk_trouble(free, now)
    return low


def db_full(exc) -> bool:
    return isinstance(exc, sqlite3.OperationalError) and "full" in str(exc).lower()


def note_db_full(now=None):
    now = time.time() if now is None else now
    with _disk_lock:
        _disk["full_seen"] = now
    disk_trouble(disk_free_bytes(), now)


def check_disk(now):
    """Тревога «диск кончается» (мимо часового лимита): свободно меньше DISK_MIN_FREE или недавно SQLite не смог
    писать, не чаще раза в DISK_ALERT_EVERY - отметка и в памяти (в базу при полном диске может не записаться).
    True - отправлено."""
    low = disk_low(now)
    with _disk_lock:
        recent = 0 < now - _disk["full_seen"] < DISK_FULL_RECENT
        last = _disk["alerted"]
        free = _disk["free"]
    if not low and not recent:
        return False
    with contextlib.suppress(sqlite3.Error), db() as conn:
        row = conn.execute("SELECT ts FROM alert_last WHERE key='disk_low'").fetchone()
        if row and row["ts"]:
            last = max(last, float(row["ts"]))
    if now - last < DISK_ALERT_EVERY:
        return False
    text = t("<b>VPNCheck</b> ⚠ На диске сервера свободно %d МБ (нужно не меньше %d МБ) - отчёты агентов не "
             "принимаются, пока не освободится место. Освободите диск: старые копии в %s, журналы - journalctl "
             "--vacuum-size=100M.") % (-1 if free is None else free >> 20, DISK_MIN_FREE >> 20, BACKUP_DIR)
    if not send_alert(text, now, force=True):
        return False
    with _disk_lock:
        _disk["alerted"] = now
    with contextlib.suppress(sqlite3.Error), db() as conn:
        conn.execute("INSERT INTO alerts(ts, kind, text) VALUES (?,?,?)", (now, "disk_low", _history_text(text)))
        conn.execute("INSERT OR REPLACE INTO alert_last(key, ts) VALUES ('disk_low', ?)", (now,))
    return True


def require_room():
    """База доросла до MAX_DB_MB (VPNAGENT_MAX_DB_MB) - вытесняем самые старые отчёты, а не отказываем всем.
    507 - только если вытеснять уже нечего или на диске свободно меньше DISK_MIN_FREE."""
    if disk_low():
        raise HTTPException(status_code=507, detail=t("на диске сервера мало места"))
    if db_used_bytes() <= db_limit_bytes():
        return
    if evict_oldest() == 0:
        raise HTTPException(status_code=507, detail=t("база сервера переполнена"))


def clip(value: Any, limit: int = 64) -> str:
    return str(value)[:limit] if value is not None else ""


DEFAULT_STATE = {"nodes": [], "interval_min": 180, "test_url": "https://api.ipify.org",
                 "latency_url": "https://www.google.com/generate_204", "manifest": None,
                 "message": "", "sites": [], "run_now": 0, "update_now": 0, "yandex_key": "", "location_round": 200,
                 "nodes_expire": 0, "nodes_user": ""}
STATIC_DIR = os.path.join(HERE, "static")
_run_now_agents: dict[str, float] = {}
_update_now_agents: dict[str, float] = {}
_locate_agents: dict[str, float] = {}

LINK_WAIT = 50
LINK_WAIT_MAX = 270
LINK_ONLINE = 90
_cmd_seq = 0
_cmds: deque = deque(maxlen=1000)
_online: dict[str, float] = {}
_polling: dict[str, int] = {}
POLLS_PER_KEY, POLLS_TOTAL = 48, 4000
UNKNOWN_POLLS_PER_KEY, UNKNOWN_POLLS_TOTAL = 2, 300
_poll_slots: dict[str, Any] = {"total": 0, "unknown": 0, "keys": {}, "unknown_keys": {}}
SAFE_ACTIONS = {"check", "update", "locate", "message", "vpn_off",
                "site_check", "diag", "xray_log", "speed", "whitelist_banner"}
RESULT_ACTIONS = {"site_check", "diag", "xray_log", "speed", "whitelist_banner"}
MAX_RESULT_BYTES = 64 * 1024


def enqueue_command(agent_id, action, text=""):
    """Положить команду в шину. Пустой agent_id - всем агентам.
    Номер команды монотонный по времени (мс) - иначе после передеплоя сервера счётчик обнулялся,
    а агент помнил высокий last-seen и пропускал новые команды."""
    global _cmd_seq
    if action not in SAFE_ACTIONS:
        return None
    now = time.time()
    while _cmds and _cmds[0]["ts"] < now - COMMAND_TTL:
        _cmds.popleft()
    _cmd_seq = max(_cmd_seq + 1, int(now * 1000))
    _cmds.append({"seq": _cmd_seq, "agent_id": clip(agent_id), "action": action,
                  "text": clip(text, 400), "ts": now})
    wake_polls()
    return _cmd_seq


_wake: dict[str, Any] = {"loop": None, "event": None}


def _wake_event() -> asyncio.Event:
    """Событие «появилась команда» для текущего цикла событий: опрос ждёт его, а не просыпается раз в секунду."""
    loop = asyncio.get_running_loop()
    if _wake["loop"] is not loop or _wake["event"] is None:
        _wake["loop"], _wake["event"] = loop, asyncio.Event()
    return _wake["event"]


def _wake_all():
    event = _wake["event"]
    _wake["event"] = asyncio.Event()
    if event is not None:
        event.set()


def wake_polls():
    """Разбудить висящие опросы; безопасно звать из любого потока."""
    loop = _wake["loop"]
    if loop is None or loop.is_closed():
        return
    try:
        running = asyncio.get_running_loop()
    except RuntimeError:
        running = None
    if running is loop:
        _wake_all()
        return
    with contextlib.suppress(RuntimeError):
        loop.call_soon_threadsafe(_wake_all)


COMMAND_TTL = 15 * 60


def commands_for(agent_id, after, now=None):
    """Команды агенту после номера after. after=0 - агент только подключился: команд не отдаём, он запомнит
    seq из ответа. Старше COMMAND_TTL не отдаём: вернувшийся после долгого молчания не должен получить
    пачку давно неактуальных команд."""
    if after <= 0:
        return []
    fresh_after = (now or time.time()) - COMMAND_TTL
    return [c for c in _cmds if c["seq"] > after and c["ts"] >= fresh_after and c["agent_id"] in ("", agent_id)]


def online_now(agent_id):
    agent_id = clip(agent_id)
    return _polling.get(agent_id, 0) > 0 or (time.time() - _online.get(agent_id, 0)) < LINK_ONLINE


MAX_SITES = 50
LOCATION_ROUND_MIN, LOCATION_ROUND_MAX = 1, 5000
MAX_ERRORS_PER_REPORT = 20
MAX_SCALAR_KEYS = 40


def store_errors(conn, agent_id, app_version, model, items):
    """items: [{ts, kind, text}] от агента - обрезаем и складываем."""
    if not isinstance(items, list):
        return 0
    stored = 0
    for item in items[:MAX_ERRORS_PER_REPORT]:
        if not isinstance(item, dict):
            continue
        ts = item.get("ts")
        try:
            ts = float(ts) / (1000 if float(ts) > 1e11 else 1)
        except (TypeError, ValueError):
            ts = time.time()
        conn.execute("INSERT INTO errors(ts, agent_id, app_version, model, kind, text) VALUES (?,?,?,?,?,?)",
                     (ts, agent_id, clip(app_version, 32), clip(model), clip(item.get("kind", "error"), 32),
                      clip(item.get("text", ""), 4000)))
        stored += 1
    if stored:
        _cap_errors(conn, agent_id)
        _cap_errors_total(conn)
    return stored


@contextlib.asynccontextmanager
async def lifespan(_app):
    startup()
    yield


app = FastAPI(title="VPNCheck Agent Server", docs_url=None, redoc_url=None, lifespan=lifespan)

ADMIN_PREFIX = "/v1/admin/"
MAX_ADMIN_BYTES = 16 * 1024 * 1024
MAX_OTHER_BYTES = 64 * 1024
UPLOAD_OVERHEAD = 1024 * 1024


class BodyTooLarge(HTTPException):
    def __init__(self):
        super().__init__(status_code=413, detail=t("слишком большой запрос"))


def body_limit(path: str) -> int:
    """Предел тела запроса по пути: отчёт агента, результаты, файлы админки - каждому свой."""
    limits = {"/v1/report": MAX_REPORT_BYTES, "/v1/result": MAX_RESULT_BYTES, "/v1/location": 4096,
              "/v1/token": 8 * 1024, "/v1/errors": 64 * 1024,
              ADMIN_PREFIX + "upload": MAX_UPLOAD_BYTES + UPLOAD_OVERHEAD}
    if path in limits:
        return limits[path]
    return MAX_ADMIN_BYTES if path.startswith(ADMIN_PREFIX) else MAX_OTHER_BYTES


def admin_token_ok(token: str) -> bool:
    return bool(ADMIN_TOKEN) and hmac.compare_digest(token.encode(), ADMIN_TOKEN.encode())


class BodyGuard:
    """Прослойка до разбора запроса: админ-пути без верного X-Admin-Token - 401 без чтения тела; тело длиннее
    предела пути - 413 по Content-Length сразу, а без него (chunked) - как только прочитано больше предела.
    Иначе FastAPI читал тело целиком в память (или multipart на диск) и только потом проверял размер и токен."""

    def __init__(self, inner):
        self.inner = inner

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.inner(scope, receive, send)
            return
        path = scope.get("path") or ""
        headers = {key.decode("latin-1").lower(): value.decode("latin-1") for key, value in scope.get("headers") or []}
        if path.startswith(ADMIN_PREFIX) and not admin_token_ok(headers.get("x-admin-token", "")):
            await self._reply(send, 401, t("нет доступа"))
            return
        limit = body_limit(path)
        declared = headers.get("content-length")
        if declared is not None:
            if not declared.strip().isdigit():
                await self._reply(send, 400, "content-length")
                return
            if int(declared) > limit:
                await self._reply(send, 413, t("слишком большой запрос"))
                return
        started = False
        overflow = False
        seen = 0

        async def limited_receive():
            nonlocal seen, overflow
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body") or b"")
                if seen > limit:
                    overflow = True
                    raise BodyTooLarge()
            return message

        async def tracked_send(message):
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
                if overflow:
                    message = {**message, "headers": [*(message.get("headers") or []), (b"connection", b"close")]}
            await send(message)

        try:
            await self.inner(scope, limited_receive, tracked_send)
        except BodyTooLarge:
            if not started:
                await self._reply(send, 413, t("слишком большой запрос"))

    @staticmethod
    async def _reply(send, status, detail):
        body = json.dumps({"detail": detail}, ensure_ascii=False).encode("utf-8")
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
                                (b"connection", b"close")]})
        await send({"type": "http.response.body", "body": body})


app.add_middleware(BodyGuard)


@app.exception_handler(ClientDisconnect)
async def client_gone(request: Request, _exc: ClientDisconnect):
    """Клиент оборвал соединение посреди тела (телефон сменил сеть) - одна строка в журнал, без трейсбека."""
    print("client disconnected mid-request: %s %s" % (request.url.path, client_ip(request)), flush=True)
    return Response(status_code=400)


@app.exception_handler(sqlite3.OperationalError)
async def sqlite_failed(_request: Request, exc: sqlite3.OperationalError):
    """SQLite не может писать, потому что диск (или база) заполнен - 507 и одна запись в журнал и в Telegram, а
    не 500 с трейсбеком на каждый отчёт; прочие ошибки SQLite - как были."""
    if not db_full(exc):
        raise exc
    await asyncio.get_running_loop().run_in_executor(None, note_db_full)
    return JSONResponse({"detail": t("на диске сервера мало места")}, status_code=507)


class AdminGZip:
    """Ответы админки (матрица, отчёты, тренды - мегабайты JSON) сжимаются; файлы, APK и запросы агентов
    идут как были."""

    def __init__(self, inner):
        self.inner = inner
        self.gzip = GZipMiddleware(inner, minimum_size=1024)

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and (scope.get("path") or "").startswith(ADMIN_PREFIX):
            await self.gzip(scope, receive, send)
        else:
            await self.inner(scope, receive, send)


app.add_middleware(AdminGZip)


DB_TIMEOUT = 30


@contextlib.contextmanager
def db():
    """Соединение на один блок: коммит при успехе, откат при ошибке и обязательное закрытие -
    иначе соединения закрывал бы только сборщик мусора. Занятая база - ждём до DB_TIMEOUT, а не 5 с."""
    conn = sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT)
    conn.row_factory = sqlite3.Row
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def init_db():
    """Схема и миграции. WAL: читатели и опросы не ждут, пока пишется отчёт или идёт чистка."""
    with contextlib.closing(sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT)) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
    with db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS agents (
            agent_id TEXT PRIMARY KEY, first_seen REAL, last_seen REAL, app_version TEXT, core_version TEXT,
            model TEXT, android TEXT, ip TEXT, country TEXT, region TEXT, city TEXT, lat REAL, lon REAL,
            org TEXT, operator TEXT, network TEXT, alive INTEGER, total INTEGER, note TEXT DEFAULT '');
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id TEXT, ts REAL, ip TEXT, region TEXT, city TEXT,
            operator TEXT, network TEXT, alive INTEGER, total INTEGER, payload TEXT);
        CREATE INDEX IF NOT EXISTS reports_ts ON reports(ts);
        CREATE TABLE IF NOT EXISTS geo (ip TEXT PRIMARY KEY, data TEXT, ts REAL);
        CREATE TABLE IF NOT EXISTS places (key TEXT PRIMARY KEY, data TEXT, ts REAL);
        CREATE TABLE IF NOT EXISTS push (agent_id TEXT PRIMARY KEY, token TEXT, ts REAL);
        CREATE TABLE IF NOT EXISTS node_state (
            node TEXT, scope TEXT, ok INTEGER, checks INTEGER, ok_checks INTEGER, changed REAL, ts REAL,
            PRIMARY KEY (node, scope));
        CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, kind TEXT, text TEXT);
        CREATE TABLE IF NOT EXISTS errors (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, agent_id TEXT, app_version TEXT, model TEXT,
            kind TEXT, text TEXT);
        CREATE INDEX IF NOT EXISTS errors_ts ON errors(ts);
        CREATE TABLE IF NOT EXISTS results (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, agent_id TEXT, action TEXT, seq INTEGER, payload TEXT);
        CREATE INDEX IF NOT EXISTS results_agent ON results(agent_id, ts);
        CREATE TABLE IF NOT EXISTS scope_agents (scope TEXT, agent_id TEXT, ts REAL, PRIMARY KEY (scope, agent_id));
        CREATE TABLE IF NOT EXISTS alert_pending (
            key TEXT PRIMARY KEY, node TEXT, scope TEXT, ok INTEGER, rate REAL, checks INTEGER, agent_id TEXT,
            witnesses INTEGER, ts REAL);
        """)
        _add_columns(conn, "reports", {"trusted": "INTEGER DEFAULT 1", "partial": "INTEGER DEFAULT 0",
                                       "report_id": "TEXT"})
        _add_columns(conn, "agents", {"last_trusted": "INTEGER", "last_partial": "INTEGER", "trusted_ts": "REAL",
                                      "report_ts": "REAL", "last_tls": "REAL"})
        _add_columns(conn, "push", {"ip": "TEXT"})
        _add_columns(conn, "node_state", {"streak": "INTEGER DEFAULT 0", "w_checks": "REAL", "w_ok": "REAL",
                                          "down_sent": "REAL", "recent": "TEXT", "flips": "INTEGER",
                                          "flips_since": "REAL", "d_since": "REAL", "d_checks": "INTEGER",
                                          "d_ok": "INTEGER"})
        _add_columns(conn, "alerts", {"node": "TEXT"})
        _add_columns(conn, "alert_pending", {"net": "TEXT", "note": "TEXT"})
        _add_columns(conn, "scope_agents", {"net": "TEXT"})
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS reports_report_id ON reports(agent_id, report_id) "
                     "WHERE report_id IS NOT NULL")
        conn.execute("CREATE INDEX IF NOT EXISTS results_ts ON results(ts)")
        conn.execute("CREATE INDEX IF NOT EXISTS errors_agent ON errors(agent_id, ts)")
        conn.execute("CREATE INDEX IF NOT EXISTS reports_agent ON reports(agent_id, ts)")
        conn.execute("CREATE INDEX IF NOT EXISTS agents_first_seen ON agents(first_seen)")
        _create_alert_last(conn)
        if conn.execute("PRAGMA user_version").fetchone()[0] < 1:
            _mark_old_reports(conn)
            conn.execute("PRAGMA user_version = 1")
        if conn.execute("PRAGMA user_version").fetchone()[0] < 2:
            _mark_open_downs(conn)
            conn.execute("PRAGMA user_version = 2")
        if conn.execute("PRAGMA user_version").fetchone()[0] < 3 and _regions:
            _merge_region_scopes(conn)
            conn.execute("PRAGMA user_version = 3")
        conn.execute("DELETE FROM node_state WHERE substr(scope, 1, 4) = '? · ' AND down_sent IS NOT NULL")
        conn.execute("UPDATE node_state SET w_checks=MIN(checks, ?), w_ok=ok_checks * MIN(checks, ?) * 1.0 / "
                     "MAX(checks, 1) WHERE w_checks IS NULL", (TREND_START_CHECKS, TREND_START_CHECKS))


def _create_alert_last(conn):
    """Когда последний раз тревожили по узлу|месту - своя таблица с ключом вместо LIKE по тексту тревог.
    Разово переносим отметки из прежней истории, чтобы после обновления не повторить свежие тревоги."""
    exists = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='alert_last'").fetchone()
    if exists:
        return
    conn.execute("CREATE TABLE alert_last (key TEXT PRIMARY KEY, ts REAL)")
    conn.execute("INSERT OR REPLACE INTO alert_last(key, ts) "
                 "SELECT substr(text, 1, length(text) - length(kind) - 1), MAX(ts) FROM alerts "
                 "WHERE kind IN ('up', 'down') AND text LIKE '%|' || kind GROUP BY 1")
    conn.execute("INSERT OR REPLACE INTO alert_last(key, ts) "
                 "SELECT 'fleet_zero', MAX(ts) FROM alerts WHERE kind='fleet_zero' HAVING MAX(ts) IS NOT NULL")


TREND_START_CHECKS = 50


def _mark_open_downs(conn):
    """Разово: «перестал отвечать», отправленный до обновления и ещё не закрытый «снова отвечает», - отметка
    down_sent у узла в месте, иначе восстановление после обновления пришло бы молча."""
    last: dict[str, tuple] = {}
    for row in conn.execute("SELECT ts, kind, text FROM alerts WHERE kind IN ('up', 'down') ORDER BY ts"):
        parts = str(row["text"] or "").rsplit("|", 2)
        if len(parts) == 3:
            last[parts[0] + "|" + parts[1]] = (row["kind"], row["ts"])
    for key, (kind, ts) in last.items():
        if kind == "down":
            node, _sep, scope = key.partition("|")
            conn.execute("UPDATE node_state SET down_sent=? WHERE node=? AND scope=? AND ok=0", (ts, node, scope))


def canonical_scope(scope):
    """Место «регион · оператор» с регионом одним названием (canonical_region)."""
    region, sep, operator = (scope or "").partition(" · ")
    return canonical_region(region) + sep + operator if sep else (scope or "")


SCOPE_SUM = ("checks", "ok_checks", "w_checks", "w_ok", "d_checks", "d_ok")
SCOPE_MAX = ("changed", "down_sent", "d_since", "flips", "flips_since")


def _merge_region_scopes(conn):
    """Разово: места, записанные до общей таблицы регионов («Krasnodar Krai · Tele2» рядом с «Краснодарский
    край · Tele2»), - одним местом. Счётчики проверок складываются, смены (flips), отметки времени и down_sent -
    наибольшие, состояние - от последней проверки; свидетели места, очередь тревог и паузы - так же по новому
    ключу. Без таблицы регионов не выполняется (и user_version не растёт) - повторится, когда таблица появится."""
    groups: dict[tuple, list] = {}
    for row in conn.execute("SELECT * FROM node_state").fetchall():
        groups.setdefault((row["node"], canonical_scope(row["scope"])), []).append(dict(row))
    for (node, scope), items in groups.items():
        if len(items) == 1 and items[0]["scope"] == scope:
            continue
        merged = dict(max(items, key=lambda item: item["ts"] or 0), scope=scope)
        for column in SCOPE_SUM:
            values = [item[column] for item in items if item.get(column) is not None]
            merged[column] = sum(values) if values else None
        for column in SCOPE_MAX:
            values = [item[column] for item in items if item.get(column) is not None]
            merged[column] = max(values) if values else None
        conn.executemany("DELETE FROM node_state WHERE node=? AND scope=?", [(node, item["scope"]) for item in items])
        columns = list(merged)
        conn.execute("INSERT INTO node_state(%s) VALUES (%s)" % (", ".join(columns), ", ".join("?" * len(columns))),
                     [merged[column] for column in columns])
    agents = [dict(row, scope=canonical_scope(row["scope"])) for row in conn.execute("SELECT * FROM scope_agents")]
    pending = [dict(row) for row in conn.execute("SELECT * FROM alert_pending")]
    for row in pending:
        if row["scope"]:
            row["scope"] = canonical_scope(row["scope"])
            flap = str(row["key"]).startswith(FLAP_PREFIX)
            row["key"] = "%s%s|%s" % (FLAP_PREFIX if flap else "", row["node"], row["scope"])
    _replace_rows(conn, "scope_agents", _latest_by(agents, lambda row: (row["scope"], row["agent_id"])))
    _replace_rows(conn, "alert_pending", _earliest_pending(pending))
    marks: dict[str, float] = {}
    for row in conn.execute("SELECT key, ts FROM alert_last").fetchall():
        parts = str(row["key"]).rsplit("|", 2)
        key = row["key"]
        if len(parts) == 3 and parts[2] in ("up", "down") and not key.startswith("node:"):
            key = "%s|%s|%s" % (parts[0], canonical_scope(parts[1]), parts[2])
        elif key.startswith(MUTE_PREFIX) and "|" in key:
            node, _sep, scope = key.rpartition("|")
            key = "%s|%s" % (node, canonical_scope(scope))
        marks[key] = max(marks.get(key, 0), row["ts"] or 0)
    conn.execute("DELETE FROM alert_last")
    conn.executemany("INSERT INTO alert_last(key, ts) VALUES (?,?)", list(marks.items()))


def _latest_by(rows, key_of) -> list:
    latest: dict = {}
    for row in rows:
        key = key_of(row)
        if key not in latest or (row["ts"] or 0) > (latest[key]["ts"] or 0):
            latest[key] = row
    return list(latest.values())


def _earliest_pending(rows) -> list:
    """Очередь тревог после слияния мест: по ключу - самое раннее событие со всеми свидетелями."""
    kept: dict = {}
    for row in sorted(rows, key=lambda item: item["ts"] or 0):
        if row["key"] in kept:
            kept[row["key"]]["witnesses"] = max(kept[row["key"]]["witnesses"] or 0, row["witnesses"] or 0)
        else:
            kept[row["key"]] = row
    return list(kept.values())


def _replace_rows(conn, table, rows):
    conn.execute("DELETE FROM %s" % table)
    for row in rows:
        columns = list(row)
        conn.execute("INSERT INTO %s(%s) VALUES (%s)" % (table, ", ".join(columns), ", ".join("?" * len(columns))),
                     [row[column] for column in columns])


def _add_columns(conn, table, columns):
    """Только добавление колонок: живая база на сервере переживает обновление без потерь."""
    present = {row["name"] for row in conn.execute("PRAGMA table_info(%s)" % table).fetchall()}
    for name, spec in columns.items():
        if name not in present:
            conn.execute("ALTER TABLE %s ADD COLUMN %s %s" % (table, name, spec))


def _mark_old_reports(conn):
    """Разово: у отчётов до появления колонок trusted/partial они стоят по умолчанию (1/0) -
    пересчитываем по сохранённому payload, иначе старые белые списки попадают в матрицу."""
    changes = []
    for row in conn.execute("SELECT id, payload, trusted, partial FROM reports"):
        payload = loads_stored(row["payload"])
        if not isinstance(payload, dict):
            continue
        trusted, partial = int(report_trusted(payload)), int(is_partial(payload))
        if (trusted, partial) != (row["trusted"], row["partial"]):
            changes.append((trusted, partial, row["id"]))
    conn.executemany("UPDATE reports SET trusted=?, partial=? WHERE id=?", changes)
    for agent in conn.execute("SELECT agent_id FROM agents").fetchall():
        last = conn.execute("SELECT trusted, partial FROM reports WHERE agent_id=? ORDER BY ts DESC LIMIT 1",
                            (agent["agent_id"],)).fetchone()
        good = conn.execute("SELECT alive, total, ts FROM reports WHERE agent_id=? AND trusted=1 AND partial=0 "
                            "AND COALESCE(operator, '') NOT LIKE 'VPN ·%' ORDER BY ts DESC LIMIT 1",
                            (agent["agent_id"],)).fetchone()
        if last is None:
            continue
        conn.execute("UPDATE agents SET last_trusted=?, last_partial=?, alive=?, total=?, trusted_ts=? "
                     "WHERE agent_id=?",
                     (last["trusted"], last["partial"], good["alive"] if good else None,
                      good["total"] if good else None, good["ts"] if good else None, agent["agent_id"]))


_state_lock = threading.Lock()
_state_cache: dict[str, Any] = {"key": None, "state": None}
_state_cache_lock = threading.Lock()


def load_state():
    """state.json с кэшем по файлу (inode, время, размер): опросы и отчёты читают его постоянно, а меняется
    он редко. Верхний уровень - своя копия, вложенное - общее, его не менять."""
    try:
        info = os.stat(STATE_PATH)
    except FileNotFoundError:
        return dict(DEFAULT_STATE)
    key = (STATE_PATH, info.st_ino, info.st_mtime_ns, info.st_size)
    with _state_cache_lock:
        if _state_cache["key"] == key:
            return dict(_state_cache["state"])
    state = dict(DEFAULT_STATE)
    with open(STATE_PATH, encoding="utf-8") as handle:
        state.update(json.load(handle))
    state = finite_state(state)
    with _state_cache_lock:
        _state_cache["key"], _state_cache["state"] = key, state
    return dict(state)


def finite_json(value) -> bool:
    try:
        json.dumps(value, allow_nan=False)
    except (TypeError, ValueError, RecursionError):
        return False
    return True


def finite_state(state):
    """state.json, записанный до проверки чисел: узлы с NaN/Infinity отбрасываются, прочие такие поля - по
    умолчанию; иначе /v1/config и админка отвечали бы 500 (ответы сериализуются с allow_nan=False)."""
    clean = {}
    for key, value in state.items():
        if key == "nodes" and isinstance(value, list):
            value = [node for node in value if finite_json(node)]
        elif not finite_json(value):
            value = DEFAULT_STATE.get(key)
        clean[key] = value
    return clean


def save_state(state):
    """Атомарно: пишем рядом во временный файл и подменяем - читатель никогда не видит полфайла.
    На Windows подмену открытого кем-то файла ОС ненадолго запрещает - тогда несколько повторов."""
    tmp = "%s.%d.%d.tmp" % (STATE_PATH, os.getpid(), threading.get_ident())
    try:
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(state, handle, ensure_ascii=False, indent=1)
        for attempt in range(20):
            try:
                os.replace(tmp, STATE_PATH)
                break
            except PermissionError:
                if attempt == 19:
                    raise
                time.sleep(0.05)
        with _state_cache_lock:
            _state_cache["key"] = None
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.remove(tmp)


def update_state(patch):
    """Прочитать-изменить-записать под локом: параллельные правки не затирают друг друга."""
    with _state_lock:
        state = load_state()
        state.update(patch)
        save_state(state)
        return state


def _reject_constant(name):
    raise ValueError("JSON constant %s" % name)


def _finite_float(text):
    value = float(text)
    if not math.isfinite(value):
        raise ValueError("JSON number out of range")
    return value


def loads_agent(body):
    """JSON от агента: NaN/Infinity и числа за пределами float - ошибка (400), а не значение, после которого
    ответы админки падают с 500."""
    return json.loads(body, parse_constant=_reject_constant, parse_float=_finite_float)


def loads_admin(body):
    """JSON из админки: как loads_agent, плюс повтор ключа в объекте запоминается (DuplicateKeys)."""
    return json.loads(body, object_pairs_hook=json_pairs, parse_constant=_reject_constant, parse_float=_finite_float)


async def _admin_body(request: Request) -> dict:
    """Тело команды админки; не JSON, не объект, NaN/Infinity - пустой словарь."""
    try:
        body = loads_agent(await request.body())
    except (ValueError, RecursionError):
        return {}
    return body if isinstance(body, dict) else {}


def loads_stored(text, default=None):
    """JSON из базы: старые записи могли сохранить NaN/Infinity - читаем их как null."""
    try:
        return json.loads(text or "null", parse_constant=lambda _name: None)
    except ValueError:
        return default


def finite(value: Any) -> float:
    """float из присланного значения; не число, NaN и бесконечность - ValueError."""
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("not finite")
    return number


async def _json_body(request: Request):
    """Тело запроса как JSON; не JSON - 400, а не 500."""
    try:
        return loads_agent(await request.body())
    except (ValueError, RecursionError):
        raise HTTPException(status_code=400, detail=t("не JSON")) from None


GEO_CACHE_DAYS = 7
GEO_PER_DAY = 1500
GEO_TIMEOUT = 3
GEO_FAILS, GEO_PAUSE = 3, 600
_geo_day = RateTable(GEO_PER_DAY, window=86400)


class Breaker:
    """Внешний сервис (ipinfo, Nominatim) не отвечает: после GEO_FAILS неудач подряд GEO_PAUSE не ходим туда
    вовсе - отчёты идут без этих данных, а не ждут таймаута каждый; удача сбрасывает счёт."""

    def __init__(self, name):
        self.name = name
        self.fails = 0
        self.until = 0.0
        self.lock = threading.Lock()

    def paused(self, now=None) -> bool:
        with self.lock:
            return (time.time() if now is None else now) < self.until

    def result(self, ok, now=None):
        now = time.time() if now is None else now
        with self.lock:
            if ok:
                self.fails = 0
                return
            self.fails += 1
            if self.fails < GEO_FAILS:
                return
            self.fails = 0
            self.until = now + GEO_PAUSE
        print("%s: %d failures in a row, paused for %d s" % (self.name, GEO_FAILS, GEO_PAUSE), flush=True)

    def reset(self):
        with self.lock:
            self.fails = 0
            self.until = 0.0


_geo_breaker = Breaker("ipinfo")
_place_breaker = Breaker("nominatim")


def geo_lookup(ip, may_fetch=None):
    """Регион по IP: ipinfo.io с кэшем в базе по сети (IPv4 /24, IPv6 /48) на GEO_CACHE_DAYS. Отдаёт {} если
    не вышло. may_fetch() -> False - не в кэше и новый запрос сейчас нельзя; сверх GEO_PER_DAY новых запросов
    в сутки на сервер - тоже {} (квота ipinfo общая). ipinfo ждём GEO_TIMEOUT, при отказах - Breaker."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return {}
    if address.is_private or address.is_loopback or address.is_link_local:
        return {}
    cache_key = net_key(ip)
    with db() as conn:
        row = conn.execute("SELECT data, ts FROM geo WHERE ip=?", (cache_key,)).fetchone()
        if row and time.time() - row["ts"] < GEO_CACHE_DAYS * 86400:
            return loads_stored(row["data"], {}) or {}
    if _geo_breaker.paused() or (may_fetch is not None and not may_fetch()) or _geo_day.hit("all"):
        return {}
    try:
        request = urllib.request.Request("https://ipinfo.io/%s/json" % ip, headers={"User-Agent": "curl/8"})
        with urllib.request.urlopen(request, timeout=GEO_TIMEOUT) as response:
            data = json.load(response)
        if not isinstance(data, dict):
            raise ValueError("not an object")
    except Exception:  # noqa: BLE001
        _geo_breaker.result(False)
        return {}
    _geo_breaker.result(True)
    try:
        lat, lon = (finite(part) for part in str(data.get("loc") or "").split(","))
    except ValueError:
        lat = lon = None
    info = {"country": data.get("country", ""), "region": data.get("region", ""), "city": data.get("city", ""),
            "org": data.get("org", ""), "lat": lat, "lon": lon}
    with db() as conn:
        conn.execute("INSERT OR REPLACE INTO geo(ip, data, ts) VALUES (?,?,?)",
                     (cache_key, json.dumps(info), time.time()))
    return info


NOMINATIM_GAP = 1.0
NOMINATIM_AGENT = "VPNCheck/1.0 (+https://github.com/SautovAndrey/vpncheck-stand)"
_nominatim_lock = threading.Lock()
_nominatim_last = [0.0]


def _nominatim_slot():
    """Nominatim - не чаще раза в NOMINATIM_GAP секунд на весь сервер (их правило и защита пула потоков):
    не успели - отчёт принимаем без города по точке, он придёт со следующим."""
    with _nominatim_lock:
        now = time.monotonic()
        if now - _nominatim_last[0] < NOMINATIM_GAP:
            return False
        _nominatim_last[0] = now
        return True


def place_lookup(lat, lon):
    """Город и регион по координатам телефона (OSM Nominatim) с кэшем в базе.
    Нужно, когда телефон прислал точку, но сам город назвать не смог - иначе остаётся город по IP оператора."""
    if lat is None or lon is None:
        return {}
    key = "%.3f,%.3f" % (float(lat), float(lon))
    with db() as conn:
        row = conn.execute("SELECT data, ts FROM places WHERE key=?", (key,)).fetchone()
        if row and time.time() - row["ts"] < 180 * 86400:
            return loads_stored(row["data"], {}) or {}
    if _place_breaker.paused() or not _nominatim_slot():
        return {}
    try:
        url = ("https://nominatim.openstreetmap.org/reverse?lat=%s&lon=%s&format=json&zoom=10&accept-language=ru"
               % (lat, lon))
        request = urllib.request.Request(url, headers={"User-Agent": NOMINATIM_AGENT})
        with urllib.request.urlopen(request, timeout=GEO_TIMEOUT) as response:
            data = json.load(response)
        if not isinstance(data, dict):
            raise ValueError("not an object")
    except Exception:  # noqa: BLE001
        _place_breaker.result(False)
        return {}
    _place_breaker.result(True)
    addr = data.get("address") or {}
    if not isinstance(addr, dict):
        addr = {}
    city = (addr.get("city") or addr.get("town") or addr.get("village") or addr.get("municipality")
            or addr.get("county") or "")
    info = {"city": str(city)[:64], "region": str(addr.get("state") or "")[:64]}
    with db() as conn:
        conn.execute("INSERT OR REPLACE INTO places(key, data, ts) VALUES (?,?,?)",
                     (key, json.dumps(info), time.time()))
    return info


def client_ip(request: Request):
    peer = request.client.host if request.client else ""
    if peer in TRUSTED_PROXIES:
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            return forwarded.split(",")[-1].strip() or peer
    return peer


def require_admin(x_admin_token: str = Header(default="")):
    if not admin_token_ok(x_admin_token):
        raise HTTPException(status_code=401, detail=t("нет доступа"))


def require_public(request: Request):
    if rate_limited(client_ip(request)):
        raise HTTPException(status_code=429, detail=t("слишком часто"))


BACKUP_DIR = os.path.join(DATA_DIR, "backups")
BACKUP_DAILY, BACKUP_WEEKLY = 7, 4
BACKUP_EVERY = 24 * 3600
BACKUP_NAME_RE = re.compile(r"^(agents|state|tls)-(\d{8})\.(db|db\.gz|json|tar)$")
BACKUP_LEFTOVER_RE = re.compile(r"^(agents-\d{8}\.db\.gz\.tmp(\.db)?|tls-\d{8}\.tar\.tmp)$")
TLS_STATE: dict[str, Any] = {"on": False, "cert": "", "key": ""}
TLS_FILE_MAX = 64 * 1024
TLS_ALERT_EVERY = 24 * 3600
TLS_SEEN_WINDOW = 3600
BACKUP_CHECK = 3600


def server_error(kind, text, merge=False):
    """Ошибка самого сервера (бэкап, Telegram) - в журнал ошибок рядом с ошибками агентов (agent_id пустой).
    merge - та же ошибка, что последняя такого вида за сутки, не множится: у неё только освежается время."""
    with contextlib.suppress(sqlite3.Error):
        with db() as conn:
            now = time.time()
            last = conn.execute("SELECT id, text FROM errors WHERE agent_id='' AND kind=? AND ts > ? "
                                "ORDER BY id DESC LIMIT 1", (clip(kind, 32), now - 86400)).fetchone() if merge else None
            if last is not None and last["text"] == clip(text, 4000):
                conn.execute("UPDATE errors SET ts=? WHERE id=?", (now, last["id"]))
                return
            conn.execute("INSERT INTO errors(ts, agent_id, app_version, model, kind, text) VALUES (?,?,?,?,?,?)",
                         (now, "", "", "server", clip(kind, 32), clip(text, 4000)))
    print("%s: %s" % (kind, text), flush=True)


def backup_db():
    """Снимок agents.db и state.json раз в сутки: копия базы одним шагом SQLite backup API (в WAL запись не
    ждёт; шагами по страницам копия начиналась заново после каждой записи и под опросами не кончалась), сжатая
    gzip. Хранятся BACKUP_DAILY последних дней и по одному снимку за BACKUP_WEEKLY недель до них. Свободно
    меньше двух размеров базы - бэкап пропускается с записью в журнал ошибок. Правило: не терять данные."""
    try:
        os.makedirs(BACKUP_DIR, exist_ok=True)
        for name in os.listdir(BACKUP_DIR):
            if BACKUP_LEFTOVER_RE.match(name):
                with contextlib.suppress(OSError):
                    os.remove(os.path.join(BACKUP_DIR, name))
        stamp = time.strftime("%Y%m%d")
        if os.path.exists(DB_PATH):
            size = os.path.getsize(DB_PATH)
            with contextlib.suppress(OSError):
                size += os.path.getsize(DB_PATH + "-wal")
            free = shutil.disk_usage(BACKUP_DIR).free
            if free < 2 * size:
                server_error("backup", t("бэкап пропущен: свободно %d МБ, нужно %d МБ")
                             % (free >> 20, (2 * size) >> 20))
            else:
                _snapshot_db(os.path.join(BACKUP_DIR, "agents-%s.db.gz" % stamp))
        if os.path.exists(STATE_PATH):
            shutil.copy2(STATE_PATH, os.path.join(BACKUP_DIR, "state-%s.json" % stamp))
        rotate_backups()
    except Exception as exc:  # noqa: BLE001 - бэкап не должен ронять сервис
        server_error("backup", "%s: %s" % (type(exc).__name__, exc))


def _snapshot_db(target):
    raw, packed = target + ".tmp.db", target + ".tmp"
    try:
        with contextlib.closing(sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT)) as source, \
                contextlib.closing(sqlite3.connect(raw)) as copy:
            source.backup(copy)
        with open(raw, "rb") as plain, gzip.open(packed, "wb", compresslevel=6) as squeezed:
            shutil.copyfileobj(plain, squeezed, 1 << 20)
        os.replace(packed, target)
    finally:
        for leftover in (raw, packed):
            with contextlib.suppress(FileNotFoundError):
                os.remove(leftover)


def tls_backup_due() -> bool:
    return bool(TLS_STATE.get("cert") and TLS_STATE.get("key")) and not os.path.exists(
        os.path.join(BACKUP_DIR, "tls-%s.tar" % time.strftime("%Y%m%d")))


def backup_tls():
    """Сертификат и ключ TLS-порта (пути даёт run.py) - в backups/tls-ГГГГММДД.tar (0600): без этого ключа агенты
    0.12.9+ с закреплённым отпечатком после переустановки сервера замолчат. restore.sh умеет вернуть его на место.
    Ключ и так читается сервисом (key.pem 640 root:vpnagent) - копия не расширяет круг читающих."""
    try:
        os.makedirs(BACKUP_DIR, exist_ok=True)
        blobs = []
        for path, name, mode in ((TLS_STATE["cert"], "cert.pem", 0o644), (TLS_STATE["key"], "key.pem", 0o600)):
            with open(path, "rb") as handle:
                data = handle.read(TLS_FILE_MAX + 1)
            if not data or len(data) > TLS_FILE_MAX:
                raise ValueError("%s: bad size" % path)
            blobs.append((name, mode, data))
        target = os.path.join(BACKUP_DIR, "tls-%s.tar" % time.strftime("%Y%m%d"))
        packed = target + ".tmp"
        with contextlib.suppress(FileNotFoundError):
            os.remove(packed)
        with os.fdopen(os.open(packed, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as raw, \
                tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for name, mode, data in blobs:
                info = tarfile.TarInfo(name)
                info.size, info.mode, info.mtime = len(data), mode, int(time.time())
                archive.addfile(info, io.BytesIO(data))
        os.replace(packed, target)
        rotate_backups()
        return True
    except Exception as exc:  # noqa: BLE001 - бэкап не должен ронять сервис
        server_error("backup", "tls: %s: %s" % (type(exc).__name__, exc), merge=True)
        return False


def tls_down(reason, now=None):
    """TLS-порт не поднялся (зовёт run.py): строка в журнал ошибок сервера и тревога в Telegram мимо часового
    лимита - не чаще раза в TLS_ALERT_EVERY (отметка в alert_last переживает перезапуски). True - тревога ушла."""
    now = time.time() if now is None else now
    TLS_STATE["on"] = False
    server_error("tls", reason, merge=True)
    with contextlib.suppress(sqlite3.Error), db() as conn:
        row = conn.execute("SELECT ts FROM alert_last WHERE key='tls_down'").fetchone()
        if row and row["ts"] and now - float(row["ts"]) < TLS_ALERT_EVERY:
            return False
    text = t("<b>VPNCheck</b> ⚠ TLS-порт сервера не поднялся: %s. Агенты 0.12.9+ с закреплённым ключом не выйдут на "
             "связь, пока его не вернут: journalctl -u vpnagent -n 50, затем python server/deploy.py.") \
        % html.escape(clip(str(reason), 300))
    if not send_alert(text, now, force=True):
        return False
    with contextlib.suppress(sqlite3.Error), db() as conn:
        conn.execute("INSERT INTO alerts(ts, kind, text) VALUES (?,?,?)", (now, "tls_down", _history_text(text)))
        conn.execute("INSERT OR REPLACE INTO alert_last(key, ts) VALUES ('tls_down', ?)", (now,))
    return True


def rotate_backups(folder=None):
    """Оставить снимки BACKUP_DAILY последних дней и самый свежий снимок каждой из BACKUP_WEEKLY недель до
    них - отдельно для базы и для state.json. Чужие файлы в папке не трогаются."""
    folder = folder or BACKUP_DIR
    groups: dict[str, list] = {}
    for name in os.listdir(folder):
        match = BACKUP_NAME_RE.match(name)
        if not match:
            continue
        with contextlib.suppress(ValueError):
            day = datetime.datetime.strptime(match.group(2), "%Y%m%d").date()
            groups.setdefault(match.group(1), []).append((day, name))
    removed = []
    for items in groups.values():
        days = sorted({day for day, _name in items}, reverse=True)
        keep = set(days[:BACKUP_DAILY])
        covered = {day.isocalendar()[:2] for day in keep}
        weeks = 0
        for day in days[BACKUP_DAILY:]:
            week = day.isocalendar()[:2]
            if week not in covered and weeks < BACKUP_WEEKLY:
                covered.add(week)
                weeks += 1
                keep.add(day)
        for day, name in items:
            if day not in keep:
                os.remove(os.path.join(folder, name))
                removed.append(name)
    return removed


REPORTS_KEEP_DAYS = 90
ERRORS_KEEP_DAYS = 30
AGENTS_KEEP_DAYS = 365
GEO_KEEP_DAYS = 180
MAX_ERRORS_PER_AGENT = 500
MAX_ERRORS_TOTAL = 20000


def prune_old(now=None):
    """Всё, что копится от агентов, живёт ограниченно: отчёты, результаты, тревоги, состояние узлов -
    REPORTS_KEEP_DAYS (узел в месте, который столько не проверяли, - тоже), ошибки - ERRORS_KEEP_DAYS и не
    больше MAX_ERRORS_TOTAL, кэш мест - GEO_KEEP_DAYS, давно пропавшие агенты - AGENTS_KEEP_DAYS (с их
    push-токенами). Возвращает число удалённых отчётов."""
    now = now or time.time()
    cutoff = now - REPORTS_KEEP_DAYS * 86400
    removed = 0
    jobs = [("reports", "ts < ?", (cutoff,)), ("results", "ts < ?", (cutoff,)), ("alerts", "ts < ?", (cutoff,)),
            ("alert_last", "ts < ?", (cutoff,)),
            ("node_state", "ts < ?", (cutoff,)), ("scope_agents", "ts < ?", (cutoff,)),
            ("alert_pending", "ts < ?", (cutoff,)), ("errors", "ts < ?", (now - ERRORS_KEEP_DAYS * 86400,)),
            ("geo", "ts < ?", (now - GEO_KEEP_DAYS * 86400,)), ("places", "ts < ?", (now - GEO_KEEP_DAYS * 86400,)),
            ("agents", "last_seen < ?", (now - AGENTS_KEEP_DAYS * 86400,)),
            ("push", "agent_id NOT IN (SELECT agent_id FROM agents)", ())]
    try:
        for table, where, params in jobs:
            count = _delete_batched(table, where, params)
            if table == "reports":
                removed = count
        with db() as conn:
            edge = conn.execute("SELECT id FROM errors ORDER BY id DESC LIMIT 1 OFFSET ?",
                                (MAX_ERRORS_TOTAL - 1,)).fetchone()
        if edge:
            _delete_batched("errors", "id < ?", (edge["id"],))
    except sqlite3.Error:
        pass
    return removed


PRUNE_BATCH = 500


def _delete_batched(table, where, params):
    """Удалить пачками по PRUNE_BATCH строк, каждая пачка - своя короткая транзакция: чистка за 90 дней
    не держит базу занятой и не роняет опросы агентов с «database is locked»."""
    total = 0
    while True:
        with db() as conn:
            count = conn.execute("DELETE FROM %s WHERE rowid IN (SELECT rowid FROM %s WHERE %s LIMIT %d)"
                                 % (table, table, where, PRUNE_BATCH), params).rowcount
        total += count
        if count < PRUNE_BATCH:
            return total
        time.sleep(0.01)


MAX_RESULTS_PER_AGENT = 200
MAX_RESULTS_TOTAL = 20000


def _cap_rows(conn, table, keep, agent_id=None):
    """Оставить в таблице (или у одного агента) не больше keep свежих строк."""
    where, params = ("WHERE agent_id=? ", (agent_id,)) if agent_id is not None else ("", ())
    edge = conn.execute("SELECT id FROM %s %sORDER BY id DESC LIMIT 1 OFFSET ?" % (table, where),
                        params + (keep - 1,)).fetchone()
    if edge:
        conn.execute("DELETE FROM %s %s%s id < ?" % (table, where, "AND" if where else "WHERE"), params + (edge["id"],))


def _cap_errors(conn, agent_id):
    """Ошибок одного агента - не больше MAX_ERRORS_PER_AGENT: остаются свежие (общий потолок - в prune_old)."""
    edge = conn.execute("SELECT id FROM errors WHERE agent_id=? ORDER BY id DESC LIMIT 1 OFFSET ?",
                        (agent_id, MAX_ERRORS_PER_AGENT - 1)).fetchone()
    if edge:
        conn.execute("DELETE FROM errors WHERE agent_id=? AND id < ?", (agent_id, edge["id"]))


def _cap_errors_total(conn):
    """Общий потолок MAX_ERRORS_TOTAL - сразу при записи, а не только в суточной чистке."""
    edge = conn.execute("SELECT id FROM errors ORDER BY id DESC LIMIT 1 OFFSET ?",
                        (MAX_ERRORS_TOTAL - 1,)).fetchone()
    if edge:
        conn.execute("DELETE FROM errors WHERE id < ?", (edge["id"],))


PRUNE_EVERY = 6 * 3600


def backup_due() -> bool:
    """Сегодняшнего снимка базы ещё нет: перезапуск сервиса (деплой) не делает лишний бэкап на минуту."""
    return not os.path.exists(os.path.join(BACKUP_DIR, "agents-%s.db.gz" % time.strftime("%Y%m%d")))


def _backup_loop():
    while True:
        if backup_due():
            backup_db()
        if tls_backup_due():
            backup_tls()
        time.sleep(BACKUP_CHECK)


def _prune_loop():
    while True:
        with contextlib.suppress(Exception):
            prune_old()
        time.sleep(PRUNE_EVERY)


_backup_thread: list = []


def startup():
    """Папки, схема, таблица регионов и фоновые потоки (бэкап, чистка - отдельно, чтобы долгий бэкап не
    останавливал чистку; тревоги) - потоки по одному на процесс."""
    os.makedirs(FILES_DIR, exist_ok=True)
    init_db()
    load_regions()
    if not _backup_thread:
        for target, name in ((_backup_loop, "backup"), (_prune_loop, "prune")):
            thread = threading.Thread(target=target, daemon=True, name=name)
            _backup_thread.append(thread)
            thread.start()
    _start_alert_worker()


_served_nodes: dict[str, Any] = {"source": None, "nodes": []}


def served_nodes(state) -> list:
    """Узлы для агентов без тех, что node_refusal не пропустил бы сейчас: выложенное до обновления сервера (ключи
    в другом регистре, echConfigList с сервером) не уходит агентам 0.9-0.12, которые таких правил не знают."""
    nodes = state.get("nodes") or []
    if _served_nodes["source"] is not nodes:
        _served_nodes["nodes"] = [node for node in nodes if not isinstance(node, dict) or not node_refusal(node)]
        _served_nodes["source"] = nodes
    return _served_nodes["nodes"]


def valid_location_round(value):
    return not isinstance(value, bool) and isinstance(value, (int, float)) \
        and LOCATION_ROUND_MIN <= value <= LOCATION_ROUND_MAX


def location_round(value):
    return value if valid_location_round(value) else DEFAULT_STATE["location_round"]


@app.get("/v1/config", dependencies=[Depends(require_public)])
def get_config():
    state = load_state()
    return {"nodes": served_nodes(state), "interval_min": state["interval_min"], "test_url": state["test_url"],
            "latency_url": state["latency_url"], "manifest": state["manifest"], "message": state["message"],
            "sites": state.get("sites") or [], "location_round": location_round(state.get("location_round")),
            "server_time": int(time.time())}


@app.get("/v1/manifest", dependencies=[Depends(require_public)])
def get_manifest():
    """Только подписанный манифест, без узлов: по нему агент 0.12.12+ восстанавливает TLS по http."""
    return {"manifest": load_state()["manifest"]}


@app.get("/v1/ping",dependencies=[Depends(require_public)])
def ping(agent_id: str = ""):
    """Лёгкий опрос раз в 15 минут: не пора ли проверить вне расписания."""
    state = load_state()
    run_now = max(float(state.get("run_now") or 0), _run_now_agents.get(clip(agent_id), 0))
    update_now = max(float(state.get("update_now") or 0), _update_now_agents.get(clip(agent_id), 0))
    return {"run_now": run_now, "update_now": update_now,
            "locate_now": _locate_agents.get(clip(agent_id), 0),
            "interval_min": state["interval_min"], "server_time": int(time.time())}


_known_agents: set = set()


def _touch_agent(agent_id, secure=False):
    """Отметить опрос агента (secure - пришёл по https: last_tls); False - такого агента в базе нет (в «на связи»
    его не пускаем). База занята дольше DB_TIMEOUT - опрос не роняем: известного раньше агента считаем известным."""
    now = time.time()
    try:
        with db() as conn:
            if secure:
                known = conn.execute("UPDATE agents SET last_seen=?, last_tls=? WHERE agent_id=?",
                                     (now, now, agent_id)).rowcount > 0
            else:
                known = conn.execute("UPDATE agents SET last_seen=? WHERE agent_id=?",
                                     (now, agent_id)).rowcount > 0
    except sqlite3.OperationalError as exc:
        print("poll: %s" % exc, flush=True)
        return agent_id in _known_agents
    if known and len(_known_agents) < RATE_MAX_KEYS:
        _known_agents.add(agent_id)
    return known


def link_wait(wait: int) -> float:
    """Сколько держать пустой опрос: агент с долгим таймаутом чтения просит wait (до LINK_WAIT_MAX) и реже
    будит радио; без wait - LINK_WAIT, под таймаут чтения старых агентов (70 с)."""
    if wait <= 0 or LINK_WAIT <= 0:
        return LINK_WAIT
    return min(max(wait, LINK_WAIT), LINK_WAIT_MAX)


def poll_hold(known: bool, after: int, wait: int) -> float:
    """Сколько держать опрос. Новый агент (есть wait) при after<=0 получает ответ сразу - точка отсчёта seq на
    момент подключения. Старый агент (0.9-0.11.0, без wait) при after<=0 меняет свой after только по seq команд
    и без команд не делает паузы - его держим LINK_WAIT, как раньше, иначе он опрашивает без остановки; команды,
    пришедшие за это время, он получает (точка отсчёта - seq на входе в опрос).
    Неизвестный серверу agent_id - не дольше LINK_WAIT."""
    if after <= 0 and wait > 0:
        return 0
    hold = link_wait(wait)
    return hold if known else min(hold, LINK_WAIT)


def _poll_enter(key: str, known: bool) -> bool:
    """Место для висящего опроса: на ключ адреса и всего; неизвестным agent_id - отдельный, меньший предел."""
    slots = _poll_slots
    keys = slots["keys"]
    if slots["total"] >= POLLS_TOTAL or keys.get(key, 0) >= POLLS_PER_KEY:
        return False
    unknown_keys = slots["unknown_keys"]
    if not known and (slots["unknown"] >= UNKNOWN_POLLS_TOTAL or unknown_keys.get(key, 0) >= UNKNOWN_POLLS_PER_KEY):
        return False
    slots["total"] += 1
    keys[key] = keys.get(key, 0) + 1
    if not known:
        slots["unknown"] += 1
        unknown_keys[key] = unknown_keys.get(key, 0) + 1
    return True


def _poll_leave(key: str, known: bool):
    pairs = [("total", "keys")] + ([] if known else [("unknown", "unknown_keys")])
    for counter, table_name in pairs:
        table = _poll_slots[table_name]
        _poll_slots[counter] -= 1
        table[key] -= 1
        if table[key] <= 0:
            del table[key]


def _poll_reply(pending):
    return {"commands": pending, "seq": _cmd_seq, "interval_min": load_state()["interval_min"],
            "server_time": int(time.time())}


@app.get("/v1/poll", dependencies=[Depends(require_public)])
async def poll(request: Request, agent_id: str = "", after: int = 0, wait: int = 0):
    """Долгий опрос: агент держит запрос открытым, сервер отвечает сразу как появится команда (по событию,
    без перебора раз в секунду). Работает через любой VPN и без Google. Пусто - вернём через poll_hold().
    Висящих опросов не больше POLLS_PER_KEY на адрес и POLLS_TOTAL всего (неизвестным agent_id - меньше):
    сверх - 429, агент отступает с паузой."""
    agent_id = clip(agent_id)
    if not AGENT_ID_RE.match(agent_id):
        raise HTTPException(status_code=400, detail="agent_id")
    known = await asyncio.to_thread(_touch_agent, agent_id, request.url.scheme == "https")
    hold = poll_hold(known, after, wait)
    if after <= 0 and hold > 0:
        after = max(_cmd_seq, 1)
    pending = commands_for(agent_id, after)
    if pending or hold <= 0:
        if known:
            _online[agent_id] = time.time()
        return _poll_reply(pending)
    key = rate_key(client_ip(request))
    if not _poll_enter(key, known):
        raise HTTPException(status_code=429, detail=t("слишком много опросов с этого адреса"))
    if known:
        _polling[agent_id] = _polling.get(agent_id, 0) + 1
        _online[agent_id] = time.time()
    gone = asyncio.ensure_future(_disconnected(request))
    try:
        deadline = time.monotonic() + hold
        while not gone.done():
            event = _wake_event()
            pending = commands_for(agent_id, after)
            remaining = deadline - time.monotonic()
            if pending or remaining <= 0:
                break
            woke = asyncio.ensure_future(event.wait())
            try:
                await asyncio.wait({woke, gone}, timeout=remaining, return_when=asyncio.FIRST_COMPLETED)
            finally:
                woke.cancel()
    finally:
        dropped = gone.done() and not gone.cancelled()
        if dropped:
            gone.exception()
        gone.cancel()
        _poll_leave(key, known)
        if known:
            if not dropped:
                _online[agent_id] = time.time()
            _polling[agent_id] -= 1
            if _polling[agent_id] <= 0:
                del _polling[agent_id]
    return _poll_reply(pending)


async def _disconnected(request: Request):
    """Дождаться, что агент оборвал соединение: висящий опрос сразу освобождает место и не держит «на связи»."""
    while True:
        message = await request.receive()
        if message["type"] == "http.disconnect":
            return


@app.post("/v1/admin/locate", dependencies=[Depends(require_admin)])
async def admin_locate(request: Request):
    """Разовый запрос точного местоположения у агента (GPS включается на телефоне только на этот замер)."""
    body = await _admin_body(request)
    agent_id = clip((body or {}).get("agent_id", ""))
    if not agent_id:
        raise HTTPException(status_code=400, detail=t("нужен agent_id"))
    _locate_agents[agent_id] = time.time()
    enqueue_command(agent_id, "locate")
    return {"ok": True, "pushed": await asyncio.to_thread(push_all, "locate", agent_id)}


@app.post("/v1/admin/message", dependencies=[Depends(require_admin)])
async def admin_message(request: Request):
    """Мгновенное сообщение на телефон через резервный канал. action=message показывает текст,
    action=vpn_off просит выключить VPN для честной проверки."""
    body = await _admin_body(request)
    agent_id = clip((body or {}).get("agent_id", ""))
    action = "vpn_off" if (body or {}).get("vpn_off") else "message"
    text = clip((body or {}).get("text", ""), 400)
    if action == "message" and not text:
        raise HTTPException(status_code=400, detail=t("нужен text"))
    enqueue_command(agent_id, action, text)
    return {"ok": True, "agent_id": agent_id, "online": online_now(agent_id)}


@app.post("/v1/admin/command", dependencies=[Depends(require_admin)])
async def admin_command(request: Request):
    """Команда с результатом одному агенту: site_check(text=URL), diag, xray_log(text=ключ узла),
    speed(text=ключ узла), whitelist_banner. Ответ придёт в /v1/result → /v1/admin/results."""
    body = await _admin_body(request)
    agent_id = clip((body or {}).get("agent_id", ""))
    action = clip((body or {}).get("action", ""), 32)
    text = clip((body or {}).get("text", ""), 400)
    if not agent_id or action not in RESULT_ACTIONS:
        raise HTTPException(status_code=400,
                            detail=t("нужен agent_id и action из: %s") % ", ".join(sorted(RESULT_ACTIONS)))
    if action in ("site_check", "xray_log", "speed") and not text:
        raise HTTPException(status_code=400, detail=t("для %s нужен text") % action)
    seq = enqueue_command(agent_id, action, text)
    return {"ok": True, "agent_id": agent_id, "action": action, "seq": seq, "online": online_now(agent_id)}


@app.post("/v1/result", dependencies=[Depends(require_public)])
async def post_result(request: Request):
    """Агент присылает результат команды с результатом (см. RESULT_ACTIONS)."""
    payload, agent_id = _parse_agent_body(await request.body(), MAX_RESULT_BYTES)
    ip = client_ip(request)
    limit_writes(agent_id, ip)
    return await asyncio.to_thread(_store_result, payload, agent_id)


def _store_result(payload, agent_id):
    """Запись результата команды - в потоке: вытеснение и запись в базу не держат цикл событий."""
    if not agent_known(agent_id):
        return {"ok": False, "detail": t("агент неизвестен серверу")}
    require_room()
    action = clip(payload.get("action", ""), 32)
    if action not in RESULT_ACTIONS:
        raise HTTPException(status_code=400, detail="agent_id/action")
    result = payload.get("result")
    if not isinstance(result, dict):
        raise HTTPException(status_code=400, detail="result")
    with db() as conn:
        conn.execute("INSERT INTO results(ts, agent_id, action, seq, payload) VALUES (?,?,?,?,?)",
                     (time.time(), agent_id, action, _int(payload.get("seq")),
                      json.dumps(result, ensure_ascii=False, allow_nan=False)[:MAX_RESULT_BYTES]))
        _cap_rows(conn, "results", MAX_RESULTS_PER_AGENT, agent_id)
        _cap_rows(conn, "results", MAX_RESULTS_TOTAL)
    return {"ok": True}


@app.get("/v1/admin/results", dependencies=[Depends(require_admin)])
def admin_results(agent_id: str = "", since: float = 0, limit: int = 50):
    limit = clamp_limit(limit, 500)
    with db() as conn:
        if agent_id:
            rows = conn.execute("SELECT id, ts, agent_id, action, seq, payload FROM results "
                                "WHERE agent_id=? AND ts>? ORDER BY ts DESC LIMIT ?",
                                (clip(agent_id), since, limit)).fetchall()
        else:
            rows = conn.execute("SELECT id, ts, agent_id, action, seq, payload FROM results "
                                "WHERE ts>? ORDER BY ts DESC LIMIT ?", (since, limit)).fetchall()
    results = []
    for row in rows:
        item = dict(row)
        item["result"] = loads_stored(item.pop("payload"), {})
        results.append(item)
    return {"results": results}


LOCATE_FRESH = 600
_locate_button = RateTable(1, window=LOCATE_FRESH)


@app.post("/v1/location", dependencies=[Depends(require_public)])
async def post_location(request: Request):
    """Точные координаты: по запросу из центра (не старше LOCATE_FRESH) или по кнопке на телефоне -
    тогда только от агента старше AGENT_TRUST_AGE и не чаще раза в LOCATE_FRESH. Иначе ok=false."""
    payload, agent_id = _parse_agent_body(await request.body(), 4096)
    limit_writes(agent_id, client_ip(request))
    try:
        lat, lon = finite(payload.get("lat")), finite(payload.get("lon"))
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail=t("координаты")) from None
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        raise HTTPException(status_code=400, detail=t("координаты вне диапазона"))
    return await asyncio.to_thread(_store_location, payload, agent_id, lat, lon)


def _store_location(payload, agent_id, lat, lon):
    now = time.time()
    if now - _locate_agents.get(agent_id, 0) > LOCATE_FRESH:
        with db() as conn:
            row = conn.execute("SELECT first_seen FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
        if not _agent_seasoned(row, now):
            return {"ok": False}
        if _locate_button.hit(agent_id, now):
            raise HTTPException(status_code=429, detail=t("слишком часто"))
    with db() as conn:
        conn.execute("UPDATE agents SET lat=?, lon=?, city=COALESCE(NULLIF(?,''), city), "
                     "region=COALESCE(NULLIF(?,''), region) WHERE agent_id=?",
                     (lat, lon, clip(payload.get("city", "")), clip(payload.get("region", "")), agent_id))
    _locate_agents.pop(agent_id, None)
    return {"ok": True}


@app.post("/v1/admin/update_now", dependencies=[Depends(require_admin)])
async def admin_update_now(request: Request):
    """Толкнуть обновление всем (без agent_id) или одному агенту."""
    body = await _admin_body(request)
    agent_id = clip((body or {}).get("agent_id", ""))
    now = time.time()
    if agent_id:
        _update_now_agents[agent_id] = now
    else:
        update_state({"update_now": now})
    enqueue_command(agent_id, "update")
    pushed = await asyncio.to_thread(push_all, "update", agent_id)
    return {"ok": True, "update_now": now, "agent_id": agent_id, "pushed": pushed, "online": online_now(agent_id)}


@app.post("/v1/admin/run_now", dependencies=[Depends(require_admin)])
async def admin_run_now(request: Request):
    """Толкнуть всех (без тела / agent_id пустой) или одного агента."""
    body = await _admin_body(request)
    agent_id = clip((body or {}).get("agent_id", ""))
    now = time.time()
    if agent_id:
        _run_now_agents[agent_id] = now
    else:
        update_state({"run_now": now})
    enqueue_command(agent_id, "check")
    pushed = await asyncio.to_thread(push_all, "check", agent_id)
    return {"ok": True, "run_now": now, "agent_id": agent_id, "pushed": pushed, "online": online_now(agent_id)}


def _int(value: Any) -> int:
    """Целое из присланного поля; мусор - 0, а не ошибка 500."""
    try:
        return int(value or 0)
    except (TypeError, ValueError, OverflowError):
        return 0


def clamp_limit(limit: int, most: int) -> int:
    """LIMIT для SQLite: отрицательный там значит «без предела» - приводим к 1..most."""
    return max(1, min(_int(limit), most))


def _parse_agent_body(body: bytes, max_bytes: int) -> tuple[dict[str, Any], str]:
    """Тело запроса агента → (словарь, agent_id); 413/400, если оно слишком большое, не JSON или без agent_id."""
    if len(body) > max_bytes:
        raise HTTPException(status_code=413, detail=t("слишком большой отчёт"))
    try:
        payload: dict[str, Any] = loads_agent(body)
    except (ValueError, RecursionError):
        raise HTTPException(status_code=400, detail=t("не JSON")) from None
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail=t("не объект"))
    agent_id = clip(payload.get("agent_id", ""))
    if not AGENT_ID_RE.match(agent_id):
        raise HTTPException(status_code=400, detail="agent_id")
    return payload, agent_id


DEAD_REASONS = ("dns-sinkhole", "dns-fail")


def _clean_results(raw: Any, known: set | None = None, skip: set | frozenset = frozenset()) -> dict:
    """Узлы из отчёта: только выложенные (known - ключи из state["nodes"]; None - любые), не больше
    MAX_RESULTS, от каждого только «жив», задержка и причина смерти из DEAD_REASONS (агент 0.12.1+: DNS
    оператора подменил адрес узла - "dns-sinkhole" - или не ответил на имя - "dns-fail"; это доверенный
    «мёртв»). Помеченные unchecked (агент не успел проверить или отверг узел) - не замер, их нет ни в итоге,
    ни в матрице. skip - узлы, замеру которых у этого агента не верим (см. chain_untrusted)."""
    if not isinstance(raw, dict):
        raise HTTPException(status_code=400, detail="results")
    results = {}
    for key, value in raw.items():
        if len(results) >= MAX_RESULTS:
            break
        if (known is not None and key not in known) or key in skip:
            continue
        if isinstance(value, dict) and not value.get("unchecked"):
            latency = value.get("latency")
            item = {"ok": bool(value.get("ok")),
                    "latency": _int(latency) if isinstance(latency, (int, float)) else None}
            if value.get("error") in DEAD_REASONS:
                item.update(ok=False, error=value["error"])
            results[clip(key, 128)] = item
    return results


EXTRA_OUTBOUNDS_MIN_CODE = 27
MAX_UNCHECKED = 300
UNCHECKED_RE = re.compile(r"^(unsupported|rejected|core-direct|vpn|core-exit:-?\d{1,6})$")
BIND_KINDS = ("device", "ip", "none")


def chain_untrusted(payload: dict, state: dict) -> set:
    """Узлы с extra_outbounds, если агент старше versionCode EXTRA_OUTBOUNDS_MIN_CODE (0.9.x, 0.10.x): он кладёт
    в конфиг только главный outbound, xray рвёт соединение - и узел ложно «мёртв»."""
    if _int(payload.get("app_version_code")) >= EXTRA_OUTBOUNDS_MIN_CODE:
        return set()
    return {node.get("key") for node in state.get("nodes") or []
            if isinstance(node, dict) and node.get("extra_outbounds")} - {None, ""}


def _clean_unchecked(payload: dict, known: set | None = None) -> dict:
    """Почему узлы не проверены: {ключ: "unsupported" | "rejected" | "core-direct" | "vpn" | "core-exit:N"} - из
    unchecked_nodes
    (агент 0.12+) и из results с пометкой unchecked (0.11.0 кладёт причину в error). Только выложенные узлы,
    не больше MAX_UNCHECKED."""
    found: dict[str, str] = {}
    raw = payload.get("unchecked_nodes")
    for key, value in (raw.items() if isinstance(raw, dict) else ()):
        if len(found) >= MAX_UNCHECKED:
            return found
        if (isinstance(key, str) and key and (known is None or key in known) and isinstance(value, str)
                and UNCHECKED_RE.match(value)):
            found[key] = value
    results = payload.get("results")
    for key, value in (results.items() if isinstance(results, dict) else ()):
        if len(found) >= MAX_UNCHECKED:
            break
        if not key or key in found or not isinstance(value, dict) or not value.get("unchecked"):
            continue
        if known is None or key in known:
            reason = value.get("error")
            found[key] = reason if isinstance(reason, str) and UNCHECKED_RE.match(reason) else "rejected"
    return found


def _clean_sites(raw: Any, known: set | None = None) -> dict:
    """Сайты из отчёта: только выложенные (known - адреса из state["sites"]; None - любые), не больше
    MAX_SITES, у каждого «открылся», код ответа, время и ошибка."""
    sites = {}
    for url, value in (raw if isinstance(raw, dict) else {}).items():
        if len(sites) >= MAX_SITES:
            break
        if known is not None and url not in known:
            continue
        if isinstance(value, dict):
            ms = value.get("ms")
            sites[clip(url, 200)] = {"ok": bool(value.get("ok")), "code": _int(value.get("code")),
                                     "ms": _int(ms) if isinstance(ms, (int, float)) else None,
                                     "error": clip(value.get("error", ""), 60)}
    return sites


NETWORK_KEYS = frozenset({"type", "vpn", "vpn_active", "operator", "sim_operator", "mcc_mnc", "radio", "roaming",
                          "metered", "transport"})
DEVICE_KEYS = frozenset({"model", "android", "brand", "manufacturer", "sdk"})


def _scalars(raw: Any, allowed: frozenset | None = None) -> dict:
    """Плоский словарь из отчёта (сеть, устройство): только известные ключи (allowed) и простые значения,
    каждое обрезано."""
    if not isinstance(raw, dict):
        return {}
    return {clip(k, 32): clip(v, 48) for k, v in list(raw.items())[:MAX_SCALAR_KEYS]
            if isinstance(v, (str, int, float, bool)) and (allowed is None or k in allowed)}


def _phone_location(raw: Any) -> dict:
    """Точка, присланная телефоном; координаты вне диапазона или не числа - считаем, что точки нет."""
    reported = raw if isinstance(raw, dict) else {}
    try:
        if reported and not (-90 <= finite(reported.get("lat")) <= 90 and -180 <= finite(reported.get("lon")) <= 180):
            reported = {}
    except (TypeError, ValueError):
        reported = {}
    return reported


def _apply_phone_location(geo: dict, reported: dict):
    """Телефон знает свой район точнее, чем гео по IP оператора (МТС «прописан» в Москве) - правим geo."""
    geo["lat"], geo["lon"] = float(reported["lat"]), float(reported["lon"])
    if reported.get("city"):
        geo["city"] = str(reported["city"])[:64]
    if reported.get("region"):
        geo["region"] = str(reported["region"])[:64]
    if not reported.get("city"):
        place = place_lookup(geo["lat"], geo["lon"])
        if place.get("city"):
            geo["city"] = place["city"]
        if place.get("region") and not reported.get("region"):
            geo["region"] = place["region"]
    geo["source"] = "phone"
    try:
        geo["accuracy"] = finite(reported.get("accuracy") or 0)
    except (TypeError, ValueError):
        geo["accuracy"] = 0


def _truthy(value: Any) -> bool:
    return value is True or str(value).strip().lower() in ("true", "1")


def vpn_in_report(payload: dict) -> bool:
    """На телефоне включён VPN: старые агенты пишут network.vpn, новые (0.12+) ещё и vpn_active по
    активной сети телефона - нижележащая сеть VPN не видит, а трафик проверки уходит в туннель."""
    network = payload.get("network") if isinstance(payload.get("network"), dict) else {}
    return any(_truthy(value) for value in (network.get("vpn"), network.get("vpn_active"), payload.get("vpn_active")))


def is_partial(payload: dict) -> bool:
    """Прогон оборван или часть узлов не проверена (agent 0.12+: unchecked - их число)."""
    return bool(payload.get("partial")) or _int(payload.get("unchecked")) > 0


def _label_operator(network: dict, geo: dict, vpn_on: bool):
    """Подпись сети для матрицы: на Wi-Fi - провайдер по IP, под VPN - с пометкой «VPN»."""
    if network.get("type") == "wifi":
        org = (geo.get("org") or "").split(" ", 1)[-1][:24]
        network["operator"] = "Wi-Fi" + (" · " + org if org else "")
    if vpn_on:
        network["operator"] = "VPN · " + (network.get("operator") or "")


def _touch_vpn_agent(conn, agent_id, payload, device, geo, now, measured_at=None):
    """Отчёт под VPN: гео по IP не верим (это выход туннеля), а координатам самого телефона - верим.
    Отметки «последний отчёт ненадёжный/частичный» - только если этот отчёт не старше уже учтённого."""
    partial = int(is_partial(payload))
    measured_at = measured_at or now
    conn.execute("UPDATE agents SET last_seen=?, app_version=?, network=?, "
                 "last_trusted=CASE WHEN ? >= COALESCE(report_ts, 0) THEN 0 ELSE last_trusted END, "
                 "last_partial=CASE WHEN ? >= COALESCE(report_ts, 0) THEN ? ELSE last_partial END, "
                 "report_ts=MAX(COALESCE(report_ts, 0), ?) WHERE agent_id=?",
                 (now, payload.get("app_version", ""), "vpn", measured_at, measured_at, partial, measured_at, agent_id))
    conn.execute("INSERT OR IGNORE INTO agents(agent_id, first_seen, last_seen, app_version, model, android, network, "
                 "last_trusted, last_partial, report_ts) VALUES (?,?,?,?,?,?,?,?,?,?)",
                 (agent_id, now, now, payload.get("app_version", ""), device.get("model", ""),
                  device.get("android", ""), "vpn", 0, partial, measured_at))
    if geo.get("source") == "phone":
        conn.execute("UPDATE agents SET city=?, region=?, lat=?, lon=?, model=?, android=? WHERE agent_id=?",
                     (geo.get("city", ""), geo.get("region", ""), geo.get("lat"), geo.get("lon"),
                      device.get("model", ""), device.get("android", ""), agent_id))


def _upsert_agent(conn, agent_id, payload, device, geo, network, ip, alive, total, now, keep_place=False,
                  measured=True, measured_at=None):
    """Карточка агента по обычному отчёту: версии, устройство, где он и сколько узлов видит живыми.
    keep_place - отчёт ушёл не через проверяемую сеть: IP и место по IP в карточке не трогаем.
    measured=False - отчёт ненадёжный или частичный: живые/всего в карточке остаются от последнего
    надёжного полного отчёта (trusted_ts - когда он был), иначе белые списки дают ложный «ноль у всех»."""
    place = "" if keep_place else ("ip=excluded.ip, country=excluded.country, region=excluded.region, "
                                   "city=excluded.city, lat=excluded.lat, lon=excluded.lon, org=excluded.org, ")
    counts = ("alive=CASE WHEN excluded.trusted_ts >= COALESCE(trusted_ts, 0) THEN excluded.alive ELSE alive END, "
              "total=CASE WHEN excluded.trusted_ts >= COALESCE(trusted_ts, 0) THEN excluded.total ELSE total END, "
              "trusted_ts=MAX(COALESCE(trusted_ts, 0), excluded.trusted_ts), ") if measured else ""
    newer = "excluded.report_ts >= COALESCE(report_ts, 0)"
    conn.execute("""INSERT INTO agents(agent_id, first_seen, last_seen, app_version, core_version, model, android,
                    ip, country, region, city, lat, lon, org, operator, network, alive, total,
                    last_trusted, last_partial, trusted_ts, report_ts)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(agent_id) DO UPDATE SET last_seen=excluded.last_seen,
                    app_version=excluded.app_version, core_version=excluded.core_version, model=excluded.model,
                    android=excluded.android, """ + place + counts + """operator=excluded.operator,
                    network=excluded.network,
                    last_trusted=CASE WHEN """ + newer + """ THEN excluded.last_trusted ELSE last_trusted END,
                    last_partial=CASE WHEN """ + newer + """ THEN excluded.last_partial ELSE last_partial END,
                    report_ts=MAX(COALESCE(report_ts, 0), excluded.report_ts)""",
                 (agent_id, now, now, payload.get("app_version", ""), payload.get("core_version", ""),
                  device.get("model", ""), device.get("android", ""), ip, geo.get("country", ""),
                  geo.get("region", ""), geo.get("city", ""), geo.get("lat"), geo.get("lon"), geo.get("org", ""),
                  network.get("operator", ""), network.get("type", ""),
                  alive if measured else None, total if measured else None,
                  int(report_trusted(payload)), int(is_partial(payload)),
                  (measured_at or now) if measured else None, measured_at or now))


def _stored_payload(payload, network, device):
    """То, что из отчёта идёт в историю: только разрешённые поля, уже почищенные и обрезанные."""
    location = payload.get("location") or {}
    stored = {"app_version": clip(payload.get("app_version", ""), 32),
              "core_version": clip(payload.get("core_version", ""), 32),
              "network": network, "device": device,
              "results": payload.get("results") or {}, "sites": payload.get("sites") or {}}
    if location:
        stored["location"] = {}
        for key in ("lat", "lon", "accuracy"):
            with contextlib.suppress(TypeError, ValueError):
                stored["location"][key] = finite(location.get(key))
        stored["location"].update({key: clip(location.get(key), 64) for key in ("city", "region", "source")
                                   if location.get(key)})
    for key in ("duration_s", "started", "deferred_s", "rejected", "sites_unchecked", "core_failed"):
        value = payload.get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool) and value:
            stored[key] = _int(value)
    if "direct_ok" in payload:
        stored["direct_ok"] = bool(payload.get("direct_ok"))
    if "core_direct_ok" in payload:
        stored["core_direct_ok"] = payload.get("core_direct_ok") is not False
    if payload.get("bind") in BIND_KINDS:
        stored["bind"] = payload["bind"]
    if payload.get("route_mismatch"):
        stored["route_mismatch"] = True
    if is_partial(payload):
        stored["partial"] = True
    if _int(payload.get("unchecked")) > 0:
        stored["unchecked"] = _int(payload.get("unchecked"))
    if payload.get("unchecked_nodes"):
        stored["unchecked_nodes"] = payload["unchecked_nodes"]
    if _truthy(payload.get("vpn_active")):
        stored["vpn_active"] = True
    for key in ("same_ip_as", "report_via"):
        if payload.get(key):
            stored[key] = clip(payload.get(key), 16)
    return stored


def report_trusted(payload):
    """Отчёту можно верить как замеру узлов: сеть выходила в интернет напрямую (не белые списки / не без
    интернета), ядро xray тоже вышло в интернет через эту сеть (агент 0.12.6+: core_direct_ok), выход SIM не
    совпал с Wi-Fi, маршрут не разошёлся и на телефоне не включён VPN. Иначе «мёртвые» узлы - это не их падение."""
    return (payload.get("direct_ok") is not False and payload.get("core_direct_ok") is not False
            and not payload.get("same_ip_as") and not payload.get("route_mismatch") and not vpn_in_report(payload))


MAX_REPORTS_PER_AGENT = 5000


def _insert_report(conn, agent_id, payload, geo, network, ip, alive, total, now, report_id=None):
    """Сам отчёт - в историю, только разрешённые поля (см. _stored_payload); trusted/partial - для матрицы и тревог.
    У одного агента хранится не больше MAX_REPORTS_PER_AGENT отчётов (90 дней по ~50 в сутки); лишние уходят
    сначала с того адреса, с которого пришёл этот отчёт (сам он не удаляется никогда): поток под чужим agent_id
    с другого адреса стирает свои отчёты, а не историю настоящего агента; с адреса больше ничего нет (мобильный
    адрес меняется каждый отчёт) - уходят самые старые отчёты агента."""
    fresh = conn.execute("INSERT INTO reports(agent_id, ts, ip, region, city, operator, network, alive, total, "
                         "payload, trusted, partial, report_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                         (agent_id, now, ip, geo.get("region", ""), geo.get("city", ""), network.get("operator", ""),
                          network.get("type", ""), alive, total, json.dumps(payload, ensure_ascii=False,
                                                                            allow_nan=False),
                          int(report_trusted(payload)), int(is_partial(payload)), report_id)).lastrowid
    excess = conn.execute("SELECT COUNT(*) FROM reports WHERE agent_id=?", (agent_id,)).fetchone()[0] \
        - MAX_REPORTS_PER_AGENT
    if excess > 0 and ip:
        excess -= conn.execute("DELETE FROM reports WHERE id IN (SELECT id FROM reports WHERE agent_id=? AND ip=? "
                               "AND id != ? ORDER BY ts LIMIT ?)", (agent_id, ip, fresh, excess)).rowcount
    if excess > 0:
        conn.execute("DELETE FROM reports WHERE id IN (SELECT id FROM reports WHERE agent_id=? AND id != ? "
                     "ORDER BY ts LIMIT ?)", (agent_id, fresh, excess))


def _report_reply(geo, **extra):
    """Ответ агенту: интервал проверок, где он по мнению сервера и сообщение от владельца."""
    state = load_state()
    return {"ok": True, **extra, "interval_min": state["interval_min"], "region": geo.get("region", ""),
            "city": geo.get("city", ""), "message": state["message"]}


REPORT_WORKERS = 8
_report_pool = ThreadPoolExecutor(max_workers=REPORT_WORKERS, thread_name_prefix="report")


@app.post("/v1/report", dependencies=[Depends(require_public)])
async def post_report(request: Request):
    """Отчёты - в своём пуле потоков: гео по IP и по точке ждут внешние сервисы до 8 с и не должны
    занимать общий пул, на котором висят долгие опросы и админка."""
    body = await request.body()
    ip = client_ip(request)
    if request.url.scheme == "https":
        return await asyncio.get_running_loop().run_in_executor(_report_pool, _handle_report, body, ip, True)
    return await asyncio.get_running_loop().run_in_executor(_report_pool, _handle_report, body, ip)


def known_nodes(state):
    return {node.get("key") for node in state.get("nodes") or [] if isinstance(node, dict)} - {None, ""}


def known_sites(state):
    return {site.get("url") for site in state.get("sites") or [] if isinstance(site, dict)} - {None, ""}


def known_subjects(state):
    """Узлы и сайты, о которых можно тревожить: только из выложенного списка, а не любые имена из отчёта."""
    return known_nodes(state) | {"site:" + url for url in known_sites(state)}


DEFERRED_MAX = 12 * 3600
DEFERRED_FRESH = 600


def deferred_seconds(payload):
    """Отложенный отчёт (агент 0.12+ копил его без связи): на сколько секунд он старше приёма, до DEFERRED_MAX."""
    return max(0, min(_int(payload.get("deferred_s")), DEFERRED_MAX))


AGENT_TRUST_AGE = 24 * 3600


def _agent_seasoned(row, now):
    """Агент известен дольше AGENT_TRUST_AGE: только такие будят Telegram (нового завести может кто угодно)."""
    return bool(row) and row["first_seen"] is not None and now - row["first_seen"] >= AGENT_TRUST_AGE


REPORTS_PER_DAY, REPORTS_PER_DAY_NEW, REPORTS_PER_DAY_IP = 300, 100, 500
_report_quota = RateTable(REPORTS_PER_DAY, window=86400)
_report_quota_new = RateTable(REPORTS_PER_DAY_NEW, window=86400)
_report_quota_ip = RateTable(REPORTS_PER_DAY_IP, window=86400)
REPORT_ID_RE = re.compile(r"^[0-9A-Za-z-]{8,64}$")
GEO_NEW_PER_HOUR = 300
_geo_new = RateTable(GEO_NEW_PER_HOUR, window=3600)


def _agent_row(agent_id):
    with db() as conn:
        return conn.execute("SELECT first_seen, ip, country, region, city, org, lat, lon, operator, network "
                            "FROM agents WHERE agent_id=?", (agent_id,)).fetchone()


def limit_daily_reports(agent_id, seasoned, ip=""):
    """Отчётов в сутки: на агента с его адресом - REPORTS_PER_DAY, а агенту младше AGENT_TRUST_AGE -
    REPORTS_PER_DAY_NEW (новый agent_id заводит кто угодно - иначе он за сутки раздувает базу); на адрес
    (IPv6 - сеть /48) по всем agent_id - REPORTS_PER_DAY_IP."""
    table = _report_quota if seasoned else _report_quota_new
    if table.hit(pair_key(agent_id, ip)) or (ip and _report_quota_ip.hit(rate_key_wide(ip))):
        raise HTTPException(status_code=429, detail=t("слишком часто"))


def public_ip(value) -> str:
    """Публичный адрес из поля отчёта или пустая строка."""
    try:
        address = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return ""
    return str(address) if address.is_global else ""


def _new_geo_allowed():
    """Новые (не из кэша) запросы гео для агентов младше суток - не больше GEO_NEW_PER_HOUR в час на сервер."""
    return not _geo_new.hit("new")


def _report_geo(payload, ip, seasoned, row=None, agent_id=""):
    """(ip для отчёта, гео). Отложенный отчёт (report_via=default) ушёл не через проверяемую сеть: IP соединения
    не его - гео берём по публичному direct_ip из самого отчёта, а без него гео нет (в матрицу такой не попадёт).
    Гео не узнать (квота ipinfo) - место из карточки агента, если он в той же сети (IPv4 /24, IPv6 /48) или на
    той же мобильной сети (тип и оператор как в карточке: мобильный адрес меняется каждый отчёт), иначе - из
    прошлых мобильных отчётов агента (_mobile_place)."""
    may_fetch = None if seasoned else _new_geo_allowed
    if payload.get("report_via") == "default":
        direct = public_ip(payload.get("direct_ip"))
        return "", (dict(geo_lookup(direct, may_fetch=may_fetch)) if direct else {})
    geo = dict(geo_lookup(ip, may_fetch=may_fetch))
    if not geo and row is not None and (row["region"] or row["city"]) and (
            (row["ip"] and net_key(row["ip"]) == net_key(ip)) or _same_mobile_net(payload, row)):
        geo = {key: row[key] for key in ("country", "region", "city", "org", "lat", "lon")}
    if not geo and row is not None and agent_id:
        geo = _mobile_place(payload, agent_id)
    return ip, geo


PLACE_MEMORY = 7 * 86400


def _mobile_place(payload, agent_id) -> dict:
    """Место мобильного отчёта без гео - из последних отчётов агента за PLACE_MEMORY: с тем же оператором (у
    телефона с двумя SIM оператор чередуется, а карточка помнит только последний), а если мобильный оператор у
    агента за это время был один (одна SIM, оператор просто подписан иначе) - по типу сети."""
    network = payload.get("network") if isinstance(payload.get("network"), dict) else {}
    kind, operator = str(network.get("type") or ""), str(network.get("operator") or "")
    if not kind or kind == "wifi" or vpn_in_report(payload):
        return {}
    with db() as conn:
        rows = conn.execute("SELECT operator, region, city FROM reports WHERE agent_id=? AND ts > ? AND network=? "
                            "AND (region != '' OR city != '') ORDER BY ts DESC LIMIT 200",
                            (agent_id, time.time() - PLACE_MEMORY, kind)).fetchall()
    same = [row for row in rows if row["operator"] == operator]
    if not same and len({row["operator"] for row in rows}) == 1:
        same = rows
    return {"region": same[0]["region"], "city": same[0]["city"]} if same else {}


def _same_mobile_net(payload, row) -> bool:
    network = payload.get("network") if isinstance(payload.get("network"), dict) else {}
    kind, operator = str(network.get("type") or ""), str(network.get("operator") or "")
    return bool(kind) and kind != "wifi" and bool(operator) and not vpn_in_report(payload) \
        and row["network"] == kind and row["operator"] == operator


class ReportContext:
    """Разобранный отчёт: всё, что нужно для записи, уже почищено."""

    def __init__(self, payload, agent_id, ip, state, geo, source_ip=""):
        self.payload, self.agent_id, self.ip, self.state, self.geo = payload, agent_id, ip, state, geo
        self.net = net_key(source_ip or ip)
        self.via_default = payload.get("report_via") == "default"
        nodes = known_nodes(state)
        untrusted = chain_untrusted(payload, state)
        payload["unchecked_nodes"] = _clean_unchecked(payload, nodes)
        self.results = payload["results"] = _clean_results(payload.get("results") or {}, nodes, untrusted)
        self.sites = payload["sites"] = _clean_sites(payload.get("sites"), known_sites(state))
        self.alive = sum(1 for value in self.results.values() if value.get("ok"))
        self.total = len(self.results)
        configured = max(0, len(state.get("nodes") or []) - _int(payload.get("rejected")) - len(untrusted))
        self.partial = is_partial(payload)
        self.incomplete = configured > 0 and self.total < max(1, configured // 2) and not self.partial
        self.network = _scalars(payload.get("network"), NETWORK_KEYS)
        self.device = _scalars(payload.get("device"), DEVICE_KEYS)
        reported = payload["location"] = _phone_location(payload.get("location"))
        if reported and reported.get("lat") is not None and reported.get("lon") is not None:
            _apply_phone_location(geo, reported)
        if geo.get("region"):
            geo["region"] = canonical_region(str(geo["region"]))
        for key in ("app_version", "core_version"):
            payload[key] = clip(payload.get(key, ""), 32)
        self.vpn_on = vpn_in_report(payload)
        self.measured = report_trusted(payload)
        _label_operator(self.network, geo, self.vpn_on)
        self.now = time.time()
        self.deferred = deferred_seconds(payload)
        report_id = clip(payload.get("report_id", ""), 64)
        self.report_id = report_id if REPORT_ID_RE.match(report_id) else None

    @property
    def placed(self):
        """Место известно: без региона и города (квота ipinfo, телефон не прислал точку) отчёт не идёт в
        стабильность, тревоги и матрицу - иначе места-призраки «? · оператор»."""
        return bool(self.geo.get("region") or self.geo.get("city"))

    @property
    def scope(self):
        return "%s · %s" % (self.geo.get("region") or canonical_region(self.geo.get("city") or "") or "?",
                            self.network.get("operator") or self.network.get("type") or "?")


def _mark_tls(agent_id):
    """Отчёт пришёл по https - отметка last_tls в карточке (по ней центр показывает, кто уже на TLS)."""
    with db() as conn:
        conn.execute("UPDATE agents SET last_tls=? WHERE agent_id=?", (time.time(), agent_id))


def _handle_report(body: bytes, ip: str, secure=False):
    payload, agent_id = _parse_agent_body(body, MAX_REPORT_BYTES)
    limit_writes(agent_id, ip, report=True)
    row = _agent_row(agent_id)
    seasoned = _agent_seasoned(row, time.time())
    limit_daily_reports(agent_id, seasoned, ip)
    require_room()
    key = admit_agent(agent_id, ip, commit=False) if row is None else None
    source_ip = ip
    ip, geo = _report_geo(payload, ip, seasoned, row, agent_id)
    report = ReportContext(payload, agent_id, ip, load_state(), geo, source_ip)
    if report.incomplete:
        _store_incomplete(report)
        reply = _report_reply(geo, ignored="incomplete")
    elif report.report_id and _report_seen(agent_id, report.report_id):
        if secure:
            _mark_tls(agent_id)
        return _report_reply(geo, duplicate=True)
    else:
        reply = _store_report(report, seasoned)
    if key:
        _new_agents.admit(key, agent_id)
    if len(_known_agents) < RATE_MAX_KEYS:
        _known_agents.add(agent_id)
    if secure:
        _mark_tls(agent_id)
    return reply


def _report_seen(agent_id, report_id):
    """Повтор уже принятого отчёта (ответ до агента не дошёл, он прислал тот же report_id ещё раз)."""
    with db() as conn:
        return conn.execute("SELECT 1 FROM reports WHERE agent_id=? AND report_id=?",
                            (agent_id, report_id)).fetchone() is not None


def _store_incomplete(report):
    """Отчёт, где проверена меньшая часть узлов: карточку агента заводим и освежаем, в историю, матрицу
    и тренды он не идёт."""
    with db() as conn:
        _upsert_agent(conn, report.agent_id, report.payload, report.device, report.geo, report.network, report.ip,
                      report.alive, report.total, report.now, keep_place=report.via_default, measured=False,
                      measured_at=report.now - report.deferred)
        store_errors(conn, report.agent_id, report.payload.get("app_version", ""), report.device.get("model", ""),
                     report.payload.get("errors"))


def _store_report(report, seasoned):
    """Запись принятого отчёта: карточка агента, ошибки, тренды (только свежий надёжный отчёт давнего агента и
    пока не истекла учётка узлов), push-токен и сам отчёт в историю; потом - тревоги."""
    payload, agent_id, now = report.payload, report.agent_id, report.now
    measured = report.measured and seasoned and report.deferred <= DEFERRED_FRESH
    fresh = measured and report.placed and not nodes_expired(report.state, now)
    events, witnesses = [], 0
    try:
        with db() as conn:
            before = conn.execute("SELECT first_seen, ip FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
            if report.vpn_on:
                _touch_vpn_agent(conn, agent_id, payload, report.device, report.geo, now,
                                 measured_at=now - report.deferred)
            else:
                _upsert_agent(conn, agent_id, payload, report.device, report.geo, report.network, report.ip,
                              report.alive, report.total, now, keep_place=report.via_default,
                              measured=report.measured and not report.partial, measured_at=now - report.deferred)
            store_errors(conn, agent_id, payload.get("app_version", ""), report.device.get("model", ""),
                         payload.get("errors"))
            if fresh:
                results, sites = report.results, report.sites
                if report.partial:
                    results = {k: v for k, v in results.items() if v["ok"]}
                    sites = {k: v for k, v in sites.items() if v["ok"]}
                events = update_trends(conn, report.scope, results, sites, known_subjects(report.state), report.net,
                                       agent_id)
                witnesses = scope_witnesses(conn, report.scope, agent_id, now, report.net)
            if payload.get("push_token"):
                store_push_token(conn, agent_id, payload["push_token"], report.ip, now, before)
            stored = _stored_payload(payload, _scalars(payload.get("network"), NETWORK_KEYS), report.device)
            _insert_report(conn, agent_id, stored, report.geo, report.network, report.ip, report.alive, report.total,
                           now - report.deferred, report.report_id)
    except sqlite3.IntegrityError:
        return _report_reply(report.geo, duplicate=True)
    if fresh:
        notify(events, report.scope, agent_id, witnesses, report.net)
    if measured and report.total and not report.alive and not report.partial:
        check_fleet_zero()
    return _report_reply(report.geo)


PUSH_REPLACE_AFTER = 24 * 3600
MAX_PUSH_TOKENS = 5000


def store_push_token(conn, agent_id, token, ip, now, agent_row=None):
    """Push-токен агента. Чужой agent_id знает любой, кто видел ссылку или опрос, поэтому:
    - новый агент (первый отчёт) - токен принимаем, отчёт сам регистрирует агента (agent_row=None);
    - совпал с действующим - только освежаем отметку времени (живой телефон шлёт его в каждом отчёте);
    - заменить действующий можно с того же IP, с которого он был прислан, или когда телефон не подтверждал
      его дольше PUSH_REPLACE_AFTER (отчёт с чужого IP не перехватит push у живого агента);
    - всего токенов не больше MAX_PUSH_TOKENS: при переполнении вытесняется самый давний токен агента
      моложе AGENT_TRUST_AGE, а если таких нет - новый не принимаем."""
    token = clip(token, 400)
    if not token:
        return False
    row = conn.execute("SELECT token, ts, ip FROM push WHERE agent_id=?", (agent_id,)).fetchone()
    if row and row["token"] == token:
        conn.execute("UPDATE push SET ts=?, ip=? WHERE agent_id=?", (now, ip or row["ip"], agent_id))
        return True
    if row:
        owner_ip = row["ip"] if row["ip"] is not None else (agent_row["ip"] if agent_row else "")
        same_ip = bool(ip) and ip == (owner_ip or "")
        if not same_ip and now - (row["ts"] or 0) < PUSH_REPLACE_AFTER:
            return False
    elif conn.execute("SELECT COUNT(*) FROM push").fetchone()[0] >= MAX_PUSH_TOKENS:
        victim = conn.execute("SELECT push.agent_id FROM push LEFT JOIN agents ON agents.agent_id = push.agent_id "
                              "WHERE agents.first_seen IS NULL OR agents.first_seen > ? ORDER BY push.ts LIMIT 1",
                              (now - AGENT_TRUST_AGE,)).fetchone()
        if victim is None:
            return False
        conn.execute("DELETE FROM push WHERE agent_id=?", (victim["agent_id"],))
    conn.execute("INSERT OR REPLACE INTO push(agent_id, token, ts, ip) VALUES (?,?,?,?)", (agent_id, token, now, ip))
    return True


@app.post("/v1/token", dependencies=[Depends(require_public)])
async def post_token(request: Request):
    """Push-токен Firebase устройства - чтобы центр мог разбудить агента. Неизвестному агенту -
    ok=false без ошибки: токен всё равно придёт в следующем отчёте."""
    payload, agent_id = _parse_agent_body(await request.body(), 8 * 1024)
    ip = client_ip(request)
    limit_writes(agent_id, ip)
    token = clip(payload.get("push_token", ""), 400)
    if not token:
        raise HTTPException(status_code=400, detail="agent_id/push_token")
    return {"ok": await asyncio.to_thread(_store_token, agent_id, token, ip)}


def _store_token(agent_id, token, ip):
    with db() as conn:
        agent = conn.execute("SELECT first_seen, ip FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
        return agent is not None and store_push_token(conn, agent_id, token, ip, time.time(), agent)


ALERT_MIN_CHECKS = 3
ALERT_CONFIRM = 2
ALERT_CONFIRM_ALONE = 4
ALERT_WINDOW = 3 * 3600
ALERT_WINDOW_CHECKS = 8
ALERT_WINDOW_FAILS = 3
ALERT_WINDOW_SHARE = 0.6
ALERT_COOLDOWN = 6 * 3600
ALERT_UP_GAP = 3 * 3600
ALERTS_PER_HOUR = 20
ALERT_BATCH_WAIT = 600
ALERT_LINES = 10
ALERT_PLACES = 10
ALERT_PLACES_WINDOW = 24 * 3600
ALERT_TEXT_MAX = 3900
ALERT_PLACE_CHARS = 40
ALERT_OLD = 3600
FLAP_CHANGES = 5
FLAP_RATE = (0.2, 0.8)
FLAP_KNOWN_CHANGES = 1
FLAP_LONG_DOWN = 6 * 3600
FLAP_MEMORY = 3 * 86400
ORPHAN_AFTER = 48 * 3600
FLAP_WINDOW = 24 * 3600
FLAP_MUTE = 24 * 3600
TREND_TAU = 2.5 * 86400
STABLE_RATE = 0.95
TELEGRAM_TRIES = 3
TELEGRAM_PAUSE = 10.0
EXPIRY_WARN_DAYS = (3, 1)
EXPIRED_NOTICE = 7 * 86400
DB_ROOM_WARN = 0.8
DB_ROOM_REARM = 0.7
DB_EVICT_NOTICE = 7 * 86400
FLEET_KEY = "fleet_zero"
FLAP_PREFIX = "flap:"
MUTE_PREFIX = "mute:"
FLAP_END = "flap_end"
EXPIRED_KIND = "expired"


def _decay(elapsed: float) -> float:
    """Вес прошлых проверок через elapsed секунд: экспонента с TREND_TAU - за неделю проверка
    теряет ~95% веса, и узел, мёртвый неделю, в «живучести» почти ноль, а не «мигает»."""
    return math.exp(-max(0.0, elapsed) / TREND_TAU)


def _recent_checks(text, now) -> list:
    """Проверки узла в месте за ALERT_WINDOW: [[ts, ok, сеть, агент]] из node_state.recent (до круга 8 - без
    агента)."""
    items = loads_stored(text, []) if text else []
    fresh = [item for item in (items if isinstance(items, list) else [])
             if isinstance(item, list) and len(item) in (3, 4) and isinstance(item[0], (int, float))
             and now - item[0] <= ALERT_WINDOW]
    return fresh[-(ALERT_WINDOW_CHECKS - 1):]


def _down_confirmed(conn, node, scope, now, streak, recent) -> bool:
    """«Перестал отвечать» после ALERT_CONFIRM неудач подряд подтверждается долей неудач в окне: в месте, где за
    ALERT_WINDOW было не меньше ALERT_WINDOW_FAILS проверок, - не меньше ALERT_WINDOW_FAILS неудач и
    ALERT_WINDOW_SHARE от последних ALERT_WINDOW_CHECKS (серия из трёх случайных неудач подряд в месте, где
    проверяют сотни раз в сутки, случается каждый день, а блокировка держится); где проверяют редко - серией
    ALERT_CONFIRM_ALONE или на одну короче, если в ней неудачи у двух разных агентов; сразу - если узел за
    ALERT_PLACES_WINDOW уже падал в другом подтверждённом месте."""
    fails = [item for item in recent if not item[1]]
    if len(recent) >= ALERT_WINDOW_FAILS:
        if len(fails) >= ALERT_WINDOW_FAILS and len(fails) >= ALERT_WINDOW_SHARE * len(recent):
            return True
    elif streak >= ALERT_CONFIRM_ALONE or (streak >= ALERT_CONFIRM_ALONE - 1
                                           and len({item[3] if len(item) > 3 else item[2] for item in fails}) >= 2):
        return True
    return _down_elsewhere(conn, node, scope, now)


def update_trends(conn, scope, results, sites, known=None, net="", agent_id=""):
    """Копим состояние узла/сайта в месте: проверки (всего и за неделю - w_checks/w_ok, старые затухают), за
    сутки (d_checks/d_ok), последние проверки окна (recent), текущее «жив/нет», когда и сколько раз за
    FLAP_WINDOW менялось (flips). Смена - после ALERT_CONFIRM проверок подряд с другим итогом (одна случайная
    неудача - не падение), «перестал отвечать» - ещё и по _down_confirmed. Событие - если проверок уже не
    меньше ALERT_MIN_CHECKS. Возвращает список событий. known - какие узлы и сайты учитывать (None - все),
    net - сеть отчёта (IPv4 /24, IPv6 /48), agent_id - кто проверял (в recent - первые 8 знаков)."""
    events = []
    now = time.time()
    items = [(key, bool(value.get("ok"))) for key, value in results.items()]
    items += [("site:" + url, bool(value.get("ok"))) for url, value in sites.items()]
    if known is not None:
        items = [(node, ok) for node, ok in items if node in known]
    for node, ok in items:
        mark = [int(now), int(ok), net or "", (agent_id or "")[:8]]
        row = conn.execute("SELECT ok, checks, ok_checks, changed, ts, streak, w_checks, w_ok, recent, flips, "
                           "flips_since, d_since, d_checks, d_ok FROM node_state WHERE node=? AND scope=?",
                           (node, scope)).fetchone()
        if row is None:
            conn.execute("INSERT INTO node_state(node, scope, ok, checks, ok_checks, changed, ts, streak, w_checks, "
                         "w_ok, recent, flips, d_since, d_checks, d_ok) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                         (node, scope, int(ok), 1, int(ok), now, now, 0, 1.0, float(ok), json.dumps([mark]), 0, now,
                          1, int(ok)))
            continue
        weight = _decay(now - (row["ts"] or now))
        w_checks = (row["w_checks"] if row["w_checks"] is not None else row["checks"]) * weight + 1
        w_ok = (row["w_ok"] if row["w_ok"] is not None else row["ok_checks"]) * weight + int(ok)
        checks, ok_checks = row["checks"] + 1, row["ok_checks"] + int(ok)
        recent = _recent_checks(row["recent"], now) + [mark]
        state, changed = bool(row["ok"]), row["changed"]
        streak = 0 if ok == state else (row["streak"] or 0) + 1
        flips, flips_since = row["flips"] or 0, row["flips_since"]
        d_since, d_checks, d_ok = row["d_since"], row["d_checks"] or 0, row["d_ok"] or 0
        if d_since is None or not 0 <= now - d_since < FLAP_WINDOW:
            d_since, d_checks, d_ok = now, 0, 0
        if streak >= ALERT_CONFIRM and (ok or _down_confirmed(conn, node, scope, now, streak, recent)):
            state, changed, streak = ok, now, 0
            if flips_since is None or not 0 <= now - flips_since < FLAP_WINDOW:
                flips, flips_since = 0, now
            flips += 1
            if checks >= ALERT_MIN_CHECKS:
                events.append({"node": node, "scope": scope, "ok": ok, "rate": w_ok / max(1.0, w_checks),
                               "checks": checks, "flips": flips, "day_rate": (d_ok + int(ok)) / (d_checks + 1),
                               "held": now - (row["changed"] or now)})
        conn.execute("UPDATE node_state SET ok=?, checks=?, ok_checks=?, changed=?, ts=?, streak=?, w_checks=?, "
                     "w_ok=?, recent=?, flips=?, flips_since=?, d_since=?, d_checks=?, d_ok=? WHERE node=? AND scope=?",
                     (int(state), checks, ok_checks, changed, now, streak, w_checks, w_ok, json.dumps(recent), flips,
                      flips_since, d_since, d_checks + 1, d_ok + int(ok), node, scope))
    return events


def _down_elsewhere(conn, node, scope, now):
    """Узел не отвечает в другом подтверждённом месте (выдуманное место не ускоряет тревоги в настоящих)."""
    scopes = [row["scope"] for row in conn.execute("SELECT scope FROM node_state WHERE node=? AND scope != ? AND "
                                                   "ok=0 AND ts > ?", (node, scope, now - ALERT_PLACES_WINDOW))]
    return bool(_confirmed_scopes(conn, scopes, now))


_telegram_error = [""]
_telegram_status = [0]


def telegram_configured():
    return bool(os.environ.get("TG_BOT_TOKEN", "") and os.environ.get("TG_ADMIN", ""))


def _telegram_description(exc) -> str:
    """Причина отказа из ответа Telegram ({"description": ...}), без неё - текст ошибки HTTP."""
    try:
        body = json.loads(exc.read().decode("utf-8", errors="replace") or "{}")
    except (OSError, ValueError, AttributeError):
        body = {}
    description = body.get("description") if isinstance(body, dict) else None
    return clip(description or "HTTP %s" % getattr(exc, "code", "?"), 300)


def telegram_send(text):
    """Тревога в Telegram через своего бота: TG_BOT_TOKEN и TG_ADMIN (chat id) из окружения сервиса.
    Причина неудачи - в _telegram_error (для журнала ошибок), код ответа HTTP - в _telegram_status (0 - сеть)."""
    token, chat = os.environ.get("TG_BOT_TOKEN", ""), os.environ.get("TG_ADMIN", "")
    _telegram_status[0] = 0
    if not token or not chat:
        return False
    try:
        data = urllib.parse.urlencode({"chat_id": chat, "text": text, "parse_mode": "HTML",
                                       "disable_web_page_preview": "1"}).encode()
        with urllib.request.urlopen("https://api.telegram.org/bot%s/sendMessage" % token, data=data, timeout=20):
            return True
    except urllib.error.HTTPError as exc:
        _telegram_status[0] = exc.code
        description = _telegram_description(exc)
        if exc.code in (401, 403, 404) or (exc.code == 400 and "chat" in description.lower()):
            message = t("Telegram: %s - проверьте TG_BOT_TOKEN / TG_ADMIN и что вы написали боту /start") % description
        else:
            message = "Telegram: HTTP %d: %s" % (exc.code, description)
        _telegram_error[0] = message.replace(token, "***")
        return False
    except Exception as exc:  # noqa: BLE001
        _telegram_error[0] = ("Telegram: %s: %s" % (type(exc).__name__, exc)).replace(token, "***")
        return False


def _telegram_refused() -> bool:
    """Telegram ответил 4xx (кроме 429): повтор того же сообщения ничего не даст."""
    return 400 <= _telegram_status[0] < 500 and _telegram_status[0] != 429


def deliver(text):
    """Отправить в Telegram: TELEGRAM_TRIES попыток с паузой TELEGRAM_PAUSE (на 4xx, кроме 429, - без повторов).
    Не вышло - запись в журнал ошибок (kind telegram; та же ошибка подряд - одна строка со свежим временем) и
    False: вызывающий оставит событие в очереди. Бот не настроен - доставлять некуда, считаем отправленным
    (история тревог в центре всё равно пишется)."""
    for attempt in range(TELEGRAM_TRIES):
        if telegram_send(text):
            return True
        if not telegram_configured():
            return True
        if _telegram_refused():
            break
        if attempt + 1 < TELEGRAM_TRIES:
            time.sleep(TELEGRAM_PAUSE)
    server_error("telegram", _telegram_error[0] or "sendMessage failed", merge=True)
    return False


_alert_worker: list = []
_alert_sent: deque = deque()
_alert_sent_lock = threading.Lock()


def _start_alert_worker():
    if not _alert_worker:
        thread = threading.Thread(target=_digest_loop, daemon=True, name="alerts")
        _alert_worker.append(thread)
        thread.start()


def send_alert(text, now=None, force=False):
    """Сообщение в Telegram: не больше ALERTS_PER_HOUR удачных отправок в час на весь сервер (неудачи лимит не
    тратят); force (учётка, «0 живых у всех», место в базе) - мимо лимита. Отправка с повторами (deliver) - из
    потока тревог, обработчик отчёта её не ждёт."""
    now = time.time() if now is None else now
    _telegram_status[0] = 0
    with _alert_sent_lock:
        while _alert_sent and now - _alert_sent[0] > 3600:
            _alert_sent.popleft()
        if not force and len(_alert_sent) >= ALERTS_PER_HOUR:
            return False
    if not deliver(text):
        return False
    with _alert_sent_lock:
        _alert_sent.append(now)
    return True


_notify_lock = threading.Lock()
_flush_lock = threading.Lock()
SCOPE_MIN_AGENTS = 2
SCOPE_WITNESS_DAYS = 7
MAX_ALERT_PENDING = 5000
MAX_ALERT_PENDING_SINGLE = 4000


def scope_witnesses(conn, scope, agent_id, now, net=""):
    """Отметить, что агент видит это место (регион · оператор), и вернуть, сколько разных СЕТЕЙ (IPv4 /24,
    IPv6 /48) видели его за SCOPE_WITNESS_DAYS: место из присланных координат выдумать легко, а десяток
    agent_id с одного адреса - всё равно один свидетель. Строки до обновления (без сети) - по agent_id."""
    if agent_id:
        conn.execute("INSERT OR REPLACE INTO scope_agents(scope, agent_id, ts, net) VALUES (?,?,?,?)",
                     (scope, agent_id, now, net or None))
    return _witness_count(conn, scope, now)


def _witness_count(conn, scope, now) -> int:
    return conn.execute("SELECT COUNT(DISTINCT COALESCE(net, 'agent:' || agent_id)) FROM scope_agents "
                        "WHERE scope=? AND ts > ?", (scope, now - SCOPE_WITNESS_DAYS * 86400)).fetchone()[0]


def _confirmed_scopes(conn, scopes, now) -> list:
    """Места с SCOPE_MIN_AGENTS свидетелями: выдуманное место не держит общие паузы по узлу."""
    return [scope for scope in scopes if _witness_count(conn, scope, now) >= SCOPE_MIN_AGENTS]


def notify(events, scope, agent_id="", witnesses=SCOPE_MIN_AGENTS, net=""):
    """События в очередь тревог (alert_pending); склеивает и отправляет их поток тревог (flush_alert_digest).
    - «перестал отвечать» - не чаще раза в ALERT_COOLDOWN на узел в месте и на узел вообще (общая пауза - только
      после тревоги из места с SCOPE_MIN_AGENTS свидетелями: выдуманное место не глушит настоящие; снимается,
      когда узел снова отвечает везде); событие под паузой ждёт в очереди её конца, а не выбрасывается;
    - «снова отвечает» - только если про это место уже ушло «перестал отвечать»;
    - узел, сменивший состояние FLAP_CHANGES раз за сутки в месте и живой там в доле проверок из FLAP_RATE (два
      настоящих падения за сутки - не мигание), - пауза FLAP_MUTE на это место (другие места тревожат как
      обычно, но глохнут уже после FLAP_KNOWN_CHANGES смен - _known_flapper), для подтверждённого места -
      сообщение «работает с перебоями»; после паузы - итог по месту (_end_mutes);
    - обратная смена до отправки гасит ожидающее событие, если пришла из другой сети; из той же - событие уйдёт,
      только если при отправке узел в месте всё ещё в том же состоянии (flush_alert_digest); погашенное
      «перестал отвечать», прождавшее дольше ALERT_BATCH_WAIT, - в историю тревог (_write_missed);
    - очередь не больше MAX_ALERT_PENDING, из них места с одним свидетелем - не больше
      MAX_ALERT_PENDING_SINGLE: поток выдуманных мест не вытесняет подтверждённые."""
    if not events:
        return
    with _notify_lock:
        now = time.time()
        with db() as conn:
            _queue_alerts(conn, events, agent_id, witnesses, net, now)


def _queue_alerts(conn, events, agent_id, witnesses, net, now):
    single = witnesses < SCOPE_MIN_AGENTS
    count = conn.execute("SELECT COUNT(*) FROM alert_pending").fetchone()[0]
    count_single = conn.execute("SELECT COUNT(*) FROM alert_pending WHERE witnesses < ?",
                                (SCOPE_MIN_AGENTS,)).fetchone()[0]
    for event in events:
        node, scope = event["node"], event["scope"]
        if _muted(conn, node, scope, now):
            continue
        key = _alert_key(event)
        waiting = conn.execute("SELECT * FROM alert_pending WHERE key=?", (key,)).fetchone()
        long_down = bool(event["ok"]) and (event.get("held") or 0) >= FLAP_LONG_DOWN
        flapping = _flapping(conn, node, now, event.get("day_rate", 0.5), _int(event.get("flips")),
                             known_only=long_down, known=not long_down)
        if waiting is not None and (flapping or (bool(waiting["ok"]) != bool(event["ok"])
                                                 and (not net or waiting["net"] != net))):
            conn.execute("DELETE FROM alert_pending WHERE key=?", (key,))
            if not flapping:
                _write_missed(conn, dict(waiting), now)
            count -= 1
            count_single -= int((waiting["witnesses"] or 0) < SCOPE_MIN_AGENTS)
        if flapping:
            _mute_place(conn, node, scope, now, announce=not single)
            continue
        if waiting is not None:
            continue
        state = conn.execute("SELECT down_sent FROM node_state WHERE node=? AND scope=?", (node, scope)).fetchone()
        if event["ok"] and not (state and state["down_sent"]):
            continue
        if count >= MAX_ALERT_PENDING or (single and count_single >= MAX_ALERT_PENDING_SINGLE):
            continue
        _pend(conn, key, event, agent_id, witnesses, now, net)
        count += 1
        count_single += int(single)


def _flapping(conn, node, now, day_rate, flips, known_only=False, known=True) -> bool:
    """Узел мигает в месте: живой там в доле проверок за сутки из FLAP_RATE и сменил состояние FLAP_CHANGES раз
    (known_only - не в счёт) или FLAP_KNOWN_CHANGES раз, если про него уже сказано «работает с перебоями» (known -
    в счёт; ожил после падения дольше FLAP_LONG_DOWN - не в счёт: это не мигание, а «снова отвечает»)."""
    if not FLAP_RATE[0] <= day_rate <= FLAP_RATE[1]:
        return False
    if flips >= FLAP_CHANGES and not known_only:
        return True
    return known and flips >= FLAP_KNOWN_CHANGES and _known_flapper(conn, node, now)


def _place_flapping(conn, node, scope, now) -> bool:
    """_flapping по текущему состоянию места (node_state): для событий, вставших в очередь раньше, чем про узел
    сказали «работает с перебоями»."""
    row = conn.execute("SELECT flips, flips_since, d_since, d_checks, d_ok FROM node_state WHERE node=? AND scope=?",
                       (node, scope)).fetchone()
    if row is None or row["d_since"] is None or not 0 <= now - row["d_since"] < FLAP_WINDOW or not row["d_checks"]:
        return False
    fresh = row["flips_since"] is not None and 0 <= now - row["flips_since"] < FLAP_WINDOW
    return _flapping(conn, node, now, (row["d_ok"] or 0) / row["d_checks"], (row["flips"] or 0) if fresh else 0,
                     known_only=True)


def _known_flapper(conn, node, now):
    """Про узел за FLAP_MEMORY сказано (или вот-вот уйдёт) «работает с перебоями» из подтверждённого места: в других
    местах он глохнет с FLAP_KNOWN_CHANGES-й смены (итог по месту придёт после его паузы). Молчаливые паузы мест
    с одним свидетелем не в счёт - выдуманное место не глушит настоящие тревоги по узлу."""
    return (_alert_cooling(conn, FLAP_PREFIX + node, now, FLAP_MEMORY)
            or conn.execute("SELECT 1 FROM alert_pending WHERE node=? AND substr(key, 1, ?) = ? LIMIT 1",
                            (node, len(FLAP_PREFIX), FLAP_PREFIX)).fetchone() is not None)


def _pend(conn, key, event, agent_id, witnesses, now, net=None, note=None):
    conn.execute("INSERT OR REPLACE INTO alert_pending(key, node, scope, ok, rate, checks, agent_id, witnesses, ts, "
                 "net, note) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                 (key, event["node"], event["scope"], int(bool(event["ok"])), float(event["rate"] or 0.0),
                  _int(event["checks"]), agent_id or "", _int(witnesses), now, net or None, note))


def _mute_key(node, scope):
    return "%s%s|%s" % (MUTE_PREFIX, node, scope)


def _muted(conn, node, scope, now):
    """Узел в месте на паузе «работает с перебоями» (MUTE_PREFIX узел|место; до круга 8 - на весь узел)."""
    return (_alert_cooling(conn, _mute_key(node, scope), now, FLAP_MUTE)
            or _alert_cooling(conn, MUTE_PREFIX + node, now, FLAP_MUTE))


def _mute_place(conn, node, scope, now, announce):
    """Узел мигает в месте: FLAP_MUTE без тревог по нему в этом месте. Не отвечает там сейчас - отметка
    down_sent, как после «перестал отвечать»: после паузы придёт итог (_end_mutes), даже если пауза молчаливая.
    announce - в очередь сообщение «работает с перебоями» (место подтверждено; по узлу - не чаще раза в
    FLAP_MUTE, места, замигавшие позже, глохнут молча)."""
    conn.execute("INSERT OR REPLACE INTO alert_last(key, ts) VALUES (?,?)", (_mute_key(node, scope), now))
    conn.execute("UPDATE node_state SET down_sent=COALESCE(down_sent, ?) WHERE node=? AND scope=? AND ok=0",
                 (now, node, scope))
    if announce and not _alert_cooling(conn, FLAP_PREFIX + node, now, FLAP_MUTE):
        conn.execute("INSERT OR IGNORE INTO alert_pending(key, node, scope, ok, rate, checks, agent_id, witnesses, "
                     "ts, net) VALUES (?,?,?,?,?,?,?,?,?,?)", ("%s%s|%s" % (FLAP_PREFIX, node, scope), node, scope, 0,
                                                              0.0, 0, "", SCOPE_MIN_AGENTS, now, None))


def _end_mutes(conn, now):
    """Пауза «работает с перебоями» кончилась. Место всё ещё меняет состояние (смена за последние
    ALERT_COOLDOWN или доля живых за сутки внутри FLAP_RATE) - пауза продлевается молча. Место не проверяли с
    начала паузы, а итог обещан (down_sent) - тоже продлевается (итог забудется, только если место пропадёт на
    ORPHAN_AFTER). Иначе итог: не отвечает - «так и не отвечает после перебоев»; отвечает - «снова отвечает»,
    если итог обещан (down_sent: «перестал отвечать», «работает с перебоями» или пауза при неответе)."""
    rows = conn.execute("SELECT l.key, l.ts AS muted, s.node, s.scope, s.ok, s.down_sent, s.ts, s.checks, s.w_ok, "
                        "s.changed, s.d_ok, s.d_checks, "
                        "s.w_checks FROM alert_last l JOIN node_state s ON l.key IN (? || s.node || '|' || s.scope, "
                        "? || s.node) WHERE substr(l.key, 1, ?) = ? AND l.ts <= ?",
                        (MUTE_PREFIX, MUTE_PREFIX, len(MUTE_PREFIX), MUTE_PREFIX, now - FLAP_MUTE)).fetchall()
    for row in rows:
        key = "%s|%s" % (row["node"], row["scope"])
        if _muted(conn, row["node"], row["scope"], now):
            continue
        day_rate = (row["d_ok"] or 0) / row["d_checks"] if row["d_checks"] else 0.0
        if (row["ts"] or 0) <= row["muted"]:
            if row["down_sent"]:
                conn.execute("INSERT OR REPLACE INTO alert_last(key, ts) VALUES (?,?)",
                             (_mute_key(row["node"], row["scope"]), now))
            continue
        if (row["changed"] or 0) > now - ALERT_COOLDOWN or FLAP_RATE[0] < day_rate < FLAP_RATE[1]:
            conn.execute("INSERT OR REPLACE INTO alert_last(key, ts) VALUES (?,?)",
                         (_mute_key(row["node"], row["scope"]), now))
            continue
        if (row["ok"] and not row["down_sent"]) or conn.execute("SELECT 1 FROM alert_pending WHERE key=?",
                                                                (key,)).fetchone():
            continue
        witnesses = _witness_count(conn, row["scope"], now)
        event = {"node": row["node"], "scope": row["scope"], "ok": row["ok"], "checks": row["checks"],
                 "rate": (row["w_ok"] or 0) / row["w_checks"] if row["w_checks"] else 0.0}
        _pend(conn, key, event, "", witnesses, now, note=FLAP_END)
    conn.execute("DELETE FROM alert_last WHERE substr(key, 1, ?) = ? AND ts <= ?",
                 (len(MUTE_PREFIX), MUTE_PREFIX, now - FLAP_MUTE))


def _mark_alerted(conn, rows, now, lines=()):
    """Отправленное: строки сообщения - в историю тревог (alerts, человеческим текстом), отметки пауз и
    «перестал отвечать» у узла в месте. «Работает с перебоями» обещает итог по месту (down_sent), память о
    перебоях узла (FLAP_MEMORY) считается от самих перебоев, а не от отправки. Общая пауза на узел - только по
    месту с SCOPE_MIN_AGENTS свидетелями; «снова отвечает», после которого узел не числится упавшим ни в одном
    подтверждённом месте, её снимает."""
    _write_history(conn, now, lines)
    for row in rows:
        conn.execute("DELETE FROM alert_pending WHERE key=? AND ts=?", (row["key"], row["ts"]))
        if row["key"].startswith(FLAP_PREFIX):
            conn.execute("INSERT INTO alert_last(key, ts) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET "
                         "ts=MAX(ts, excluded.ts)", (FLAP_PREFIX + row["node"], row["ts"] or now))
            conn.execute("UPDATE node_state SET down_sent=COALESCE(down_sent, ?) WHERE node=? AND scope=?",
                         (now, row["node"], row["scope"]))
            continue
        key, direction = _alert_key(row), "up" if row["ok"] else "down"
        conn.execute("INSERT OR REPLACE INTO alert_last(key, ts) VALUES (?,?)", ("%s|%s" % (key, direction), now))
        if not row["ok"] and (row["witnesses"] or 0) >= SCOPE_MIN_AGENTS:
            conn.execute("INSERT OR REPLACE INTO alert_last(key, ts) VALUES (?,?)", ("node:%s|down" % row["node"], now))
        if row["ok"]:
            conn.execute("INSERT OR REPLACE INTO alert_last(key, ts) VALUES (?,?)", ("node:%s|up" % row["node"], now))
        conn.execute("UPDATE node_state SET down_sent=? WHERE node=? AND scope=?",
                     (None if row["ok"] else now, row["node"], row["scope"]))
        _requeue_turned(conn, row, key, now)
    for node in {row["node"] for row in rows if row["ok"] and not row["key"].startswith(FLAP_PREFIX)}:
        scopes = [item["scope"] for item in conn.execute("SELECT scope FROM node_state WHERE node=? AND "
                                                         "down_sent IS NOT NULL", (node,)).fetchall()]
        if not _confirmed_scopes(conn, scopes, now):
            conn.execute("DELETE FROM alert_last WHERE key=?", ("node:%s|down" % node,))


def _requeue_turned(conn, row, key, now):
    """Пока сообщение уходило, узел в месте успел смениться обратно (обратное событие тогда не встало в очередь -
    ждало это): обратное событие - в очередь, иначе «перестал отвечать» остался бы без пары."""
    state = conn.execute("SELECT ok, checks, w_ok, w_checks FROM node_state WHERE node=? AND scope=?",
                         (row["node"], row["scope"])).fetchone()
    if state is None or bool(state["ok"]) == bool(row["ok"]) or _muted(conn, row["node"], row["scope"], now):
        return
    if conn.execute("SELECT 1 FROM alert_pending WHERE key=?", (key,)).fetchone():
        return
    event = {"node": row["node"], "scope": row["scope"], "ok": state["ok"], "checks": state["checks"],
             "rate": (state["w_ok"] or 0) / state["w_checks"] if state["w_checks"] else 0.0}
    _pend(conn, key, event, row["agent_id"], row["witnesses"], now, row["net"])


def _write_history(conn, now, lines, suffix=""):
    conn.executemany("INSERT INTO alerts(ts, kind, text, node) VALUES (?,?,?,?)",
                     [(now, kind, text + suffix, node) for kind, node, text in lines])


def _write_missed(conn, row, now):
    """Выброшенное из очереди без отправки - в историю тревог с пометкой «в Telegram не ушло»: «перестал
    отвечать», прождавшее дольше ALERT_BATCH_WAIT (молчал Telegram или шла пауза), - «не отвечал с - по»;
    «работает с перебоями», чья пауза кончилась, - «работал с перебоями». Короткие провалы, погашенные до
    отправки, в историю не идут."""
    if now - (row["ts"] or now) < ALERT_BATCH_WAIT:
        return
    what, name = _event_subject(row)
    place = html.escape(_scope_label(row["scope"] or ""))
    if row["key"].startswith(FLAP_PREFIX):
        kind, text = "flap", t("🟡 %s %s работал с перебоями: %s") % (what, name, place)
    elif not row["ok"]:
        state = conn.execute("SELECT ok, changed FROM node_state WHERE node=? AND scope=?",
                             (row["node"], row["scope"])).fetchone()
        until = state["changed"] if state is not None and state["ok"] and state["changed"] else now
        kind, text = "down", t("🔴 %s %s не отвечал: %s, %s - %s UTC") % (what, name, place, _utc(row["ts"]),
                                                                       _utc(until))
    else:
        return
    _write_history(conn, now, [(kind, row["node"], _plain(text))], " " + t("(в Telegram не ушло)"))


def _fresh_rows(conn, rows, now) -> list:
    """Что из очереди ещё правда. «Работает с перебоями» - пока пауза места действует (кончилась, пока молчал
    Telegram, - итог уже не придёт, не обещаем). Остальное - узел в месте сейчас в том же состоянии, что в
    событии (иначе «перестал отвечать», за которым успело прийти «снова отвечает», ушёл бы без пары), и место не
    на паузе. Выброшенное - из очереди, давнее - в историю тревог (_write_missed). Событие места, которое само
    мигает (_place_flapping), когда про узел уже сказано «работает с перебоями» (не в этой же пачке), ставит
    место на паузу вместо отправки."""
    fresh = []
    for row in rows:
        muted = _muted(conn, row["node"], row["scope"], now)
        if row["key"].startswith(FLAP_PREFIX):
            if not muted:
                conn.execute("DELETE FROM alert_pending WHERE key=? AND ts=?", (row["key"], row["ts"]))
                _write_missed(conn, row, now)
                continue
        else:
            state = conn.execute("SELECT ok FROM node_state WHERE node=? AND scope=?",
                                 (row["node"], row["scope"])).fetchone()
            turned = state is not None and bool(state["ok"]) != bool(row["ok"])
            if turned or muted:
                conn.execute("DELETE FROM alert_pending WHERE key=? AND ts=?", (row["key"], row["ts"]))
                if turned:
                    _write_missed(conn, row, now)
                continue
            if not row["ok"] and row.get("note") != FLAP_END and _place_flapping(
                    conn, row["node"], row["scope"], now) and not any(
                    item["node"] == row["node"] and item["key"].startswith(FLAP_PREFIX) for item in rows):
                _mute_place(conn, row["node"], row["scope"], now, announce=False)
                conn.execute("DELETE FROM alert_pending WHERE key=? AND ts=?", (row["key"], row["ts"]))
                continue
        fresh.append(row)
    return fresh


def _held(conn, row, now) -> bool:
    """«Перестал отвечать» под паузой ALERT_COOLDOWN (по месту или по узлу) ждёт в очереди её конца; «снова
    отвечает» по узлу, пока он ещё не отвечает в подтверждённом месте, - не чаще раза в ALERT_UP_GAP (места
    оживают вразнобой - одна строка на всех), иначе - сразу."""
    if row["key"].startswith(FLAP_PREFIX):
        return False
    if row["ok"]:
        if not _alert_cooling(conn, "node:%s|up" % row["node"], now, ALERT_UP_GAP):
            return False
        scopes = [item["scope"] for item in conn.execute("SELECT scope FROM node_state WHERE node=? AND ok=0 AND "
                                                         "ts > ?", (row["node"], now - ALERT_PLACES_WINDOW))]
        return bool(_confirmed_scopes(conn, scopes, now))
    return (_alert_cooling(conn, _alert_key(row) + "|down", now)
            or _alert_cooling(conn, "node:%s|down" % row["node"], now))


def _node_groups(rows):
    """События по узлу и направлению: [(node, ok, [строки])]. Первыми - узлы, у которых есть место с двумя
    свидетелями, потом по числу мест; внутри - подтверждённые места первыми, дальше по агентам по очереди -
    поток одного агента не вытесняет другие."""
    groups: OrderedDict[tuple, list] = OrderedDict()
    for row in _digest_order(rows):
        groups.setdefault((row["node"], bool(row["ok"])), []).append(row)

    def rank(group):
        confirmed = max(item["witnesses"] or 0 for item in group[2]) >= SCOPE_MIN_AGENTS
        return (not confirmed, -len(group[2]), group[0], group[1])

    return sorted(([node, ok, items] for (node, ok), items in groups.items()), key=rank)


def _digest_order(rows):
    queues: OrderedDict[str, deque] = OrderedDict()
    for row in sorted(rows, key=lambda row: (-(row["witnesses"] or 0), row["ts"] or 0)):
        queues.setdefault(row["agent_id"] or "", deque()).append(row)
    ordered = []
    while queues:
        for agent in list(queues):
            ordered.append(queues[agent].popleft())
            if not queues[agent]:
                del queues[agent]
    return ordered


def _places_down(conn, node, now):
    """(в скольких местах узел сейчас не отвечает, во скольких его проверяли за ALERT_PLACES_WINDOW)."""
    row = conn.execute("SELECT COUNT(*), SUM(ok = 0) FROM node_state WHERE node=? AND ts > ?",
                       (node, now - ALERT_PLACES_WINDOW)).fetchone()
    return int(row[1] or 0), int(row[0] or 0)


def _day_rate(conn, node, now) -> float:
    """Доля удачных проверок узла за сутки по всем местам."""
    row = conn.execute("SELECT SUM(d_ok), SUM(d_checks) FROM node_state WHERE node=? AND d_since > ?",
                       (node, now - FLAP_WINDOW)).fetchone()
    return (row[0] or 0) / row[1] if row and row[1] else 0.0


def flush_alert_digest(now=None):
    """Поток тревог, раз в минуту: учётка узлов, место в базе, «0 живых у всех», итоги пауз «работает с
    перебоями» (_end_mutes), место, которое не проверяли ORPHAN_AFTER, забывает своё «перестал отвечать» (молча:
    «снова отвечает» оттуда не придёт), и склеенные события узлов. События копятся ALERT_BATCH_WAIT от самого раннего и
    уходят одним сообщением: строка на узел со списком мест (до ALERT_PLACES) и сколько мест всего не отвечает,
    до ALERT_LINES строк и ALERT_TEXT_MAX символов, дальше «…и ещё N» (в историю тревог пишутся все). «Перестал
    отвечать» под паузой ALERT_COOLDOWN ждёт её конца (_held). Перед отправкой выбрасываются события, которые уже
    неправда (_fresh_rows). Пока половина и больше сетей агентов в нуле - похоже на поломку у нас: события держим
    (до FLEET_WINDOW), а когда в нуле все - «перестал отвечать» выбрасываем (вместо них одно «0 живых у всех»).
    Telegram не ответил - события остаются в очереди сколько угодно (старые помечаются «было N ч назад»);
    Telegram отказал 400 - сообщение выброшено с записью в журнал ошибок и в историю тревог с пометкой. Telegram
    ждём без замка очереди. True - что-то отправлено."""
    with _flush_lock:
        now = time.time() if now is None else now
        sent = check_disk(now)
        sent = check_expiry(now) or sent
        sent = check_db_room(now) or sent
        with _notify_lock, db() as conn:
            _end_mutes(conn, now)
            conn.execute("UPDATE node_state SET down_sent=NULL WHERE down_sent IS NOT NULL AND ts < ?",
                         (now - ORPHAN_AFTER,))
            rows = [dict(row) for row in conn.execute("SELECT * FROM alert_pending ORDER BY ts").fetchall()]
            fleet = [row for row in rows if row["key"] == FLEET_KEY]
            rows = [row for row in rows if row["key"] != FLEET_KEY and not _held(conn, row, now)]
        if fleet:
            sent = _send_fleet_zero(fleet[0], now) or sent
        if not rows or now - rows[0]["ts"] < ALERT_BATCH_WAIT:
            return sent
        with db() as conn:
            nets, zero = fleet_zero_status(conn, now)
        if nets >= FLEET_MIN_AGENTS and zero * 2 >= nets:
            if zero < nets and now - rows[0]["ts"] < FLEET_WINDOW:
                return sent
            if zero >= nets:
                with _notify_lock, db() as conn:
                    conn.execute("DELETE FROM alert_pending WHERE ok=0 AND key != ? AND substr(key, 1, ?) != ?",
                                 (FLEET_KEY, len(FLAP_PREFIX), FLAP_PREFIX))
                rows = [row for row in rows if row["ok"] or row["key"].startswith(FLAP_PREFIX)]
        with _notify_lock, db() as conn:
            rows = _fresh_rows(conn, rows, now)
        if not rows:
            return sent
        with db() as conn:
            text, lines = _alert_text(conn, rows, now)
        if not send_alert(text, now):
            if telegram_configured() and _telegram_status[0] == 400:
                with _notify_lock, db() as conn:
                    _mark_dropped(conn, rows, now, lines)
                server_error("telegram", t("Telegram не принял сообщение, тревоги выброшены: %s")
                             % " / ".join(line[2] for line in lines)[:600])
            return sent
        with _notify_lock, db() as conn:
            _mark_alerted(conn, rows, now, lines)
        return True


def _mark_dropped(conn, rows, now, lines=()):
    """Telegram отказал: события - из очереди, их строки - в историю тревог с пометкой «в Telegram не ушло»."""
    _write_history(conn, now, lines, " " + t("(в Telegram не ушло)"))
    for row in rows:
        conn.execute("DELETE FROM alert_pending WHERE key=? AND ts=?", (row["key"], row["ts"]))


ALERT_HEAD = "<b>VPNCheck</b>"


def _plain(text):
    return html.unescape(re.sub(r"<[^>]+>", "", text))


def _history_text(text):
    """Строка для истории тревог: без разметки и без приставки «VPNCheck» (в центре и так видно, чьё)."""
    return _plain(text[len(ALERT_HEAD):].lstrip() if text.startswith(ALERT_HEAD) else text)


def _alert_text(conn, rows, now):
    """(текст сообщения, [(вид, узел, строка без разметки)] - для истории тревог: все события пачки, в том числе
    не вошедшие в сообщение)."""
    flaps: OrderedDict[str, list] = OrderedDict()
    for row in rows:
        if row["key"].startswith(FLAP_PREFIX):
            flaps.setdefault(row["node"], []).append(row)
    entries = [("flap", node, items) for node, items in flaps.items()]
    entries += [("up" if ok else "down", node, items)
                for node, ok, items in _node_groups([row for row in rows if not row["key"].startswith(FLAP_PREFIX)])]
    out, lines, size, full = [ALERT_HEAD], [], len(ALERT_HEAD), False
    for kind, node, items in entries:
        line = _alert_line(conn, kind, node, items, now)
        lines.append((kind, node, _plain(line)))
        full = full or len(out) > ALERT_LINES or size + 1 + len(line) > ALERT_TEXT_MAX - 200
        if not full:
            out.append(line)
            size += 1 + len(line)
    hidden = len(lines) - len(out) + 1
    if hidden:
        out.append(t("…и ещё %d - все тревоги: стенд → Агенты → Центр управления агентами → Стабильность") % hidden)
    return "\n".join(out), lines


def _alert_line(conn, kind, node, items, now):
    what, name = _event_subject({"node": node})
    places = [html.escape(_short(_scope_label(item["scope"]))) for item in items if item["scope"]]
    shown = ", ".join(places[:ALERT_PLACES])
    if len(places) > ALERT_PLACES:
        shown += " " + t("…и ещё %d") % (len(places) - ALERT_PLACES)
    down, total = _places_down(conn, node, now)
    if kind == "flap":
        line = "🟡 " + t("%s %s работает с перебоями: %s - отвечал в %d%% проверок за сутки, %s. Пока перебои не "
                         "кончатся (не меньше суток), тревог по нему там не будет, потом придёт итог.") % (
            what, name, shown or t("во всех местах"), round(100 * _day_rate(conn, node, now)),
            _now_note(down, total))
    elif kind == "down":
        template = (t("🔴 %s %s так и не отвечает после перебоев: %s %s")
                    if any(item.get("note") == FLAP_END for item in items if not item["ok"])
                    else t("🔴 %s %s перестал отвечать: %s %s"))
        line = template % (what, name, shown, _down_note(down, total))
    elif down:
        line = t("🟢 %s %s снова отвечает: %s (ещё не отвечает: мест %d из %d)") % (what, name, shown, down, total)
    else:
        line = t("🟢 %s %s снова отвечает: %s (теперь отвечает везде)") % (what, name, shown)
    age = now - min(item["ts"] or now for item in items)
    if age >= 48 * 3600:
        line += " · " + t("было %d дн. назад") % int(age // 86400)
    elif age >= ALERT_OLD:
        line += " · " + t("было %d ч назад") % int(age // 3600)
    return line


def _down_note(down, total):
    if total <= 1:
        return t("(не отвечает в единственном месте, где его проверяют)")
    return t("(не отвечает сейчас: мест %d из %d)") % (down, total)


def _now_note(down, total):
    if total <= 1:
        return t("сейчас не отвечает") if down else t("сейчас отвечает")
    return t("сейчас не отвечает: мест %d из %d") % (down, total)


def _short(text):
    return text if len(text) <= ALERT_PLACE_CHARS else text[:ALERT_PLACE_CHARS - 1] + "…"


OPERATORS_EN = {"мтс": "MTS", "мегафон": "MegaFon", "билайн": "Beeline", "т2": "T2", "теле2": "Tele2",
                "ростелеком": "Rostelecom", "йота": "Yota", "дом.ру": "Dom.ru", "мгтс": "MGTS",
                "вымпелком": "Vimpelcom"}


def operator_name(text: str) -> str:
    """Оператор места на языке сервера: при en - известные названия по-английски, остальное латиницей."""
    if LANG != "en" or not text:
        return text
    parts = []
    for part in text.split(" · "):
        parts.append(OPERATORS_EN.get(part.strip().lower()) or _latin(part))
    return " · ".join(parts)


def _scope_label(scope):
    region, sep, operator = (scope or "").partition(" · ")
    return place_name(region) + sep + operator_name(operator)


def _digest_loop():
    while True:
        time.sleep(60)
        with contextlib.suppress(Exception):
            flush_alert_digest()


def _alert_key(event):
    return "%s|%s" % (event["node"], event["scope"])


def _alert_cooling(conn, key, now, cooldown=None):
    row = conn.execute("SELECT ts FROM alert_last WHERE key=?", (key,)).fetchone()
    return bool(row) and now - row["ts"] < (ALERT_COOLDOWN if cooldown is None else cooldown)


def _event_subject(event):
    """(«сайт»/«узел», имя без приставки site:) для строки тревоги; имя экранировано для parse_mode=HTML."""
    if event["node"].startswith("site:"):
        return t("сайт"), html.escape(event["node"][len("site:"):])
    return t("узел"), html.escape(event["node"])


def nodes_expired(state, now=None):
    """Учётка узлов агентов истекла (nodes_expire из state): их «мёртвые» узлы - не падение узлов."""
    expire = _finite_or_zero(state.get("nodes_expire"))
    return 0 < expire <= (time.time() if now is None else now)


def _finite_or_zero(value):
    try:
        return finite(value or 0)
    except (TypeError, ValueError):
        return 0.0


MONTHS_EN = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def _utc(ts):
    """Дата и время UTC для тревог: «01.10 01:25» по-русски, "Oct 1 01:25" по-английски (01.10 там - 10 января)."""
    moment = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
    if LANG == "en":
        return "%s %d %s" % (MONTHS_EN[moment.month - 1], moment.day, moment.strftime("%H:%M"))
    return moment.strftime("%d.%m %H:%M")


def _expired_text(state, expire):
    return t("<b>VPNCheck</b> ⛔ Учётка узлов агентов %s истекла %s - агенты не могут подключиться к узлам, "
             "проверки стоят. Перевыложите узлы (стенд заведёт новую учётку на 30 дней): стенд → Агенты → Центр "
             "управления агентами → Узлы и обновления.") % (html.escape(clip(state.get("nodes_user") or "?", 64)),
                                                              _utc(expire) + " UTC")


def check_expiry(now):
    """Учётка узлов агентов (nodes_expire из state), мимо часового лимита: предупреждение за EXPIRY_WARN_DAYS
    дней - по одному на порог (пройдены сразу несколько - одно сообщение), и одно «истекла» сразу после срока
    (не позже EXPIRED_NOTICE). True - отправлено."""
    state = load_state()
    expire = _finite_or_zero(state.get("nodes_expire"))
    if expire <= 0 or now - expire > EXPIRED_NOTICE:
        return False
    warns = ["expire:%d:%d" % (int(expire), days) for days in EXPIRY_WARN_DAYS]
    if now >= expire:
        passed = ["expired:%d" % int(expire)] + warns
        text, kind = _expired_text(state, expire), EXPIRED_KIND
    else:
        passed = [key for key, days in zip(warns, EXPIRY_WARN_DAYS, strict=True) if now >= expire - days * 86400]
        text = t("<b>VPNCheck</b> ⚠ Учётка узлов агентов %s истекает %s UTC (осталось дней: %d) - после этого "
                 "агенты не смогут подключаться к узлам. Перевыложите узлы: стенд → Агенты → Центр управления "
                 "агентами → Узлы и обновления.") % (html.escape(clip(state.get("nodes_user") or "?", 64)),
                                                     _utc(expire), max(1, math.ceil((expire - now) / 86400)))
        kind = "expiry"
    with db() as conn:
        fresh = [key for key in passed
                 if conn.execute("SELECT 1 FROM alert_last WHERE key=?", (key,)).fetchone() is None]
    if not fresh or (now >= expire and fresh[0] != passed[0]):
        return False
    if not send_alert(text, now, force=True):
        return False
    with db() as conn:
        conn.execute("INSERT INTO alerts(ts, kind, text) VALUES (?,?,?)", (now, kind, _history_text(text)))
        conn.executemany("INSERT OR REPLACE INTO alert_last(key, ts) VALUES (?,?)", [(key, now) for key in passed])
    return True


def db_limit_bytes() -> int:
    return (_int(os.environ.get("VPNAGENT_MAX_DB_MB")) or MAX_DB_MB) * 1024 * 1024


def check_db_room(now):
    """Место в базе (мимо часового лимита): база перешла DB_ROOM_WARN от предела - одно предупреждение (следующее
    - только после того, как она опустится ниже DB_ROOM_REARM); самые старые отчёты уже вытесняются - одно
    сообщение, сколько дней хранится, и не чаще раза в DB_EVICT_NOTICE. True - отправлено."""
    limit = db_limit_bytes()
    used = db_used_bytes(now)
    with db() as conn:
        if used < DB_ROOM_REARM * limit:
            conn.execute("DELETE FROM alert_last WHERE key IN ('db_room', 'db_evict')")
            return False
        evicting = 0 < now - _evicted[0] < 86400
        if evicting:
            if _alert_cooling(conn, "db_evict", now, DB_EVICT_NOTICE):
                return False
            oldest = conn.execute("SELECT MIN(ts) FROM reports").fetchone()[0] or now
        elif used < DB_ROOM_WARN * limit or conn.execute("SELECT 1 FROM alert_last WHERE key='db_room'").fetchone():
            return False
    command = "echo VPNAGENT_MAX_DB_MB=%d | sudo tee -a /opt/vpnagent/env && sudo systemctl restart vpnagent" % (
        3 * (limit >> 20))
    if evicting:
        key = "db_evict"
        text = t("<b>VPNCheck</b> ⚠ База сервера на пределе (%d МБ) - самые старые отчёты уже удаляются, хранятся "
                 "последние %d дн. Поднимите предел: %s (или освободите диск).") % (
            limit >> 20, max(1, int((now - oldest) // 86400)), command)
    else:
        key = "db_room"
        text = t("<b>VPNCheck</b> ⚠ База сервера заполнена на %d%% (%d из %d МБ) - скоро начнут удаляться самые "
                 "старые отчёты. Поднимите предел: %s (или освободите диск).") % (
            min(100, round(100 * used / limit)), used >> 20, limit >> 20, command)
    if not send_alert(text, now, force=True):
        return False
    with db() as conn:
        conn.execute("INSERT INTO alerts(ts, kind, text) VALUES (?,?,?)", (now, "db_room", _history_text(text)))
        conn.executemany("INSERT OR REPLACE INTO alert_last(key, ts) VALUES (?,?)", [("db_room", now), (key, now)])
    return True


FLEET_WINDOW = 3 * 3600
FLEET_MIN_AGENTS = 3


def fleet_zero_status(conn, now=None):
    """(сколько сетей агентов отчитались за FLEET_WINDOW, во скольких из них все агенты с нулём живых узлов).

    Берётся последний надёжный полный отчёт каждого агента, известного дольше AGENT_TRUST_AGE; агенты
    считаются по сетям адреса (IPv4 /24, IPv6 /48) - десяток agent_id с одного адреса не делает «всех».
    Все в нуле одновременно - почти никогда не операторы: они режут по-разному в разных регионах.
    Это наша поломка - истекла учётка узлов агентов, сменились узлы в панели или упала сама панель.
    """
    now = now or time.time()
    rows = conn.execute("SELECT agent_id, ip, alive, total, MAX(ts) FROM reports WHERE ts > ? AND total > 0 "
                        "AND operator NOT LIKE 'VPN ·%' AND trusted = 1 AND partial = 0 "
                        "AND agent_id IN (SELECT agent_id FROM agents WHERE first_seen <= ?) GROUP BY agent_id",
                        (now - FLEET_WINDOW, now - AGENT_TRUST_AGE)).fetchall()
    nets: dict[str, bool] = {}
    for row in rows:
        key = net_key(row["ip"]) if row["ip"] else "agent:" + row["agent_id"]
        nets[key] = nets.get(key, True) and not row["alive"]
    return len(nets), sum(1 for zero in nets.values() if zero)


def check_fleet_zero():
    """«Вся сеть агентов в нуле» - в очередь тревог (уйдёт с ближайшим проходом потока тревог, мимо часового
    лимита), не чаще раза в ALERT_COOLDOWN."""
    with _notify_lock:
        now = time.time()
        with db() as conn:
            nets, zero = fleet_zero_status(conn, now)
            if nets < FLEET_MIN_AGENTS or zero < nets or _alert_cooling(conn, FLEET_KEY, now):
                return
            conn.execute("INSERT OR REPLACE INTO alert_pending(key, node, scope, ok, rate, checks, agent_id, "
                         "witnesses, ts, net) VALUES (?,?,?,?,?,?,?,?,?,?)",
                         (FLEET_KEY, "", "", 0, 0.0, nets, "", nets, now, None))


def _send_fleet_zero(row, now):
    """«0 у всех»; если учётка узлов уже истекла - вместо него «учётка истекла» (одно на срок учётки)."""
    state = load_state()
    expire = _finite_or_zero(state.get("nodes_expire"))
    keys = [FLEET_KEY]
    if nodes_expired(state, now):
        keys.append("expired:%d" % int(expire))
        with db() as conn:
            told = conn.execute("SELECT 1 FROM alert_last WHERE key=?", (keys[1],)).fetchone() is not None
        text, kind = (None if told else _expired_text(state, expire)), EXPIRED_KIND
    else:
        text = t("<b>VPNCheck</b> ⚠ За 3 часа ни один агент не достучался ни до одного узла (агенты из %d разных "
                 "сетей). Операторы так не режут - скорее всего, истекла учётка узлов агентов, узлы сменились в "
                 "панели или панель недоступна. Перевыложите узлы: стенд → Агенты → Центр управления агентами → "
                 "Узлы и обновления.") % (row["checks"] or 0)
        kind = FLEET_KEY
    if text is not None and not send_alert(text, now, force=True):
        return False
    with _notify_lock, db() as conn:
        if text is not None:
            conn.execute("INSERT INTO alerts(ts, kind, text) VALUES (?,?,?)", (now, kind, _history_text(text)))
        conn.executemany("INSERT OR REPLACE INTO alert_last(key, ts) VALUES (?,?)", [(key, now) for key in keys])
        conn.execute("DELETE FROM alert_pending WHERE key=?", (FLEET_KEY,))
    return text is not None


@app.get("/v1/admin/trends", dependencies=[Depends(require_admin)])
def admin_trends(scope: str = "", limit: int = 5000, offset: int = 0):
    """Стабильность: доля удачных проверок за последнюю неделю (rate, checks - затухающие счёты, старые
    проверки весят меньше; checks_all/ok_checks_all - за всё время) и когда состояние менялось. Страница -
    limit строк после offset, свежие первыми; total - сколько строк всего (центр пишет «показано N из M»)."""
    limit = clamp_limit(limit, 20000)
    offset = max(0, _int(offset))
    where, params = ("WHERE scope=? ", (scope,)) if scope else ("", ())
    now = time.time()
    with db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM node_state " + where, params).fetchone()[0]
        rows = conn.execute("SELECT * FROM node_state " + where + "ORDER BY ts DESC LIMIT ? OFFSET ?",
                            params + (limit, offset)).fetchall()
    rows = sorted(rows, key=lambda row: (row["scope"] or "", row["node"] or ""))
    nodes = []
    for row in rows:
        item = dict(row)
        weight = _decay(now - (row["ts"] or now))
        w_checks = (row["w_checks"] if row["w_checks"] is not None else row["checks"] or 0) * weight
        w_ok = (row["w_ok"] if row["w_ok"] is not None else row["ok_checks"] or 0) * weight
        item["checks_all"], item["ok_checks_all"] = row["checks"], row["ok_checks"]
        item["checks"] = int(round(w_checks))
        item["ok_checks"] = int(round(w_ok))
        item["rate"] = w_ok / w_checks if w_checks > 0 else 0.0
        item["stable"] = item["checks"] >= ALERT_MIN_CHECKS and (item["rate"] >= STABLE_RATE
                                                                 or item["rate"] <= 1 - STABLE_RATE)
        for key in ("w_checks", "w_ok", "streak", "down_sent"):
            item.pop(key, None)
        nodes.append(item)
    return {"nodes": nodes, "total": total, "offset": offset, "new_agents": new_agents(now)}


def new_agents(now) -> int:
    """Агенты младше AGENT_TRUST_AGE: их отчёты ещё не в матрице и стабильности (центр пишет, почему пусто)."""
    with db() as conn:
        return conn.execute("SELECT COUNT(*) FROM agents WHERE first_seen > ?", (now - AGENT_TRUST_AGE,)).fetchone()[0]


@app.get("/v1/admin/alerts", dependencies=[Depends(require_admin)])
def admin_alerts(limit: int = 100):
    """История тревог, свежие первыми: kind - down, up, flap, expiry (учётка скоро истечёт), expired (истекла),
    fleet_zero, db_room (more - записи до круга 8); text - строка сообщения без разметки и без приставки
    «VPNCheck» (записи до круга 7 - служебные ключи «узел|место|вид»); «(в Telegram не ушло)» - Telegram отказал."""
    limit = clamp_limit(limit, 1000)
    with db() as conn:
        rows = conn.execute("SELECT * FROM alerts ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
    return {"alerts": [dict(row) for row in rows]}


def push_all(action, agent_id=""):
    """Разослать push всем (или одному) и убрать умершие токены. Возвращает число отправленных."""
    with db() as conn:
        if agent_id:
            rows = conn.execute("SELECT agent_id, token FROM push WHERE agent_id=?", (agent_id,)).fetchall()
        else:
            rows = conn.execute("SELECT agent_id, token FROM push").fetchall()
    sent, dead = fcm.send([row["token"] for row in rows], action)
    if dead:
        with db() as conn:
            conn.executemany("DELETE FROM push WHERE token=?", [(token,) for token in dead])
    return sent


@app.post("/v1/errors", dependencies=[Depends(require_public)])
async def post_errors(request: Request):
    """Падения агента вне проверки (необработанные исключения) - без ожидания следующего отчёта."""
    payload, agent_id = _parse_agent_body(await request.body(), 64 * 1024)
    ip = client_ip(request)
    limit_writes(agent_id, ip)
    return await asyncio.to_thread(_store_agent_errors, payload, agent_id, ip)


def _store_agent_errors(payload, agent_id, ip):
    require_room()
    admit_agent(agent_id, ip)
    device = payload.get("device") if isinstance(payload.get("device"), dict) else {}
    with db() as conn:
        stored = store_errors(conn, agent_id, payload.get("app_version", ""), device.get("model", ""),
                              payload.get("errors"))
    return {"ok": True, "stored": stored}


@app.post("/v1/admin/errors/clear", dependencies=[Depends(require_admin)])
def admin_errors_clear():
    with db() as conn:
        conn.execute("DELETE FROM errors")
    return {"ok": True}


@app.get("/v1/admin/errors", dependencies=[Depends(require_admin)])
def admin_errors(since: float = 0, limit: int = 300):
    limit = clamp_limit(limit, 2000)
    with db() as conn:
        rows = conn.execute("SELECT * FROM errors WHERE ts > ? ORDER BY ts DESC LIMIT ?", (since, limit)).fetchall()
    return {"errors": [dict(r) for r in rows]}


@app.get("/files/{name}", dependencies=[Depends(require_public)])
def get_file(name: str):
    if not re.match(r"^[A-Za-z0-9._-]{1,80}$", name) or name.startswith(".") or name.endswith(".part"):
        raise HTTPException(status_code=404)
    path = os.path.join(FILES_DIR, name)
    if not os.path.exists(path):
        raise HTTPException(status_code=404)
    return FileResponse(path, filename=name, content_disposition_type="attachment", headers=FILE_HEADERS)


def agent_on_tls(row) -> bool:
    """Агент ходит по https: последний запрос по TLS не старше TLS_SEEN_WINDOW от последнего выхода на связь."""
    last_tls, last_seen = row.get("last_tls"), row.get("last_seen")
    return bool(last_tls) and bool(last_seen) and last_seen - last_tls <= TLS_SEEN_WINDOW


@app.get("/v1/admin/agents", dependencies=[Depends(require_admin)])
def admin_agents():
    """Карточки агентов. alive/total - из последнего надёжного полного отчёта (trusted_ts - когда он был);
    last_trusted/last_partial - каким был самый последний отчёт (до обновления сервера - считаем надёжным);
    doubts - почему последнему отчёту нельзя верить или его маршрут под сомнением (report_doubts)."""
    with db() as conn:
        rows = conn.execute("SELECT * FROM agents ORDER BY last_seen DESC").fetchall()
        pushable = {row["agent_id"] for row in conn.execute("SELECT agent_id FROM push").fetchall()}
        last = {}
        for row in rows[:MAX_DOUBT_AGENTS]:
            found = conn.execute("SELECT payload FROM reports WHERE agent_id = ? ORDER BY ts DESC LIMIT 1",
                                 (row["agent_id"],)).fetchone()
            last[row["agent_id"]] = loads_stored(found["payload"], {}) if found else {}
    agents = []
    for row in rows:
        item = dict(row)
        item["doubts"] = report_doubts(last.get(item["agent_id"]))
        item["push"] = item["agent_id"] in pushable
        item["online"] = online_now(item["agent_id"])
        item["last_trusted"] = item.get("last_trusted") is None or bool(item["last_trusted"])
        item["last_partial"] = bool(item.get("last_partial"))
        item["https"] = agent_on_tls(item)
        agents.append(item)
    return {"agents": agents, "server_time": time.time(), "push_enabled": bool(fcm.project_id())}


@app.get("/v1/admin/reports", dependencies=[Depends(require_admin)])
def admin_reports(since: float = 0, limit: int = 500, agent_id: str = ""):
    limit = clamp_limit(limit, 2000)
    with db() as conn:
        if agent_id:
            rows = conn.execute("SELECT " + REPORT_COLUMNS + " FROM reports WHERE ts > ? AND agent_id = ? "
                                "ORDER BY ts DESC LIMIT ?",
                                (since, clip(agent_id), limit)).fetchall()
        else:
            rows = conn.execute("SELECT " + REPORT_COLUMNS + " FROM reports WHERE ts > ? ORDER BY ts DESC LIMIT ?",
                                (since, limit)).fetchall()
    return {"reports": [report_item(row) for row in rows]}


MAX_DOUBT_AGENTS = 1000


def report_doubts(payload) -> list:
    """Коды сомнений отчёта для админки: vpn, direct (нет обычного интернета), core-direct (ядро не вышло в сеть),
    route (выход совпал с Wi-Fi или разошёлся), bind-ip (ядро держалось сети только по адресу), partial."""
    if not isinstance(payload, dict):
        return []
    checks = (("vpn", vpn_in_report(payload)), ("direct", payload.get("direct_ok") is False),
              ("core-direct", payload.get("core_direct_ok") is False),
              ("route", bool(payload.get("same_ip_as") or payload.get("route_mismatch"))),
              ("bind-ip", payload.get("bind") == "ip"), ("partial", bool(payload.get("partial"))))
    return [code for code, hit in checks if hit]


REPORT_COLUMNS = "id, agent_id, ts, ip, region, city, operator, network, alive, total, payload, trusted, partial"


def report_item(row):
    """Отчёт для центра: trusted/partial - можно ли верить замеру; direct_ok, core_direct_ok, same_ip_as,
    route_mismatch, vpn, deferred - почему нельзя (из payload); bind - как ядро держалось сети (device / ip /
    none); dead_reasons - почему узлы мертвы (dns-sinkhole, dns-fail). Старые отчёты без колонок считаются
    надёжными."""
    item = dict(row)
    payload = loads_stored(item["payload"], {})
    payload = payload if isinstance(payload, dict) else {}
    item["payload"] = payload
    item["trusted"] = item.get("trusted") is None or bool(item["trusted"])
    item["partial"] = bool(item.get("partial"))
    item["direct_ok"] = payload.get("direct_ok") is not False
    item["same_ip_as"] = clip(payload.get("same_ip_as") or "", 16)
    item["route_mismatch"] = bool(payload.get("route_mismatch"))
    item["core_direct_ok"] = payload.get("core_direct_ok") is not False
    item["bind"] = payload.get("bind") if payload.get("bind") in BIND_KINDS else ""
    item["vpn"] = bool(payload.get("vpn_active")) or str(item.get("operator") or "").startswith("VPN")
    item["deferred"] = _int(payload.get("deferred_s"))
    unchecked = payload.get("unchecked_nodes")
    item["unchecked_nodes"] = unchecked if isinstance(unchecked, dict) else {}
    item["dead_reasons"] = dead_reasons(payload.get("results"))
    return item


def dead_reasons(results):
    """{узел: "dns-sinkhole" | "dns-fail"} - почему узел в отчёте мёртв, если агент знает причину."""
    return {key: value["error"] for key, value in (results.items() if isinstance(results, dict) else ())
            if isinstance(value, dict) and value.get("error") in DEAD_REASONS}


MATRIX_MAX_REPORTS = 20000
MATRIX_MAX_HOURS = 24 * 30
MATRIX_CACHE_TTL = 60.0
MATRIX_CACHE_KEEP = 8
_matrix_cache: OrderedDict = OrderedDict()
_matrix_lock = threading.Lock()


@app.get("/v1/admin/matrix", dependencies=[Depends(require_admin)])
def admin_matrix(hours: float = 24):
    """Узел × (регион, оператор): сколько раз жив / сколько проверок за период. Из частичного отчёта
    берутся только живые узлы: «мёртвые» там могут быть просто не проверенными до конца. Только агенты
    старше AGENT_TRUST_AGE, не больше MATRIX_MAX_REPORTS свежих отчётов, отчёты читаются потоком.
    unchecked - узел × колонка: почему агент не проверил узел в последний раз ("unsupported", "rejected",
    "core-direct", "vpn", "core-exit:N"). reasons - узел × колонка: почему узел был мёртв в последнем отчёте
    ("dns-sinkhole", "dns-fail"). truncated - отчётов больше MATRIX_MAX_REPORTS, матрица собрана с since
    (граница последнего вошедшего отчёта), а не за все hours. Регион колонки приведён к одному названию
    (canonical_region). Готовая матрица живёт MATRIX_CACHE_TTL: центр спрашивает её каждые 20 с, а отчёты на
    большом парке идут чаще - кэш по последнему отчёту почти не попадал."""
    now = time.time()
    hours = hours if math.isfinite(hours) else 24
    hours = max(0.0, min(hours, MATRIX_MAX_HOURS))
    key = (DB_PATH, hours)
    with _matrix_lock:
        cached = _matrix_cache.get(key)
        if cached is not None and now - cached[0] < MATRIX_CACHE_TTL:
            return cached[1]
    since = now - hours * 3600
    matrix: dict[str, dict[str, list[int]]] = {}
    columns: dict[str, dict[str, Any]] = {}
    sites_matrix: dict[str, dict[str, list[int]]] = {}
    unchecked: dict[str, dict[str, str]] = {}
    reasons: dict[str, dict[str, str]] = {}
    count, oldest = 0, None
    with db() as conn:
        for row in conn.execute("SELECT ts, region, city, operator, network, payload, partial FROM reports "
                                "WHERE ts > ? AND trusted = 1 AND COALESCE(operator, '') NOT LIKE 'VPN%' "
                                "AND agent_id IN (SELECT agent_id FROM agents WHERE first_seen <= ?) "
                                "ORDER BY ts DESC LIMIT ?", (since, now - AGENT_TRUST_AGE, MATRIX_MAX_REPORTS)):
            _matrix_add(row, matrix, sites_matrix, columns, unchecked, reasons)
            count, oldest = count + 1, row["ts"]
    truncated = count >= MATRIX_MAX_REPORTS
    reply = {"columns": columns, "matrix": matrix, "sites": sites_matrix, "unchecked": unchecked,
             "reasons": {node: {column: reason for column, reason in cells.items() if reason}
                         for node, cells in reasons.items() if any(cells.values())},
             "since": oldest if truncated and oldest is not None else since, "truncated": truncated,
             "new_agents": new_agents(now)}
    with _matrix_lock:
        _matrix_cache[key] = (now, reply)
        while len(_matrix_cache) > MATRIX_CACHE_KEEP:
            _matrix_cache.popitem(last=False)
    return reply


def _matrix_add(row, matrix, sites_matrix, columns, unchecked=None, reasons=None):
    """Отложенный отчёт старше DEFERRED_FRESH (как в трендах) и отчёт без места (квота ipinfo, отчёт в обход
    проверяемой сети) - не в матрицу: иначе старые замеры и колонки «? · оператор»."""
    data = loads_stored(row["payload"], {})
    if not isinstance(data, dict) or _int(data.get("deferred_s")) > DEFERRED_FRESH:
        return
    if not (row["region"] or row["city"]):
        return
    region = canonical_region(row["region"] or "")
    column = "%s · %s" % (region or row["city"] or "?", row["operator"] or row["network"] or "?")
    columns.setdefault(column, {"region": region, "operator": row["operator"], "reports": 0})
    columns[column]["reports"] += 1
    for target, items in ((matrix, data.get("results")), (sites_matrix, data.get("sites"))):
        if not isinstance(items, dict):
            continue
        for key, value in items.items():
            if not isinstance(value, dict) or (row["partial"] and not value.get("ok")):
                continue
            cell = target.setdefault(key, {}).setdefault(column, [0, 0])
            if reasons is not None and target is matrix:
                reasons.setdefault(key, {}).setdefault(column, value.get("error") if value.get("error") in
                                                       DEAD_REASONS else "")
            cell[1] += 1
            if value.get("ok"):
                cell[0] += 1
    reasons = data.get("unchecked_nodes")
    if unchecked is None or not isinstance(reasons, dict):
        return
    for key, reason in reasons.items():
        unchecked.setdefault(key, {}).setdefault(column, reason)


@app.get("/v1/admin/state", dependencies=[Depends(require_admin)])
def admin_state():
    return load_state()


EXTRA_PROTOCOLS = frozenset({"vless", "vmess", "trojan", "shadowsocks", "hysteria", "hysteria2", "freedom"})
EXTRA_RESERVED_TAGS = frozenset({"vc-direct", "vc-block"})
MAX_EXTRA_OUTBOUNDS = 8


def linked_tags(outbound) -> list:
    """Теги outbound'ов, через которые этот ходит: sockopt.dialerProxy и proxySettings.tag."""
    stream = outbound.get("streamSettings") if isinstance(outbound, dict) else None
    sockopt = stream.get("sockopt") if isinstance(stream, dict) else None
    proxy = outbound.get("proxySettings") if isinstance(outbound, dict) else None
    tags = [sockopt.get("dialerProxy") if isinstance(sockopt, dict) else None,
            proxy.get("tag") if isinstance(proxy, dict) else None]
    return [tag for tag in tags if isinstance(tag, str) and tag]


def chain_ok(main, by_tag) -> bool:
    """Цепочка от главного outbound'а по ссылкам: каждое звено есть среди extra, ни одно не встречается дважды
    (кольцо x->y->x или ссылка на себя раздувает xray до сотен МБ, и телефон убивает приложение), лишних
    звеньев нет. Так же проверяют агент (XrayRunner.chainRefusal) и стенд (stand/core.py)."""
    seen = set()
    queue = deque(linked_tags(main))
    while queue:
        tag = queue.popleft()
        if tag not in by_tag or tag in seen:
            return False
        seen.add(tag)
        queue.extend(linked_tags(by_tag[tag]))
    return len(seen) == len(by_tag)


def valid_extra_outbounds(extra, outbound=None) -> bool:
    """Связанные outbound'ы узла (dialerProxy, proxySettings.tag): список до MAX_EXTRA_OUTBOUNDS объектов с
    непустым уникальным tag (не служебный агента и не тег главного outbound'а), протокол из EXTRA_PROTOCOLS,
    freedom - без redirect, цепочка от outbound'а без колец и лишних звеньев (chain_ok). Нет поля - годится, если
    сам outbound ни на что не ссылается."""
    main = outbound if isinstance(outbound, dict) else {}
    if extra is None:
        return chain_ok(main, {})
    if not isinstance(extra, list) or len(extra) > MAX_EXTRA_OUTBOUNDS:
        return False
    tags: dict[str, dict] = {}
    for item in extra:
        if not isinstance(item, dict):
            return False
        tag = item.get("tag")
        if not isinstance(tag, str) or not tag or tag in EXTRA_RESERVED_TAGS or tag in tags or tag == main.get("tag"):
            return False
        tags[tag] = item
        protocol = item.get("protocol")
        if not isinstance(protocol, str) or protocol.lower() not in EXTRA_PROTOCOLS:
            return False
        if _redirects(item):
            return False
    return chain_ok(main, tags)


NODE_PROTOCOLS = EXTRA_PROTOCOLS - {"freedom"}
XHTTP_KEYS = ("xhttpSettings", "splithttpSettings")
MAX_DOWNLOAD_DEPTH = 4
PRIVATE_NETS = [ipaddress.ip_network(cidr) for cidr in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
    "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/3", "::/128", "::1/128", "64:ff9b:1::/48", "fc00::/7", "fe80::/10",
    "ff00::/8")]
NAT64 = ipaddress.ip_network("64:ff9b::/96")
UNKNOWN_TO_CORE = frozenset({"hysteria2"})
XRAY_NAMES = ("address", "server", "port", "vnext", "servers", "settings", "streamSettings", "sockopt", "dialerProxy",
              "proxySettings", "tag", "xhttpSettings", "splithttpSettings", "extra", "downloadSettings", "redirect",
              "domainStrategy", "tlsSettings", "echConfigList", "protocol", "allowInsecure")
FOLDED_NAMES = {name.lower(): name for name in XRAY_NAMES}
MAX_KEY_DEPTH = 64
HEADERS_KEY = "headers"
FREEDOM_SETTINGS = frozenset({"domainstrategy", "fragment", "noises", "userlevel", "redirect"})
MUX_KEY = "mux"
MUX_ENABLED_KEY = "enabled"
PORT_STRATEGY_KEY = "addressportstrategy"
AGENT_SOCKOPT = frozenset({"interface", "mark", "customsockopt"})
NODE_FIELDS_FILES = (os.path.join(HERE, "node_fields.json"),
                     os.path.join(os.path.dirname(HERE), "stand", "node_fields.json"))
ENV_PREFIX = "env:"
EXTRA_SPACES = "\u1680\u2028\u2029\u202f\u205f\u3000\ufeff"


class DuplicateKeys(dict):
    """Объект JSON, в котором ключ повторялся: xray берёт последний, а проверки видели бы первый."""

    duplicate_keys = True


def json_pairs(pairs):
    data = dict(pairs)
    return DuplicateKeys(data) if len(data) < len(pairs) else data


def fold_key(key) -> str:
    """Имя поля так, как его сравнивает xray (Go encoding/json): без регистра, «ſ» - это s, знак кельвина - k."""
    return str(key).replace("\u017f", "s").replace("\u212a", "k").lower()


def load_node_fields(paths=NODE_FIELDS_FILES) -> dict:
    """Белый список полей узла (node_fields.json - тот же файл, что stand/node_fields.json; копия у агента в
    NodeFields.kt): {раздел: {имя поля без регистра: что внутри}}. Без файла сервер не запускается - иначе
    пропустил бы любые поля."""
    for path in paths:
        if os.path.exists(path):
            with open(path, encoding="utf-8") as handle:
                data = json.load(handle)
            return {context: {fold_key(name): spec for name, spec in fields.items()}
                    for context, fields in data.items()}
    raise RuntimeError("node_fields.json not found: %s" % ", ".join(paths))


NODE_FIELDS = load_node_fields()


def fields_refused(outbound) -> bool:
    """Поле не из белого списка (node_fields.json) или поле «только пустое» (sendThrough, sockopt.tproxy) задано:
    новое поле ядра может набирать свои адреса мимо проверок. "" - любое значение, "*" - любые ключи (заголовки),
    "@раздел" - вложенный объект, "!а,б" - только пусто или одно из значений. Как NodeRules.fieldsRefused."""
    protocol = outbound.get("protocol")
    return _fields_refused(outbound, "outbound", protocol.lower() if isinstance(protocol, str) else "")


def _fields_refused(value, context, protocol) -> bool:
    fields = NODE_FIELDS.get("settings." + protocol if context == "settings" else context)
    if isinstance(value, list):
        return any(_fields_refused(item, context, protocol) for item in value)
    if not isinstance(value, dict):
        return False
    if fields is None:
        return True
    for key, item in value.items():
        spec = fields.get(fold_key(key))
        if spec is None:
            return True
        if spec.startswith("!") and item and not (isinstance(item, str) and item.lower() in spec[1:].split(",")):
            return True
        if spec.startswith("@") and _fields_refused(item, spec[1:], protocol):
            return True
    return False


def keys_ambiguous(value, depth=0) -> bool:
    """В узле есть поле, которое xray прочтёт не так, как проверки: имя xray в другом регистре или через «ſ»/«K»,
    два ключа одного объекта, совпадающие для xray, повтор ключа в исходном JSON.
    То же правило у агента (NodeRules) и стенда (stand/core.py)."""
    if depth > MAX_KEY_DEPTH:
        return True
    if isinstance(value, list):
        return any(keys_ambiguous(item, depth + 1) for item in value)
    if not isinstance(value, dict):
        return False
    if getattr(value, "duplicate_keys", False):
        return True
    seen = set()
    for key, item in value.items():
        folded = fold_key(key)
        if folded in seen or FOLDED_NAMES.get(folded, key) != key:
            return True
        seen.add(folded)
        if folded != HEADERS_KEY and keys_ambiguous(item, depth + 1):
            return True
    return False


BASE64_RE = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")


def ech_refused(value, depth=0):
    """tlsSettings.echConfigList - только готовый конфиг в base64: «имя+сервер» или адрес сервера DNS - xray сам
    пойдёт за записью ECH на указанный сервер, в том числе в частную сеть. Как NodeRules.inlineEch у агента."""
    if depth > MAX_KEY_DEPTH:
        return True
    if isinstance(value, list):
        return any(ech_refused(item, depth + 1) for item in value)
    if not isinstance(value, dict):
        return False
    for key, item in value.items():
        if key == "echConfigList":
            if item is not None and not (isinstance(item, str) and len(item) % 4 == 0 and BASE64_RE.match(item)):
                return True
        elif ech_refused(item, depth + 1):
            return True
    return False


def insecure(value, depth=0):
    """allowInsecure где угодно в узле: xray 26 с ним не запускается (как NodeRules.insecure у агента)."""
    if depth > MAX_KEY_DEPTH:
        return True
    if isinstance(value, list):
        return any(insecure(item, depth + 1) for item in value)
    if not isinstance(value, dict):
        return False
    return any((key == "allowInsecure" and item is not False) or insecure(item, depth + 1)
               for key, item in value.items())


def is_private(address) -> bool:
    """Адрес не из интернета - те же сети, что у агента (SiteCheck/XrayRunner) и стенда (stand/core.py), в том
    числе IPv4 внутри IPv6 (::ffff:, NAT64 64:ff9b::/96, 6to4 2002::/16)."""
    if address.version == 6:
        inner = address.ipv4_mapped or address.sixtofour
        if inner is None and address in NAT64:
            inner = ipaddress.IPv4Address(int(address) & 0xFFFFFFFF)
        if inner is not None:
            return is_private(inner)
    return any(address in net for net in PRIVATE_NETS if net.version == address.version)


def odd_address(address) -> bool:
    """Адрес с пробельным или управляющим символом (Go TrimSpace срезает и U+0085, Kotlin trim - нет) или "env:ИМЯ"
    (xray возьмёт адрес из переменной окружения), зона IPv6 через "%". Как NodeRules.oddAddress и stand/core.py."""
    text = str(address or "")
    return text.lower().startswith(ENV_PREFIX) or any(
        char == "%" or ord(char) <= 0x20 or 0x7F <= ord(char) <= 0xA0 or 0x2000 <= ord(char) <= 0x200A
        or char in EXTRA_SPACES
        for char in text)


def address_refused(address) -> bool:
    if odd_address(address):
        return True
    host = str(address or "").strip().strip("[]").lower().rstrip(".")
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return is_private(ipaddress.ip_address(host))
    except ValueError:
        return False


def download_settings(outbound, limit=MAX_DOWNLOAD_DEPTH) -> list:
    """Каналы загрузки xhttp: downloadSettings прямо в xhttpSettings/splithttpSettings или в их extra, и
    вложенные в них (до limit уровней) - у каждого свой адрес и свой sockopt.dialerProxy."""
    found: list = []
    pending = [(outbound.get("streamSettings") if isinstance(outbound, dict) else None, 0)]
    while pending:
        stream, depth = pending.pop()
        if not isinstance(stream, dict) or depth >= limit:
            continue
        for name in XHTTP_KEYS:
            xhttp = stream.get(name)
            if not isinstance(xhttp, dict):
                continue
            extra = xhttp.get("extra")
            for holder in (xhttp, extra) if isinstance(extra, dict) else (xhttp,):
                download = holder.get("downloadSettings")
                if isinstance(download, dict):
                    found.append(download)
                    pending.append((download, depth + 1))
    return found


def addresses_of(outbound) -> list:
    settings = outbound.get("settings") if isinstance(outbound, dict) else None
    found = []
    if isinstance(settings, dict):
        found += [settings[field] for field in ("address", "server") if isinstance(settings.get(field), str)]
        for name in ("vnext", "servers"):
            items = settings.get(name)
            found += [item["address"] for item in (items if isinstance(items, list) else [])
                      if isinstance(item, dict) and isinstance(item.get("address"), str)]
    found += [item["address"] for item in download_settings(outbound) if isinstance(item.get("address"), str)]
    return [address for address in found if address]


def _address_refusal(outbound, allowed) -> bool:
    protocol = outbound.get("protocol")
    if not isinstance(protocol, str) or protocol.lower() not in allowed:
        return True
    return any(address_refused(address) for address in addresses_of(outbound))


def _download_chained(download) -> bool:
    sockopt = download.get("sockopt")
    return (isinstance(sockopt, dict) and bool(sockopt.get("dialerProxy"))) or bool(download.get("proxySettings"))


def node_refusal(node) -> str:
    """Почему агент не станет проверять узел (то же правило и тот же порядок у агента - NodeRules.refusal - и
    стенда - stand/core.py node_refusal; общие случаи - tests/data/chain_cases.json): "unsupported" - ключи,
    которые xray прочтёт иначе (keys_ambiguous), цепочка не собирается, канал загрузки (downloadSettings) ходит
    через другой outbound или вложен глубже MAX_DOWNLOAD_DEPTH, протокол, которого нет в ядре, allowInsecure,
    поле не из белого списка node_fields.json (fields_refused); "rejected" - протокол не тот, адрес не из
    интернета (и у звена цепочки, и у канала загрузки xhttp), с пробельным символом или "env:", freedom с
    redirect, echConfigList не готовым конфигом. "" - годится. Узел без outbound (старые state) - не
    проверяется."""
    outbound = node.get("outbound") if isinstance(node, dict) else None
    if not isinstance(outbound, dict):
        return ""
    extras = node.get("extra_outbounds")
    if keys_ambiguous([outbound, extras]):
        return "unsupported"
    if _address_refusal(outbound, NODE_PROTOCOLS):
        return "rejected"
    extras = [] if extras is None else extras
    if (not isinstance(extras, list) or not all(isinstance(item, dict) for item in extras)
            or len(extras) > MAX_EXTRA_OUTBOUNDS):
        return "unsupported"
    tags: dict[str, dict] = {}
    for item in extras:
        tag = item.get("tag")
        if not isinstance(tag, str) or not tag or tag in EXTRA_RESERVED_TAGS or tag in tags:
            return "unsupported"
        tags[tag] = item
        if _address_refusal(item, EXTRA_PROTOCOLS) or _redirects(item):
            return "rejected"
        if _freedom_extras(item) or _muxed(item):
            return "unsupported"
    main_tag = outbound.get("tag")
    if main_tag is not None and not isinstance(main_tag, str):
        return "unsupported"
    if main_tag in EXTRA_RESERVED_TAGS or main_tag in tags:
        return "unsupported"
    items = [outbound] + extras
    if any(ech_refused(item) for item in items):
        return "rejected"
    if any(map(fields_refused, items)):
        return "unsupported"
    if any(len(download_settings(item, MAX_DOWNLOAD_DEPTH + 1)) > len(download_settings(item)) for item in items):
        return "unsupported"
    if any(str(item.get("protocol")).lower() in UNKNOWN_TO_CORE for item in items) or any(map(insecure, items)):
        return "unsupported"
    if any(map(_port_strategy, items)):
        return "unsupported"
    if any(map(_agent_sockopt, items)):
        return "unsupported"
    if any(_download_chained(download) for item in items for download in download_settings(item)):
        return "unsupported"
    return "" if chain_ok(outbound, tags) else "unsupported"


def _redirects(outbound) -> bool:
    settings = outbound.get("settings")
    return (str(outbound.get("protocol")).lower() == "freedom" and isinstance(settings, dict)
            and bool(settings.get("redirect")))


def _freedom_extras(outbound) -> bool:
    """freedom-звено с настройками не из FREEDOM_SETTINGS (finalRules, ipsBlocked...): свои правила по IP заставят
    freedom резолвить имя цели мимо закрепления. Как NodeRules.freedomExtras у агента."""
    settings = outbound.get("settings")
    if str(outbound.get("protocol")).lower() != "freedom" or not isinstance(settings, dict):
        return False
    return any(fold_key(key) not in FREEDOM_SETTINGS for key in settings)


def _muxed(outbound) -> bool:
    return any(fold_key(key) == MUX_KEY and isinstance(mux, dict)
               and any(fold_key(name) == MUX_ENABLED_KEY and bool(value) for name, value in mux.items())
               for key, mux in outbound.items())


def _own_sockopts(outbound) -> list:
    stream = outbound.get("streamSettings")
    holders = ([stream] if isinstance(stream, dict) else []) + download_settings(outbound)
    return [holder["sockopt"] for holder in holders if isinstance(holder.get("sockopt"), dict)]


def _port_strategy(outbound) -> bool:
    """sockopt.addressPortStrategy не none (у outbound'а и каналов загрузки): xray спросит SRV/TXT имени узла
    мимо закрепления и подменит адрес ответом. Как NodeRules.portStrategy у агента."""
    return any(fold_key(key) == PORT_STRATEGY_KEY and value is not None
               and not (isinstance(value, str) and value.lower() == "none")
               for sockopt in _own_sockopts(outbound) for key, value in sockopt.items())


def _agent_sockopt(outbound) -> bool:
    """sockopt interface, mark или customSockopt не пусты (у outbound'а и каналов загрузки): привязку к проверяемой
    сети ставит агент, узел перебил бы её (SO_BINDTODEVICE, SO_MARK) и увёл набор в Wi-Fi. Как
    NodeRules.agentSockopt."""
    return any(fold_key(key) in AGENT_SOCKOPT and bool(value)
               for sockopt in _own_sockopts(outbound) for key, value in sockopt.items())


@app.post("/v1/admin/state", dependencies=[Depends(require_admin)])
async def admin_set_state(request: Request):
    """Частичное обновление: nodes, interval_min, test_url, manifest, message."""
    try:
        patch = loads_admin(await request.body())
    except (ValueError, RecursionError):
        raise HTTPException(status_code=400, detail=t("не JSON")) from None
    if not isinstance(patch, dict):
        raise HTTPException(status_code=400, detail=t("не объект"))
    if "interval_min" in patch:
        patch["interval_min"] = max(15, min(1440, _int(patch["interval_min"]) or DEFAULT_STATE["interval_min"]))
    for key in ("test_url", "latency_url"):
        if key in patch and not str(patch[key]).startswith("https://"):
            raise HTTPException(status_code=400, detail=t("%s: только https") % key)
    if "location_round" in patch and not valid_location_round(patch["location_round"]):
        raise HTTPException(status_code=400, detail=t("location_round: число от %d до %d")
                            % (LOCATION_ROUND_MIN, LOCATION_ROUND_MAX))
    if "message" in patch:
        patch["message"] = clip(patch["message"], 300)
    if "nodes" in patch and (not isinstance(patch["nodes"], list) or len(patch["nodes"]) > 300):
        raise HTTPException(status_code=400, detail=t("nodes: список до 300"))
    for node in patch.get("nodes") or []:
        if not isinstance(node, dict) or not valid_extra_outbounds(node.get("extra_outbounds"), node.get("outbound")):
            raise HTTPException(status_code=400, detail=t("nodes: неверные extra_outbounds у узла %s")
                                % clip(node.get("key") if isinstance(node, dict) else node, 80))
        refusal = node_refusal(node)
        if refusal:
            raise HTTPException(status_code=400, detail=t("nodes: узел %s отклонён (%s)") % (clip(node.get("key"), 80),
                                                                                              refusal))
    if "nodes_expire" in patch:
        try:
            patch["nodes_expire"] = float(patch["nodes_expire"] or 0)
        except (TypeError, ValueError):
            patch["nodes_expire"] = 0
    if "nodes_user" in patch:
        patch["nodes_user"] = clip(patch["nodes_user"], 64)
    if "yandex_key" in patch:
        patch["yandex_key"] = re.sub(r"[^A-Za-z0-9-]", "", clip(patch["yandex_key"], 64))
    if "sites" in patch:
        sites = patch["sites"] if isinstance(patch["sites"], list) else []
        clean = []
        for item in sites[:MAX_SITES]:
            url = clip(item.get("url") if isinstance(item, dict) else item, 200).strip()
            if not url.startswith(("http://", "https://")):
                continue
            name = clip(item.get("name") if isinstance(item, dict) else "", 60) or url.split("//", 1)[1].split("/")[0]
            clean.append({"url": url, "name": name})
        patch["sites"] = clean
    state = update_state({key: patch[key] for key in DEFAULT_STATE if key in patch})
    return {"ok": True, "nodes": len(state["nodes"])}


@app.post("/v1/admin/upload", dependencies=[Depends(require_admin)])
async def admin_upload(file: UploadFile):
    name = os.path.basename(file.filename or "")
    if not name or name.startswith(".") or not re.match(r"^[A-Za-z0-9._-]{1,80}$", name):
        raise HTTPException(status_code=400, detail=t("имя файла: только буквы, цифры, точка, дефис"))
    path = os.path.join(FILES_DIR, name)
    tmp = path + ".part"
    size = 0
    with open(tmp, "wb") as handle:
        while True:
            chunk = await file.read(1 << 20)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_UPLOAD_BYTES:
                handle.close()
                os.remove(tmp)
                raise HTTPException(status_code=413, detail=t("файл больше %d МБ") % (MAX_UPLOAD_BYTES >> 20))
            handle.write(chunk)
    os.replace(tmp, path)
    return {"ok": True, "name": name, "size": size}


@app.post("/v1/admin/agents/{agent_id}/note", dependencies=[Depends(require_admin)])
async def admin_note(agent_id: str, request: Request):
    body = await _json_body(request)
    note = clip(body.get("note", "") if isinstance(body, dict) else "", 200)
    await asyncio.to_thread(_store_note, agent_id, note)
    return {"ok": True}


def _store_note(agent_id, note):
    with db() as conn:
        conn.execute("UPDATE agents SET note=? WHERE agent_id=?", (note, agent_id))


@app.get("/agent.apk", dependencies=[Depends(require_public)])
def latest_apk():
    """Постоянная ссылка на актуальный APK: берётся из подписанного манифеста."""
    manifest = load_state().get("manifest") or {}
    url = ((manifest.get("app") or {}).get("url") or "").rsplit("/", 1)[-1]
    path = os.path.join(FILES_DIR, url) if url else ""
    if not url or not os.path.exists(path):
        raise HTTPException(status_code=404, detail=t("APK ещё не выложен"))
    return FileResponse(path, media_type="application/vnd.android.package-archive", filename="vpncheck-agent.apk")


YANDEX = ("https://api-maps.yandex.ru https://suggest-maps.yandex.ru https://*.maps.yandex.net https://yandex.ru "
          "https://yastatic.net")
ADMIN_CSP = ("default-src 'self'; script-src 'self' %s; connect-src 'self' %s; img-src 'self' data: blob: %s; "
             "style-src 'self' 'unsafe-inline' blob: https://yastatic.net; font-src 'self' data: https://yastatic.net; "
             "frame-src https://api-maps.yandex.ru; worker-src 'self' blob:; object-src 'none'; base-uri 'none'; "
             "form-action 'self'; frame-ancestors 'none'" % (YANDEX, YANDEX, YANDEX))
ADMIN_HEADERS = {"Content-Security-Policy": ADMIN_CSP, "X-Content-Type-Options": "nosniff",
                 "Referrer-Policy": "no-referrer"}
STATIC_HEADERS = {"X-Content-Type-Options": "nosniff"}
SHARED_ASSETS_DIR = os.path.join(os.path.dirname(HERE), "stand", "ui", "assets")
SHARED_ASSETS = {"ru_regions.geojson"}
FILE_HEADERS = {"X-Content-Type-Options": "nosniff", "Content-Security-Policy": "sandbox; default-src 'none'"}


@app.get("/")
def root_page():
    return RedirectResponse("/admin", status_code=302)


@app.get("/admin")
def admin_page():
    """Мобильный центр управления: страница публичная, данные - только по токену."""
    path = os.path.join(STATIC_DIR, "admin.html")
    if not os.path.exists(path):
        raise HTTPException(status_code=404)
    return FileResponse(path, media_type="text/html", headers=ADMIN_HEADERS)


@app.get("/static/{name}", dependencies=[Depends(require_public)])
def static_file(name: str):
    """Файлы админки. .html - с теми же заголовками (CSP), что и /admin. Границы регионов при запуске
    из репозитория лежат в ../stand/ui/assets."""
    if not re.match(r"^[A-Za-z0-9._-]{1,80}$", name) or name.startswith("."):
        raise HTTPException(status_code=404)
    path = os.path.join(STATIC_DIR, name)
    if not os.path.exists(path) and name in SHARED_ASSETS:
        path = os.path.join(SHARED_ASSETS_DIR, name)
    if not os.path.exists(path):
        raise HTTPException(status_code=404)
    return FileResponse(path, headers=ADMIN_HEADERS if name.lower().endswith((".html", ".htm")) else STATIC_HEADERS)


@app.get("/whoami")
def whoami(request: Request):
    """Каким IP до нас дошёл запрос. Сервер в Москве (RU) - если через полный конфиг сюда пришёл
    реальный IP телефона, значит РФ идёт напрямую; если IP узла - российский трафик утёк в VPN."""
    return PlainTextResponse(client_ip(request))


HEALTH_TTL = 30.0
_health = {"ts": 0.0, "agents": 0}


@app.get("/health")
def health():
    """Жив ли сервис; число агентов пересчитывается не чаще раза в HEALTH_TTL (COUNT(*) по всей таблице).
    tls - поднят ли TLS-порт (run.py), без отпечатка."""
    now = time.time()
    if now - _health["ts"] >= HEALTH_TTL:
        with db() as conn:
            _health["agents"] = conn.execute("SELECT COUNT(*) FROM agents").fetchone()[0]
        _health["ts"] = now
    return JSONResponse({"ok": True, "agents": _health["agents"], "time": int(now), "tls": bool(TLS_STATE["on"])})
