"""IP и хостер узла: имя → адрес через DNS, адрес → провайдер через ipinfo.io. Всё кэшируется."""
import ipaddress
import json
import os
import socket
import threading
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from .storage import APP_DIR

CACHE_PATH = os.path.join(APP_DIR, "geo_cache.json")
_cache = None
_lock = threading.RLock()
_doh_down = threading.Event()
DOH_URLS = ("https://1.1.1.1/dns-query?name=%s&type=A", "https://8.8.8.8/resolve?name=%s&type=A")
FAKE_NETS = tuple(ipaddress.ip_network(net) for net in ("198.18.0.0/15", "198.20.0.0/16", "0.0.0.0/8", "127.0.0.0/8",
                                                      "100.64.0.0/10"))


def _load():
    global _cache
    with _lock:
        if _cache is not None:
            return _cache
        _cache = {}
        if os.path.exists(CACHE_PATH):
            try:
                with open(CACHE_PATH, encoding="utf-8") as handle:
                    _cache = json.load(handle)
            except (ValueError, OSError):
                _cache = {}
        return _cache


def _save():
    """Кэш пишется целиком под локом во временный файл и подменяется разом: lookup_many зовут
    из нескольких мест одновременно, а полузаписанный файл потерял бы весь кэш."""
    with _lock:
        snapshot = json.dumps(_load(), ensure_ascii=False, indent=0)
        try:
            os.makedirs(APP_DIR, exist_ok=True)
            tmp = "%s.%d.%d.tmp" % (CACHE_PATH, os.getpid(), threading.get_ident())
            with open(tmp, "w", encoding="utf-8") as handle:
                handle.write(snapshot)
            os.replace(tmp, CACHE_PATH)
        except OSError:
            pass


def cached(host):
    """Что уже известно об узле из кэша (без сети): {"ip", "org", "country", ...} или {}."""
    with _lock:
        entry = dict(_load().get(host) or {})
    return {} if entry.get("ip") and fake(entry["ip"]) else entry


def fake(ip):
    """Адрес подмены DNS (fake-ip у Clash - 198.18.0.0/15, у Karing - 198.20.0.0/16) или заведомо не адрес узла."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return address.version == 4 and any(address in net for net in FAKE_NETS)


def resolve_doh(host, timeout=6):
    """Адрес через DoH или "". Не ответил ни один DoH - до конца сессии не пробуем: иначе каждый узел ждал бы
    2×timeout, а имя всё равно разрешит системный DNS."""
    if _doh_down.is_set():
        return ""
    reached = False
    for template in DOH_URLS:
        try:
            request = urllib.request.Request(template % urllib.parse.quote(host),
                                             headers={"Accept": "application/dns-json", "User-Agent": "curl/8"})
            with urllib.request.urlopen(request, timeout=timeout) as response:
                data = json.load(response)
        except Exception:  # noqa: BLE001
            continue
        reached = True
        for answer in data.get("Answer") or []:
            ip = str(answer.get("data") or "")
            if answer.get("type") == 1 and not fake(ip):
                return ip
    if not reached:
        _doh_down.set()
    return ""


def resolve(host):
    """Имя -> адрес. Сначала DoH: системный DNS на компьютере с Karing/Clash в режиме fake-ip отдаёт
    служебные 198.18.0.0/15 или 198.20.0.0/16, по ним ipinfo называет чужого провайдера."""
    try:
        socket.inet_aton(host)
        return host
    except OSError:
        pass
    ip = resolve_doh(host)
    if ip:
        return ip
    try:
        ip = socket.gethostbyname(host)
    except OSError:
        return ""
    return "" if fake(ip) else ip


def hoster(ip, timeout=8):
    """Провайдер по ipinfo.io: «AS12345 Имя» → короткое имя без номера AS + страна."""
    if not ip:
        return {}
    try:
        request = urllib.request.Request("https://ipinfo.io/%s/json" % ip, headers={"User-Agent": "curl/8"})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.load(response)
    except Exception:  # noqa: BLE001 - нет сети/лимит: просто без хостера
        return {}
    org = data.get("org", "")
    name = org.split(" ", 1)[1] if org.startswith("AS") and " " in org else org
    return {"org": name, "asn": org.split(" ")[0] if org.startswith("AS") else "",
            "country": data.get("country", ""), "city": data.get("city", "")}


def lookup(host):
    with _lock:
        entry = _load().get(host)
    if entry and entry.get("org") and not fake(entry.get("ip", "")):
        return entry
    cached_ip = (entry or {}).get("ip", "")
    ip = cached_ip if cached_ip and not fake(cached_ip) else resolve(host)
    info = hoster(ip) if ip else {}
    entry = {"ip": ip, **info}
    with _lock:
        _load()[host] = entry
    return entry


def lookup_many(hosts, workers=8):
    hosts = list(dict.fromkeys(hosts))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(lookup, hosts))
    _save()
    return dict(zip(hosts, results, strict=True))
