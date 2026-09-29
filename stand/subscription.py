"""Откуда взять список узлов: панель Remnawave, ссылка на подписку, файл.

Подписка бывает трёх видов: JSON-массив конфигов Happ/xray (Remnawave), JSON одного конфига
и список vless://-ссылок (обычная выдача панели для клиентов). Всё приводится к одному виду:
[{"location", "key", "address", "port", "sni", "outbound"}] - outbound готов для xray.
"""
import base64
import contextlib
import copy
import json
import re
import threading
import urllib.parse
import urllib.request
from collections import OrderedDict

from .core import loads_json, main_outbounds, node_refusal, parse_subscription, skip_label
from .i18n import t
from .remnawave import SUB_HEADERS, Panel, PanelError


def vless_link_to_outbound(link):
    """vless://uuid@host:port?query#remark → (remark, outbound dict) или None, если ссылка кривая."""
    if not link.startswith("vless://"):
        return None
    body = link[len("vless://"):]
    remark = ""
    if "#" in body:
        body, remark = body.split("#", 1)
        remark = urllib.parse.unquote(remark).strip()
    query = {}
    if "?" in body:
        body, raw_query = body.split("?", 1)
        query = {k: v[0] for k, v in urllib.parse.parse_qs(raw_query, keep_blank_values=True).items()}
    match = re.match(r"([^@]+)@(.+):(\d+)/?$", body)
    if not match:
        return None
    uuid, host, port = match.group(1), match.group(2).strip("[]"), int(match.group(3))
    network = query.get("type", "tcp") or "tcp"
    security = query.get("security", "none") or "none"
    user = {"id": uuid, "encryption": query.get("encryption", "none") or "none"}
    if query.get("flow"):
        user["flow"] = query["flow"]
    stream = {"network": network, "security": security}
    if security == "reality":
        stream["realitySettings"] = {
            "serverName": query.get("sni", ""), "publicKey": query.get("pbk", ""),
            "shortId": query.get("sid", ""), "fingerprint": query.get("fp", "chrome"),
            "spiderX": query.get("spx", "/")}
    elif security == "tls":
        stream["tlsSettings"] = tls_settings(query, host)
    stream.update(transport_settings(network, query))
    if network == "tcp" and query.get("headerType") == "http":
        stream["tcpSettings"] = {"header": {"type": "http", "request": {
            "path": [query.get("path", "/")], "headers": {"Host": [query.get("host", "")]}}}}
    outbound = {"protocol": "vless", "tag": "proxy",
                "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
                "streamSettings": stream}
    return remark or "%s:%d" % (host, port), outbound


def tls_settings(query, host):
    """TLS из ссылки. allowInsecure xray 26 не принимает (не запускается) - вместо него закрепление сертификата
    pcs (pinnedPeerCertSha256) и проверка по имени vcn (verifyPeerCertByName), если они есть в ссылке."""
    tls = {"serverName": query.get("sni", host), "fingerprint": query.get("fp", "chrome")}
    if query.get("alpn"):
        tls["alpn"] = query["alpn"].split(",")
    if query.get("pcs"):
        tls["pinnedPeerCertSha256"] = query["pcs"]
    if query.get("vcn"):
        tls["verifyPeerCertByName"] = query["vcn"]
    return tls


def transport_settings(network, query):
    """Настройки транспорта из ссылки: ws и httpupgrade (host - полем, а не заголовком: заголовок Host xray 26
    считает устаревшим), xhttp с extra, grpc с authority и mode=multi."""
    path, host = query.get("path", "/"), query.get("host", "")
    if network == "ws":
        return {"wsSettings": {"path": path, "host": host} if host else {"path": path}}
    if network == "httpupgrade":
        return {"httpupgradeSettings": {"path": path, "host": host} if host else {"path": path}}
    if network in ("xhttp", "splithttp"):
        xhttp = {"path": path, "host": host, "mode": query.get("mode", "auto") or "auto"}
        try:
            extra = loads_json(query["extra"]) if query.get("extra") else None
        except ValueError:
            extra = None
        if isinstance(extra, dict):
            xhttp["extra"] = extra
        return {"network": "xhttp", "xhttpSettings": xhttp}
    if network == "grpc":
        grpc = {"serviceName": query.get("serviceName", "")}
        if query.get("authority"):
            grpc["authority"] = query["authority"]
        if query.get("mode") == "multi":
            grpc["multiMode"] = True
        return {"grpcSettings": grpc}
    return {}


LINK_SCHEMES = ("vmess", "trojan", "ss", "ssr", "hysteria", "hysteria2", "hy2", "tuic", "wireguard", "socks", "http")


def _int(value, default):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def vmess_info(link):
    """vmess://base64(JSON) → словарь (add, port, ps) или {}."""
    body = link.split("://", 1)[1].split("#", 1)[0].strip()
    try:
        data = json.loads(base64.b64decode(body + "=" * (-len(body) % 4)).decode("utf-8", errors="replace"))
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def unsupported_links(text):
    """Узлы-ссылки, которые стенд не разбирает (vmess://, trojan://, ss://, hysteria2:// и прочие) - чтобы
    сказать «не проверено», а не выкинуть молча."""
    out = []
    for line in maybe_base64(text).splitlines():
        line = line.strip()
        scheme = line.split("://", 1)[0].lower() if "://" in line else ""
        parsed = vless_link_to_outbound(line) if scheme == "vless" else None
        refusal = node_refusal({"outbound": parsed[1]}) if parsed else ""
        if scheme not in LINK_SCHEMES and not (scheme == "vless" and (parsed is None or refusal)):
            continue
        if refusal:
            scheme = skip_label(parsed[1], [], refusal)
        remark = urllib.parse.unquote(line.split("#", 1)[1]).strip() if "#" in line else ""
        server = re.match(r"[^@/?#]*@\[?([^\]/?#]+?)\]?:(\d+)", line.split("://", 1)[1])
        address, port = (server.group(1), int(server.group(2))) if server else ("?", 443)
        if scheme == "vmess" and not server:
            info = vmess_info(line)
            remark, address, port = info.get("ps") or remark, info.get("add") or "?", _int(info.get("port"), 443)
        out.append({"location": remark or "?", "protocol": scheme, "address": address, "port": port})
    return out


def links_to_entries(text):
    entries = []
    for line in text.splitlines():
        line = line.strip()
        parsed = vless_link_to_outbound(line)
        if parsed:
            remark, outbound = parsed
            entries.append({"remarks": remark, "outbounds": [outbound]})
    return entries


def maybe_base64(text):
    stripped = "".join(text.split())
    if "://" in text or stripped.startswith("[") or stripped.startswith("{"):
        return text
    try:
        padded = stripped + "=" * (-len(stripped) % 4)
        return base64.b64decode(padded).decode("utf-8", errors="replace")
    except Exception:
        return text


def dedupe_keys(targets):
    """Один IP:порт с разными SNI (тестовые матрицы) - разные узлы; ключ дополняем SNI, иначе строки склеятся.
    Полные дубли (тот же SNI и та же локация) получают ещё и порядковый номер."""
    seen = {}
    for node in targets:
        seen.setdefault(node["key"], []).append(node)
    for key, group in seen.items():
        if len(group) > 1:
            snis = {node.get("sni") for node in group}
            for node in group:
                tail = node.get("sni") if len(snis) == len(group) else node["location"]
                node["key"] = "%s · %s" % (key, tail or node["location"])
    counts = {}
    for node in targets:
        counts[node["key"]] = counts.get(node["key"], 0) + 1
    taken = set(counts)
    numbers = {}
    for node in targets:
        key = node["key"]
        if counts[key] < 2:
            continue
        numbers[key] = numbers.get(key, 0) + 1
        if numbers[key] == 1:
            continue
        number = numbers[key]
        while "%s · %d" % (key, number) in taken:
            number += 1
        numbers[key] = number
        node["key"] = "%s · %d" % (key, number)
        taken.add(node["key"])
    return targets


def parse_any(raw, only_443=True, location_filter=None):
    """JSON-подписка (Happ) или vless-ссылки (в base64 или как есть) → список узлов."""
    text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
    text = text.strip()
    if not text:
        return []
    if text.startswith("[") or text.startswith("{"):
        data = loads_json(text)
        if isinstance(data, dict):
            data = data.get("outbounds") and [data] or data.get("subscription") or []
        return dedupe_keys(parse_subscription(data, only_443=only_443, location_filter=location_filter))
    decoded = maybe_base64(text)
    entries = links_to_entries(decoded)
    return dedupe_keys(parse_subscription(entries, only_443=only_443, location_filter=location_filter))


def unsupported(raw):
    """Узлы, которые стенд не проверит (не VLESS, ссылки vmess/trojan/ss/hysteria, цепочка dialerProxy, которую
    не собрать) - чтобы честно сказать «не проверено», а не выкинуть молча."""
    text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
    text = (text or "").strip()
    if not text.startswith("["):
        return unsupported_links(text) if text else []
    try:
        data = loads_json(text)
    except ValueError:
        return []
    out = []
    if not isinstance(data, list):
        return out
    with contextlib.suppress(AttributeError, TypeError, ValueError):
        parse_subscription(data, only_443=False, skipped=out)
    for entry in data:
        if not isinstance(entry, dict) or not isinstance(entry.get("outbounds"), list):
            continue
        for outbound in entry["outbounds"]:
            if not isinstance(outbound, dict):
                continue
            protocol = outbound.get("protocol")
            if outbound.get("tag") != "proxy" or str(protocol).lower() == "vless":
                continue
            settings = outbound.get("settings") or {}
            out.append({"location": entry.get("remarks") or "?", "protocol": protocol,
                        "address": settings.get("address") or settings.get("server") or "?",
                        "port": settings.get("port") or 443})
    return out


RU_MARKERS = ("geoip:ru", "geosite:ru", "geosite:category-ru", "ru.dat", "regexp:.*\\.ru",
              "gosuslugi", "sberbank", "nalog.ru", "domain:ru")


def config_ru_direct(entry):
    """По одному конфигу: идут ли РФ-сайты напрямую (в direct-правилах есть российский whitelist)."""
    routing = entry.get("routing")
    rules = (routing.get("rules") or []) if isinstance(routing, dict) else []
    direct = []
    for rule in rules if isinstance(rules, list) else []:
        if not isinstance(rule, dict) or rule.get("outboundTag") != "direct":
            continue
        for field in ("protocol", "domain", "ip", "network"):
            values = rule.get(field) or []
            direct += [str(v) for v in (values if isinstance(values, list) else [values])]
    blob = " ".join(direct).lower()
    return any(m in blob for m in RU_MARKERS), direct


def routing_summary(raw):
    """Идут ли РФ-сайты напрямую - ПО КАЖДОЙ ЛОКАЦИИ (в некоторых панелях split-tunnel настроен не на всех узлах).

    Возвращает {'has_routing','per_location','ru_ok','total','ru_direct','verdict'}. Где РФ не в direct -
    все российские сервисы видят IP узла и ругаются на VPN."""
    text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else (raw or "")
    text = text.strip()
    if not text.startswith("["):
        return {"has_routing": False, "per_location": [], "ru_ok": 0, "total": 0, "ru_direct": False,
                "verdict": t("подписка ссылками - правил маршрутизации в ней нет (routing на стороне клиента)")}
    try:
        data = json.loads(text)
    except ValueError:
        return {"has_routing": False, "per_location": [], "ru_ok": 0, "total": 0, "ru_direct": False,
                "verdict": t("не разобрать подписку")}
    per_location = []
    for entry in data if isinstance(data, list) else []:
        if not isinstance(entry, dict):
            continue
        ru_direct, _direct = config_ru_direct(entry)
        per_location.append({"location": entry.get("remarks") or "?", "ru_direct": ru_direct})
    ok = [row["location"] for row in per_location if row["ru_direct"]]
    bad = [row["location"] for row in per_location if not row["ru_direct"]]
    total = len(per_location)
    if not total:
        verdict = t("узлов в подписке нет")
    elif not bad:
        verdict = t("РФ идёт напрямую на всех локациях (локаций: %d) - split-tunnel настроен везде") % total
    elif not ok:
        verdict = t("РФ нигде не выведена напрямую - весь российский трафик через VPN, VPN-детект на всех узлах")
    else:
        verdict = (t("РФ напрямую на %d из %d: %s. На остальных всё через VPN (там ловят VPN-детект): %s")
                   % (len(ok), total, ", ".join(ok), ", ".join(bad)))
    return {"has_routing": True, "per_location": per_location, "ru_ok": len(ok), "total": total,
            "ru_direct": bool(ok) and not bad, "verdict": verdict}


FULL_CONFIG_CACHE = 4
_full_config_index: "OrderedDict[bytes, dict]" = OrderedDict()
_full_config_lock = threading.Lock()


def _config_index(raw):
    """{(адрес, порт): конфиг} по подписке; разбор кэшируется - геомаршрут спрашивает по каждой локации."""
    key = raw if isinstance(raw, bytes) else (raw or "").encode("utf-8")
    with _full_config_lock:
        if key in _full_config_index:
            _full_config_index.move_to_end(key)
            return _full_config_index[key]
    text = key.decode("utf-8", errors="replace")
    index = None
    if text.strip().startswith("["):
        try:
            data = json.loads(text)
        except ValueError:
            data = None
        if isinstance(data, list):
            index = {}
            for entry in data:
                if not isinstance(entry, dict):
                    continue
                outbounds = entry.get("outbounds") if isinstance(entry.get("outbounds"), list) else []
                mains = main_outbounds(outbounds)
                for outbound in mains + [item for item in outbounds if isinstance(item, dict)
                                         and item.get("tag") == "proxy" and item not in mains]:
                    settings = outbound.get("settings", {}) or {}
                    first = (settings.get("vnext") or [settings])[0]
                    node_address = first.get("address") or (None if settings.get("vnext") else settings.get("server"))
                    index.setdefault((node_address, str(first.get("port") or 0)), entry)
    with _full_config_lock:
        _full_config_index[key] = index
        while len(_full_config_index) > FULL_CONFIG_CACHE:
            _full_config_index.popitem(last=False)
    return index


def full_config_for(raw, address, port):
    """Полный конфиг узла из подписки (с dns/routing), чтобы прогнать геомаршрут как у клиента.
    Ищем по адресу:порту в proxy-аутбаунде. Возвращает dict (копию) или None (если подписка ссылками)."""
    index = _config_index(raw)
    if not index:
        return None
    entry = index.get((address, str(port or 0)))
    return copy.deepcopy(entry) if entry is not None else None


def site_targets(sites):
    """Сайты из центра как псевдо-узлы: проверяются напрямую из сети телефона, без VPN."""
    targets = []
    for site in sites or []:
        url = site.get("url") if isinstance(site, dict) else str(site)
        if not url:
            continue
        host = url.split("//", 1)[-1].split("/")[0]
        name = (site.get("name") if isinstance(site, dict) else "") or host
        targets.append({"location": t("🌐 Сайт без VPN"), "address": host, "port": 443, "key": "🌐 " + name,
                        "sni": host, "outbound": None, "site_url": url})
    return targets


LAST_RAW = b""
LAST_AGENT_USER = None


class Release:
    """Что вернуть после прогона (удалить временного пользователя) плюс сырая подписка этого прогона.

    raw едет вместе с узлами: общий LAST_RAW перезаписывает любая другая загрузка, а геомаршрут
    должен брать полный конфиг именно той подписки, которую проверяет. agent_user - учётка агентов
    (username, uuid, expire), созданная именно этой загрузкой; None, если загрузка не для агентов."""

    def __init__(self, raw=b"", action=None, agent_user=None):
        self.raw = raw
        self._action = action
        self.agent_user = agent_user

    def __call__(self):
        if self._action:
            self._action()


def from_url(url, only_443=True, timeout=30):
    global LAST_RAW
    request = urllib.request.Request(url, headers=dict(SUB_HEADERS))
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read()
    LAST_RAW = raw
    targets = parse_any(raw, only_443=only_443)
    return targets, Release(raw)


def from_file(path, only_443=True):
    global LAST_RAW
    with open(path, "rb") as handle:
        raw = handle.read()
    LAST_RAW = raw
    return parse_any(raw, only_443=only_443), Release(raw)


def list_squads(panel_config):
    """Имена сквадов панели - для выпадающего списка в окне."""
    return sorted(squad["name"] for squad in Panel.from_config(panel_config).squads())


def from_panel(panel_config, squad, only_443=True, limit=None):
    """Временный пользователь в скваде → его подписка → узлы.

    Возвращает (узлы, release). Пользователя надо удалить ПОСЛЕ проверки: узлы пускают только
    существующий ключ, поэтому удаление - в release(). Если release() не позовут (программу
    закрыли на середине), пользователь истечёт сам через сутки.

    limit=(мегабайт, дней) - учётка с лимитом для агентов волонтёров: её ключ уезжает на чужие
    телефоны, поэтому она ограничена по трафику и сроку, а release() её не удаляет и LAST_RAW
    (подписку прогона в окне) не трогает. Сырая подписка - в release.raw, учётка - в release.agent_user
    (LAST_AGENT_USER - только для старых вызовов: при двух выкладках подряд он указывает на последнюю).
    Не вышло получить узлы - созданная учётка удаляется сразу.
    """
    global LAST_AGENT_USER, LAST_RAW
    panel = Panel.from_config(panel_config)
    agent_user = None
    if limit:
        user = panel.create_user(squad, days=limit[1], traffic_mb=limit[0], prefix="vpnagent")
        agent_user = {"username": user["username"], "uuid": user["uuid"], "expire": user["expire"]}
    else:
        user = panel.create_user(squad)

    def delete():
        if not limit:
            panel.delete_user(user["uuid"])

    release = Release(action=delete, agent_user=agent_user)
    try:
        raw = release.raw = panel.fetch_subscription(user)
        if not limit:
            LAST_RAW = raw
        targets = parse_any(raw, only_443=only_443)
        if not targets:
            raise ValueError(t("подписка пуста: %s") % raw[:200])
    except BaseException:
        try:
            panel.delete_user(user["uuid"])
        except PanelError:
            pass
        raise
    if agent_user:
        LAST_AGENT_USER = agent_user
    return targets, release
