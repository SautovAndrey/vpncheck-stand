import copy
import ipaddress
import json
import math
import os
import re

from .i18n import t

PORTS_STANDARD = 443
MAX_EXTRA_OUTBOUNDS = 8
NODE_PROTOCOLS = frozenset({"vless", "vmess", "trojan", "shadowsocks", "hysteria", "hysteria2"})
EXTRA_PROTOCOLS = NODE_PROTOCOLS | {"freedom"}
EXTRA_RESERVED_TAGS = frozenset({"vc-direct", "vc-block", "direct"})
AGENT_TAGS = frozenset({"vc-direct", "vc-block"})
XHTTP_KEYS = ("xhttpSettings", "splithttpSettings")
MAX_DOWNLOAD_DEPTH = 4
PRIVATE_V4 = ("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
              "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/3")
PRIVATE_V6 = ("::/128", "::1/128", "64:ff9b:1::/48", "fc00::/7", "fe80::/10", "ff00::/8")
PRIVATE_NETS = [ipaddress.ip_network(cidr) for cidr in PRIVATE_V4 + PRIVATE_V6]
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
NODE_FIELDS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "node_fields.json")
ENV_PREFIX = "env:"
EXTRA_SPACES = "\u1680\u2028\u2029\u202f\u205f\u3000\ufeff"


class DuplicateKeys(dict):
    """Объект JSON, в котором ключ повторялся: xray берёт последний, а проверки видели бы первый."""

    duplicate_keys = True


def json_pairs(pairs):
    data = dict(pairs)
    return DuplicateKeys(data) if len(data) < len(pairs) else data


def _reject_constant(name):
    raise ValueError("JSON constant %s" % name)


def _finite_float(text):
    value = float(text)
    if not math.isfinite(value):
        raise ValueError("JSON number out of range")
    return value


def loads_json(text):
    """JSON подписки и узлов: повтор ключа в объекте запоминается (DuplicateKeys) - такой узел не проверяем;
    NaN, Infinity и числа за пределами float - ValueError: сервер агентов такие узлы не примет."""
    return json.loads(text, object_pairs_hook=json_pairs, parse_constant=_reject_constant, parse_float=_finite_float)


def tag_of(outbound):
    """tag outbound'а строкой; не строка - "" (как у агента)."""
    tag = outbound.get("tag") if isinstance(outbound, dict) else None
    return tag if isinstance(tag, str) else ""


def fold_key(key):
    """Имя поля так, как его сравнивает xray (Go encoding/json): без регистра, «ſ» - это s, знак кельвина - k."""
    return str(key).replace("\u017f", "s").replace("\u212a", "k").lower()


def load_node_fields(path=NODE_FIELDS_PATH):
    """Белый список полей узла (stand/node_fields.json - тот же файл у сервера агентов, копия у агента в
    NodeFields.kt): {раздел: {имя поля без регистра: что внутри}}."""
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    return {context: {fold_key(name): spec for name, spec in fields.items()} for context, fields in data.items()}


NODE_FIELDS = load_node_fields()


def fields_refused(outbound):
    """В outbound'е есть поле не из белого списка (node_fields.json) или поле «только пустое» (sendThrough,
    sockopt.tproxy) задано: новое поле ядра может набирать свои адреса мимо проверок - такой узел не проверяем.
    "" - любое значение, "*" - любые ключи (заголовки), "@раздел" - вложенный объект, "!а,б" - только пусто или
    одно из значений. Как NodeRules.fieldsRefused у агента."""
    protocol = outbound.get("protocol")
    return _fields_refused(outbound, "outbound", protocol.lower() if isinstance(protocol, str) else "")


def _fields_refused(value, context, protocol):
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


def keys_ambiguous(value, depth=0):
    """В узле есть поле, которое xray прочтёт не так, как проверки: имя xray в другом регистре или через «ſ»/«K»,
    два ключа одного объекта, совпадающие для xray, повтор ключа в исходном JSON."""
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


def strip_insecure(outbound):
    """xray 26 не запускается с allowInsecure (заменён на pinnedPeerCertSha256 и verifyPeerCertByName) -
    убираем поле из TLS-настроек outbound'а."""
    stream = outbound.get("streamSettings") if isinstance(outbound, dict) else None
    tls = stream.get("tlsSettings") if isinstance(stream, dict) else None
    if isinstance(tls, dict):
        tls.pop("allowInsecure", None)
    return outbound


def linked_tags(outbound):
    """Теги outbound'ов, через которые этот ходит: sockopt.dialerProxy и proxySettings.tag."""
    tags = []
    if not isinstance(outbound, dict):
        return tags
    stream = outbound.get("streamSettings") or {}
    sockopt = stream.get("sockopt") if isinstance(stream, dict) else None
    if isinstance(sockopt, dict) and sockopt.get("dialerProxy"):
        tags.append(sockopt["dialerProxy"])
    proxy = outbound.get("proxySettings")
    if isinstance(proxy, dict) and proxy.get("tag"):
        tags.append(proxy["tag"])
    return [tag for tag in tags if isinstance(tag, str)]


def is_private(address):
    """Адрес не из интернета - те же сети, что у агента (SiteCheck.PRIVATE_V4_CIDRS, XrayRunner.PRIVATE_CIDRS),
    в том числе IPv4 внутри IPv6 (::ffff:, NAT64 64:ff9b::/96, 6to4 2002::/16)."""
    if address.version == 6:
        inner = address.ipv4_mapped or address.sixtofour
        if inner is None and address in NAT64:
            inner = ipaddress.IPv4Address(int(address) & 0xFFFFFFFF)
        if inner is not None:
            return is_private(inner)
    return any(address in net for net in PRIVATE_NETS if net.version == address.version)


def bare_host(address):
    return str(address or "").strip().strip("[]").lower().rstrip(".")


def odd_address(address):
    """Адрес с пробельным или управляющим символом (Go TrimSpace срезает и U+0085, Kotlin trim - нет) или "env:ИМЯ"
    (xray возьмёт адрес из переменной окружения), зона IPv6 через "%": проверки и xray увидели бы разные адреса.
    Как NodeRules.oddAddress."""
    text = str(address or "")
    return text.lower().startswith(ENV_PREFIX) or any(
        char == "%" or ord(char) <= 0x20 or 0x7F <= ord(char) <= 0xA0 or 0x2000 <= ord(char) <= 0x200A
        or char in EXTRA_SPACES
        for char in text)


def address_refused(address):
    """Узел не должен вести на localhost и на IP не из интернета. Домен решает резолв на телефоне."""
    if odd_address(address):
        return True
    host = bare_host(address)
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return is_private(ipaddress.ip_address(host))
    except ValueError:
        return False


def download_settings(outbound, limit=MAX_DOWNLOAD_DEPTH):
    """Отдельные каналы загрузки xhttp (downloadSettings прямо в xhttpSettings или в его extra, и вложенные в
    них до limit уровней): у каждого свой адрес и свой sockopt.dialerProxy, которых не видят проверки главного
    outbound'а."""
    stream = outbound.get("streamSettings") if isinstance(outbound, dict) else None
    return _downloads(stream, 0, limit)


def _downloads(stream, depth, limit):
    found = []
    if not isinstance(stream, dict) or depth >= limit:
        return found
    for name in XHTTP_KEYS:
        xhttp = stream.get(name)
        if not isinstance(xhttp, dict):
            continue
        extra = xhttp.get("extra")
        for holder in (xhttp, extra) if isinstance(extra, dict) else (xhttp,):
            download = holder.get("downloadSettings")
            if isinstance(download, dict):
                found.append(download)
                found += _downloads(download, depth + 1, limit)
    return found


def addresses_of(outbound):
    """Адреса, куда подключается outbound: settings.address/server, vnext[]/servers[] и каналы загрузки."""
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


def node_refusal(node):
    """Почему агент не станет проверять узел - то же правило и тот же порядок у агента (NodeRules.refusal) и
    сервера агентов (node_refusal); общие случаи - tests/data/chain_cases.json. "unsupported" - ключи, которые
    xray прочтёт иначе (keys_ambiguous), цепочка не собирается (кольцо, лишнее или потерянное звено, повтор тега),
    канал загрузки ходит через другой outbound или вложен слишком глубоко, протокол, которого нет в ядре,
    allowInsecure, поле не из белого списка node_fields.json (fields_refused); "rejected" - протокол не тот, адрес
    не из интернета (в том числе у звена цепочки и у канала загрузки xhttp), с пробельным символом или "env:",
    freedom с redirect, echConfigList не готовым конфигом. "" - проверять можно."""
    outbound = node.get("outbound") if isinstance(node, dict) else None
    if not isinstance(outbound, dict):
        return "rejected"
    extras = node.get("extra_outbounds")
    if keys_ambiguous([outbound, extras]):
        return "unsupported"
    if _address_refusal(outbound, NODE_PROTOCOLS):
        return "rejected"
    extras = [] if extras is None else extras
    if (not isinstance(extras, list) or not all(isinstance(item, dict) for item in extras)
            or len(extras) > MAX_EXTRA_OUTBOUNDS):
        return "unsupported"
    tags = {}
    for item in extras:
        tag = item.get("tag")
        if not isinstance(tag, str) or not tag or tag in AGENT_TAGS or tag in tags:
            return "unsupported"
        tags[tag] = item
        if _address_refusal(item, EXTRA_PROTOCOLS) or _redirects(item):
            return "rejected"
        if _freedom_extras(item) or _muxed(item):
            return "unsupported"
    main_tag = outbound.get("tag")
    if main_tag is not None and not isinstance(main_tag, str):
        return "unsupported"
    if main_tag in AGENT_TAGS or main_tag in tags:
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
    if any(_chained(download) for item in items for download in download_settings(item)):
        return "unsupported"
    return "" if _chain_complete(outbound, tags) else "unsupported"


def _address_refusal(outbound, allowed):
    protocol = outbound.get("protocol")
    if not isinstance(protocol, str) or protocol.lower() not in allowed:
        return True
    return any(address_refused(address) for address in addresses_of(outbound))


def _redirects(outbound):
    settings = outbound.get("settings")
    return (str(outbound.get("protocol")).lower() == "freedom" and isinstance(settings, dict)
            and bool(settings.get("redirect")))


def _freedom_extras(outbound):
    """freedom-звено с настройками не из FREEDOM_SETTINGS (finalRules, ipsBlocked...): как NodeRules.freedomExtras."""
    settings = outbound.get("settings")
    if str(outbound.get("protocol")).lower() != "freedom" or not isinstance(settings, dict):
        return False
    return any(fold_key(key) not in FREEDOM_SETTINGS for key in settings)


def _muxed(outbound):
    return any(fold_key(key) == MUX_KEY and isinstance(mux, dict)
               and any(fold_key(name) == MUX_ENABLED_KEY and bool(value) for name, value in mux.items())
               for key, mux in outbound.items())


def _own_sockopts(outbound):
    stream = outbound.get("streamSettings")
    holders = ([stream] if isinstance(stream, dict) else []) + download_settings(outbound)
    return [holder["sockopt"] for holder in holders if isinstance(holder.get("sockopt"), dict)]


def _port_strategy(outbound):
    """sockopt.addressPortStrategy не none у outbound'а или канала загрузки: как NodeRules.portStrategy."""
    return any(fold_key(key) == PORT_STRATEGY_KEY and value is not None
               and not (isinstance(value, str) and value.lower() == "none")
               for sockopt in _own_sockopts(outbound) for key, value in sockopt.items())


def _agent_sockopt(outbound):
    """sockopt interface, mark или customSockopt не пусты у outbound'а или канала загрузки: привязку к сети ставит
    агент, узел её перебил бы. Как NodeRules.agentSockopt."""
    return any(fold_key(key) in AGENT_SOCKOPT and bool(value)
               for sockopt in _own_sockopts(outbound) for key, value in sockopt.items())


def _chained(download):
    sockopt = download.get("sockopt")
    return (isinstance(sockopt, dict) and bool(sockopt.get("dialerProxy"))) or bool(download.get("proxySettings"))


def _chain_complete(main, by_tag):
    seen, queue = set(), list(linked_tags(main))
    while queue:
        tag = queue.pop(0)
        if tag not in by_tag or tag in seen:
            return False
        seen.add(tag)
        queue.extend(linked_tags(by_tag[tag]))
    return len(seen) == len(by_tag)


def extra_outbounds(outbound, outbounds):
    """Связанные outbound'ы узла (цепочка dialerProxy/proxySettings) из того же конфига - копии, по порядку.
    None - на какой-то тег ссылки нет в конфиге, звено встречается дважды или ссылается на сам узел (кольцо
    раздувает xray до сотен МБ), цепочка длиннее MAX_EXTRA_OUTBOUNDS или звено не годится агенту (протокол не из
    EXTRA_PROTOCOLS, служебный тег, freedom с redirect): такой узел не проверяем. Те же правила у сервера агентов
    (chain_ok) и агента (XrayRunner.chainRefusal)."""
    by_tag = {tag_of(item): item for item in outbounds if tag_of(item)}
    own = tag_of(outbound)
    found, queue = [], linked_tags(outbound)
    while queue:
        tag = queue.pop(0)
        if tag == own or any(tag_of(item) == tag for item in found):
            return None
        if tag not in by_tag or len(found) >= MAX_EXTRA_OUTBOUNDS:
            return None
        item = strip_insecure(copy.deepcopy(by_tag[tag]))
        if not extra_allowed(item):
            return None
        found.append(item)
        queue.extend(linked_tags(item))
    return found


def extra_allowed(outbound):
    """Звено цепочки, которое примут сервер агентов и агент (те же правила, что у сервера)."""
    protocol = outbound.get("protocol")
    return (isinstance(protocol, str) and protocol.lower() in EXTRA_PROTOCOLS
            and tag_of(outbound) not in EXTRA_RESERVED_TAGS and not _redirects(outbound))


def vless_servers(outbound):
    """Серверы VLESS-outbound'а: [(адрес, порт, outbound только с этим сервером)]. Обе формы xray -
    settings.vnext[] и плоская settings.address/port/id."""
    settings = outbound.get("settings") or {}
    if settings.get("vnext"):
        servers = []
        for node in settings["vnext"]:
            single = copy.deepcopy(outbound)
            single["settings"]["vnext"] = [node]
            servers.append((node.get("address"), node.get("port"), single))
        return servers
    if settings.get("address"):
        return [(settings.get("address"), settings.get("port"), copy.deepcopy(outbound))]
    return []


def main_outbounds(outbounds):
    """VLESS-outbound'ы конфига, которые сами узлы, а не звенья чужой цепочки (на них не ссылаются dialerProxy и
    proxySettings.tag). Все VLESS в кольце - берём тот, что с тегом proxy: extra_outbounds его отбракует."""
    vless = [item for item in outbounds if isinstance(item, dict) and str(item.get("protocol")).lower() == "vless"]
    referenced = {tag for item in outbounds for tag in linked_tags(item)}
    return ([item for item in vless if tag_of(item) not in referenced]
            or [item for item in vless if tag_of(item) == "proxy"])


def skip_label(outbound, extra, refusal):
    """Подпись пропущенного VLESS-узла: почему стенд его не проверяет."""
    if keys_ambiguous([outbound, extra]):
        return t("vless (неоднозначные ключи настроек)")
    if any(download_settings(item) for item in [outbound] + (extra or [])):
        return "vless+downloadSettings"
    if refusal == "rejected" and not extra:
        return t("vless (адрес не из интернета)")
    if refusal and not extra and not linked_tags(outbound):
        return t("vless (настройки, которые агент не проверяет)")
    return "vless+dialerProxy"


def node_sni(outbound, address):
    """SNI, с которым xray идёт к узлу: serverName из reality или tls; у tls без serverName - сам адрес узла."""
    stream = outbound.get("streamSettings")
    stream = stream if isinstance(stream, dict) else {}
    security = str(stream.get("security") or "").lower()
    for section in ("realitySettings", "tlsSettings"):
        settings = stream.get(section)
        name = settings.get("serverName") if isinstance(settings, dict) else None
        if isinstance(name, str) and name:
            return name
    return address if security == "tls" else None


def parse_subscription(raw, only_443=True, location_filter=None, skipped=None):
    """Узлы VLESS из JSON-подписки. skipped (список) - сюда узлы, которые не проверить: цепочка dialerProxy
    ссылается на то, чего в конфиге нет, замкнута в кольцо или агент её не поднимет, канал загрузки xhttp
    (downloadSettings) идёт через цепочку, адрес не из интернета (node_refusal)."""
    data = loads_json(raw) if isinstance(raw, (str, bytes)) else raw
    targets = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        location = entry.get("remarks") or "?"
        if location_filter and location_filter.lower() not in location.lower():
            continue
        seen = set()
        outbounds = entry.get("outbounds") or []
        outbounds = outbounds if isinstance(outbounds, list) else []
        for outbound in main_outbounds(outbounds):
            for address, port, single in vless_servers(outbound):
                if only_443 and port != PORTS_STANDARD:
                    continue
                key = (address, port)
                if key in seen:
                    continue
                seen.add(key)
                strip_insecure(single)
                target = {
                    "location": location,
                    "address": address,
                    "port": port,
                    "key": "%s:%s" % (address, port),
                    "sni": node_sni(single, address),
                    "outbound": single,
                }
                extra = extra_outbounds(single, outbounds) if linked_tags(single) else []
                refusal = node_refusal({"outbound": single, "extra_outbounds": extra}) if extra is not None else ""
                if extra is None or refusal:
                    if skipped is not None:
                        skipped.append({"location": location, "protocol": skip_label(single, extra, refusal),
                                        "address": address or "?", "port": port or 443})
                    continue
                if extra:
                    target["extra_outbounds"] = extra
                targets.append(target)
    return targets
