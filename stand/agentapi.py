"""Клиент к серверу агентов (админ-часть) и подпись манифестов обновлений.

Секреты: адрес и админ-токен в настройках программы (кладёт server/deploy.py), ключ подписи -
%APPDATA%\\VPNCheckStand\\keys\\manifest_ed25519.key (не покидает этот компьютер).
"""
import base64
import functools
import gzip
import hashlib
import http.client
import json
import os
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from . import safehttp, storage
from .i18n import t
from .storage import APP_DIR

AGENT_CONFIG = os.path.join(APP_DIR, "agent.json")
KEY_PATH = os.path.join(APP_DIR, "keys", "manifest_ed25519.key")
MAX_UPLOAD_BYTES = 120 * 1024 * 1024
UPLOAD_CHUNK = 1 << 20
PUB_PATH = os.path.join(APP_DIR, "keys", "manifest_ed25519.pub")
PIN_RE = re.compile(r"^sha256/[A-Za-z0-9+/]{43}=$")
TLS_KEYS = ("tls_host", "tls_port", "tls_pin")


def load_agent_config():
    """Адрес сервера и админ-токен - в своём файле, чтобы окно стенда их не затирало.
    Битый или нечитаемый файл - как будто его нет (центр строится с пустыми полями, а не падает)."""
    try:
        with open(AGENT_CONFIG, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        data = None
    return data if isinstance(data, dict) else {"server": "", "token": ""}


def save_agent_config(server, token):
    """Обновить адрес и токен, остальные поля (ключ Яндекса, провайдер карты) не трогать.
    Файл с админ-токеном: атомарно и только для владельца (0600)."""
    cfg = load_agent_config()
    cfg.update({"server": server, "token": token})
    storage.write_json(AGENT_CONFIG, cfg, indent=1, mode=0o600)


def save_tls(host="", port=0, pin=""):
    """Порт и отпечаток TLS сервера агентов (кладёт server/deploy.py по SSH); пустой host - убрать."""
    cfg = load_agent_config()
    for key in TLS_KEYS:
        cfg.pop(key, None)
    if host:
        cfg.update({"tls_host": host, "tls_port": int(port), "tls_pin": pin})
    storage.write_json(AGENT_CONFIG, cfg, indent=1, mode=0o600)


def tls_for(server, cfg=None):
    """TLS из agent.json - только для http-адреса того же хоста, для которого его сохранил deploy."""
    cfg = load_agent_config() if cfg is None else cfg
    host, port, pin = cfg.get("tls_host"), cfg.get("tls_port"), cfg.get("tls_pin")
    if not isinstance(host, str) or not isinstance(pin, str) or not PIN_RE.match(pin):
        return None
    if isinstance(port, bool) or not isinstance(port, int) or not 0 < port < 65536:
        return None
    try:
        parts = urllib.parse.urlsplit(server.strip())
        hostname = parts.hostname
    except ValueError:
        return None
    if parts.scheme.lower() != "http" or not hostname or hostname.lower() != host.strip("[]").lower():
        return None
    return {"port": port, "pin": pin}


def server_for(server, token):
    return AgentServer(server, token, tls=tls_for(server))


def connect_from_config():
    cfg = load_agent_config()
    return AgentServer(cfg.get("server", ""), cfg.get("token", ""), tls=tls_for(cfg.get("server", ""), cfg))


def spki_pin(cert):
    """Отпечаток открытого ключа сертификата, как у OkHttp CertificatePinner: sha256/ + base64(sha256(SPKI DER))."""
    if isinstance(cert, str):
        cert = cert.encode("ascii")
    parsed = x509.load_pem_x509_certificate(cert) if b"-----BEGIN" in cert else x509.load_der_x509_certificate(cert)
    spki = parsed.public_key().public_bytes(serialization.Encoding.DER,
                                            serialization.PublicFormat.SubjectPublicKeyInfo)
    return "sha256/" + base64.b64encode(hashlib.sha256(spki).digest()).decode("ascii")


class PinMismatch(OSError):
    pass


class PinnedConnection(http.client.HTTPSConnection):
    def __init__(self, *args, pin, **kwargs):
        super().__init__(*args, **kwargs)
        self.pin = pin

    def connect(self):
        super().connect()
        der = self.sock.getpeercert(binary_form=True)
        try:
            got = spki_pin(der) if der else ""
        except ValueError:
            got = ""
        if got != self.pin:
            self.sock.close()
            raise PinMismatch("server certificate pin %s != %s" % (got or "-", self.pin))


class PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    """HTTPS к самоподписанному сертификату сервера: цепочка и имя не проверяются, проверяется отпечаток ключа."""

    def __init__(self, pin):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        super().__init__(context=context)
        self.pin = pin

    def https_open(self, req):
        return self.do_open(functools.partial(PinnedConnection, pin=self.pin), req, context=self._context)


def canonical(obj):
    """Тот же канонический JSON, что проверяет агент: ключи по алфавиту, без пробелов, без signature."""
    if isinstance(obj, dict):
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + canonical(v)
                              for k, v in sorted(obj.items()) if k != "signature") + "}"
    if isinstance(obj, list):
        return "[" + ",".join(canonical(v) for v in obj) + "]"
    if isinstance(obj, bool) or obj is None:
        return "true" if obj is True else "false" if obj is False else "null"
    if isinstance(obj, (int, float)):
        return str(int(obj)) if float(obj) == int(obj) else repr(obj)
    return json.dumps(obj, ensure_ascii=False)


def sign_manifest(manifest):
    with open(KEY_PATH, "rb") as handle:
        key = ed25519.Ed25519PrivateKey.from_private_bytes(handle.read())
    signed = dict(manifest)
    signed.pop("signature", None)
    signed["signature"] = key.sign(canonical(signed).encode("utf-8")).hex()
    return signed


def public_key_hex():
    with open(PUB_PATH, "rb") as handle:
        return handle.read().hex()


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


class AgentServer:
    def __init__(self, base_url, token, tls=None):
        self.base = base_url.rstrip("/")
        self.token = token
        self.tls = None
        if tls:
            parts = urllib.parse.urlsplit(self.base)
            host = parts.hostname or ""
            host = "[%s]" % host if ":" in host else host
            self.base = "https://%s:%d" % (host, int(tls["port"]))
            self.tls = {"port": int(tls["port"]), "pin": str(tls["pin"])}

    def _request(self, method, path, body=None, raw=None, content_type="application/json", timeout=30, length=None):
        data = raw
        if data is None and body is not None:
            data = json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")
        headers = {"X-Admin-Token": self.token, "Content-Type": content_type, "Accept-Encoding": "gzip"}
        if length is not None:
            headers["Content-Length"] = str(length)
        request = urllib.request.Request(self.base + path, data=data, method=method, headers=headers)
        pinned = {"https_handler": PinnedHTTPSHandler(self.tls["pin"])} if self.tls else {}
        try:
            with safehttp.urlopen(request, timeout=timeout, **pinned) as response:
                raw = response.read()
                if str(response.headers.get("Content-Encoding", "")).lower() == "gzip":
                    raw = gzip.decompress(raw)
                return json.loads(raw)
        except urllib.error.HTTPError as exc:
            raise RuntimeError("HTTP %s %s: %s" % (exc.code, path, exc.read()[:200].decode(errors="replace"))) from exc
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, PinMismatch):
                raise RuntimeError(t("сертификат сервера не совпадает с сохранённым отпечатком (%s) - "
                                     "перевыкатите сервер: python server/deploy.py") % self.base) from exc
            raise

    def health(self):
        return self._request("GET", "/health")

    def agents(self):
        return self._request("GET", "/v1/admin/agents")["agents"]

    def reports(self, since=0, limit=500, agent_id=""):
        path = "/v1/admin/reports?" + urllib.parse.urlencode({"since": since, "limit": limit, "agent_id": agent_id})
        return self._request("GET", path)["reports"]

    def matrix(self, hours=24):
        return self._request("GET", "/v1/admin/matrix?hours=%s" % hours)

    def state(self):
        return self._request("GET", "/v1/admin/state")

    def set_state(self, **patch):
        return self._request("POST", "/v1/admin/state", body=patch)

    def set_nodes(self, targets, expire=None, user=""):
        """Узлы vpncheck → то, что нужно агенту: ключ, локация, outbound.
        expire (epoch) и user - срок и имя учётки агентов в панели: по ним стенд предупреждает,
        когда выложить заново."""
        nodes = []
        for target in targets:
            node = {"key": target["key"], "location": target["location"], "sni": target.get("sni") or "",
                    "outbound": target["outbound"]}
            if target.get("extra_outbounds"):
                node["extra_outbounds"] = target["extra_outbounds"]
            nodes.append(node)
        return self.set_state(nodes=nodes, nodes_expire=float(expire or 0), nodes_user=user or "")

    def upload(self, path, timeout=600):
        """Файл на сервер (multipart) потоком, без чтения целиком в память; больше MAX_UPLOAD_BYTES - отказ сразу:
        сервер такой всё равно не примет."""
        size = os.path.getsize(path)
        if size > MAX_UPLOAD_BYTES:
            raise RuntimeError(t("файл больше %d МБ - сервер его не примет") % (MAX_UPLOAD_BYTES >> 20))
        boundary = "----vpnstand%s" % os.urandom(8).hex()
        head = ("--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\n"
                "Content-Type: application/octet-stream\r\n\r\n" % (boundary, os.path.basename(path))).encode()
        tail = ("\r\n--%s--\r\n" % boundary).encode()

        def parts():
            yield head
            with open(path, "rb") as handle:
                yield from iter(lambda: handle.read(UPLOAD_CHUNK), b"")
            yield tail
        return self._request("POST", "/v1/admin/upload", raw=parts(), length=len(head) + size + len(tail),
                             content_type="multipart/form-data; boundary=%s" % boundary, timeout=timeout)

    def publish_manifest(self, app=None, disable_tls=False):
        """Собрать, подписать и выложить манифест. app - словарь с version_code/url/sha256 (None - оставить как есть).
        Ядро по воздуху агент больше не обновляет, поэтому core из манифеста убирается.
        tls {"port", "pin"} - только из agent.json этого стенда, не из состояния сервера. В манифесте сервера tls
        есть, а у стенда нет - отказ: иначе выкладка молча выключила бы TLS агентам. Выключить - только явно
        (disable_tls=True): в манифест идёт "tls": null, его агенты 0.12.11+ понимают как выключение."""
        current = (self.state().get("manifest") or {})
        if not disable_tls and not self.tls and current.get("tls"):
            raise RuntimeError(t("в манифесте сервера есть TLS, а в agent.json этого стенда его нет - выкладка "
                                 "выключила бы шифрование агентам. Перевыкатите сервер: python server/deploy.py "
                                 "(выключить TLS - python server/deploy.py --disable-tls)"))
        manifest = {k: v for k, v in current.items() if k not in ("signature", "core", "tls")}
        if app is not None:
            manifest["app"] = app
        if self.tls and not disable_tls:
            manifest["tls"] = dict(self.tls)
        elif disable_tls or "tls" in current:
            manifest["tls"] = None
        manifest["issued"] = int(time.time())
        signed = sign_manifest(manifest)
        self.set_state(manifest=signed)
        return signed

    def run_now(self, agent_id=""):
        return self._request("POST", "/v1/admin/run_now", body={"agent_id": agent_id})

    def update_now(self, agent_id=""):
        return self._request("POST", "/v1/admin/update_now", body={"agent_id": agent_id})

    def trends(self, limit=5000, offset=0, scope=""):
        """Стабильность постранично: (узлы, сколько строк на сервере всего - None у старого сервера)."""
        query = {"limit": limit, "offset": offset}
        if scope:
            query["scope"] = scope
        answer = self._request("GET", "/v1/admin/trends?" + urllib.parse.urlencode(query))
        answer = answer if isinstance(answer, dict) else {}
        nodes = answer.get("nodes") if isinstance(answer.get("nodes"), list) else []
        total = answer.get("total")
        return nodes, total if isinstance(total, int) and not isinstance(total, bool) else None

    def clear_errors(self):
        return self._request("POST", "/v1/admin/errors/clear", body={})

    def locate(self, agent_id):
        return self._request("POST", "/v1/admin/locate", body={"agent_id": agent_id})

    def message(self, agent_id, text="", vpn_off=False):
        return self._request("POST", "/v1/admin/message",
                             body={"agent_id": agent_id, "text": text, "vpn_off": vpn_off})

    def command(self, agent_id, action, text=""):
        """Команда с результатом: site_check(text=URL), diag, xray_log(text=узел), speed(text=узел),
        whitelist_banner."""
        return self._request("POST", "/v1/admin/command", body={"agent_id": agent_id, "action": action, "text": text})

    def results(self, agent_id="", since=0, limit=50):
        path = "/v1/admin/results?" + urllib.parse.urlencode({"agent_id": agent_id, "since": since, "limit": limit})
        return self._request("GET", path)["results"]

    def errors(self, since=0, limit=300):
        return self._request("GET", "/v1/admin/errors?since=%s&limit=%d" % (since, limit))["errors"]
