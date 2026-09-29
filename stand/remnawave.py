"""Клиент API панели Remnawave: сквады, временный пользователь и его подписка.

Работает напрямую по HTTPS с API-токеном панели (в админке Remnawave: Settings → API Tokens),
без SSH и доступа к серверу панели. Стенд создаёт в выбранном скваде временного пользователя,
забирает его подписку - это ровно тот набор узлов, который видят клиенты сквада, - и после
проверки удаляет пользователя.

Remnawave-клиенты с лимитом устройств получают список узлов только с заголовками устройства
(HWID) - поэтому подписка запрашивается с ними же.
"""
import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from . import safehttp
from .i18n import t

HAPP_UA = "Happ/5.6.0/ios"
SUB_HEADERS = {"User-Agent": HAPP_UA, "x-hwid": "vpncheckstand0001",
               "x-device-os": "iOS", "x-ver-os": "18.0", "x-device-model": "iPhone 15"}


class PanelError(Exception):
    """Панель ответила ошибкой или не ответила - текст понятен человеку."""


def user_id(user):
    """Как адресовать пользователя в API: старые Remnawave - строковый uuid, новые (2.x) -
    числовой id, а uuid в ответе нет вовсе. Возвращает строку или None."""
    if not isinstance(user, dict):
        return None
    ident = user.get("uuid") or user.get("id")
    return str(ident) if ident not in (None, "") else None


class Panel:
    """Одна панель Remnawave: адрес и API-токен.

    headers - дополнительные заголовки, если панель спрятана за прокси с секретом
    (например, Caddy с cookie/заголовком доступа). verify_tls=False - для панели
    с самоподписанным сертификатом.
    """

    def __init__(self, url, token, headers=None, verify_tls=True, timeout=30):
        token = (token or "").strip()
        if not url or not token:
            raise PanelError(t("у панели должны быть адрес и API-токен"))
        if any(ch.isspace() for ch in token):
            raise PanelError(t("в API-токене пробел или перенос строки - скопируйте токен заново, одной строкой"))
        self.url = url.rstrip("/")
        if not self.url.startswith(("http://", "https://")):
            self.url = "https://" + self.url
        self.token = token
        self.headers = dict(headers or {})
        self.timeout = timeout
        self.context = None if verify_tls else ssl._create_unverified_context()  # noqa: SLF001

    @classmethod
    def from_config(cls, config):
        """config - запись панели из connections.json: {"url", "token", "headers", "verify_tls"}."""
        return cls(config.get("url", ""), config.get("token", ""), config.get("headers"),
                   config.get("verify_tls", True))


    def api(self, method, path, body=None):
        """Вызов API. Возвращает поле response ответа (или весь ответ, если его нет)."""
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Authorization": "Bearer %s" % self.token, "Accept": "application/json",
                   "User-Agent": "vpncheck-stand"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        headers.update(self.headers)
        request = urllib.request.Request(self.url + path, data=data, method=method, headers=headers)
        try:
            with safehttp.urlopen(request, timeout=self.timeout, context=self.context) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read()[:300].decode("utf-8", "replace")
            if exc.code in (401, 403):
                raise PanelError(t("панель не пустила (HTTP %d): проверьте API-токен") % exc.code) from exc
            raise PanelError(t("панель ответила HTTP %d на %s %s: %s") % (exc.code, method, path, detail)) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise PanelError(t("панель %s не отвечает: %s") % (self.url, getattr(exc, "reason", exc))) from exc
        if not raw:
            return {}
        try:
            payload = json.loads(raw)
        except ValueError as exc:
            raise PanelError(t("панель вернула не JSON (адрес указывает не на API?): %s")
                             % raw[:120].decode("utf-8", "replace")) from exc
        return payload.get("response", payload) if isinstance(payload, dict) else payload


    def squads(self):
        """[{"uuid", "name"}] внутренних сквадов панели."""
        found = self.api("GET", "/api/internal-squads")
        if isinstance(found, dict):
            found = found.get("internalSquads", [])
        return [{"uuid": squad.get("uuid"), "name": squad.get("name")} for squad in found or [] if squad.get("name")]

    def squad_uuid(self, name):
        names = []
        for squad in self.squads():
            if squad["name"] == name:
                return squad["uuid"]
            names.append(squad["name"])
        raise PanelError(t("сквад «%s» не найден; есть: %s") % (name, ", ".join(names) or "-"))


    def create_user(self, squad_name, days=1, traffic_mb=0, prefix="vpncheck_tmp"):
        """Пользователь в скваде. traffic_mb=0 - без лимита трафика.

        Возвращает {"uuid", "short_uuid", "username", "expire" (epoch), "sub_url"}.
        """
        squad = self.squad_uuid(squad_name)
        username = "%s_%d" % (prefix, int(time.time()))
        expire = time.time() + days * 86400
        created = self.api("POST", "/api/users", {
            "username": username, "status": "ACTIVE",
            "expireAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(expire)),
            "trafficLimitBytes": int(traffic_mb) * 1024 * 1024, "trafficLimitStrategy": "NO_RESET",
            "activeInternalSquads": [squad]})
        created = created if isinstance(created, dict) else {}
        ident = user_id(created)
        if not ident or not created.get("shortUuid"):
            raise PanelError(t("панель не создала пользователя: %s") % json.dumps(created, ensure_ascii=False)[:200])
        sub_url = str(created.get("subscriptionUrl") or "")
        if not sub_url.lower().startswith(("http://", "https://")):
            sub_url = "%s/api/sub/%s" % (self.url, created["shortUuid"])
        return {"uuid": ident, "short_uuid": created["shortUuid"], "username": username, "expire": expire,
                "sub_url": sub_url}

    def delete_user(self, ident):
        """ident - то, что вернул create_user в поле uuid (строка uuid или числовой id)."""
        self.api("DELETE", "/api/users/%s" % urllib.parse.quote(str(ident)))

    def fetch_subscription(self, user):
        """Подписка пользователя (dict из create_user или ссылка) как её получит клиент Happ."""
        url = user["sub_url"] if isinstance(user, dict) else user
        if not str(url).lower().startswith(("http://", "https://")):
            raise PanelError(t("ссылка на подписку - не http(s): %s") % str(url)[:200])
        request = urllib.request.Request(url, headers=dict(SUB_HEADERS))
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.context) as response:
                return response.read()
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise PanelError(t("подписка %s не скачалась: %s") % (url, getattr(exc, "reason", exc))) from exc
