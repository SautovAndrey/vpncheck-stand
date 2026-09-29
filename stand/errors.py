"""Переводчик сетевых ошибок: вместо «<urlopen error [SSL: UNEXPECTED_EOF_WHILE_READING]…>» или
«HTTP 401 /v1/admin/agents: {"detail": …}» - короткая понятная фраза. Сырой текст остаётся для подсказки
и журнала (его показывает вызывающий).

explain(exc) - исключение или его текст -> фраза на языке интерфейса, "" - если не узнали;
explain(exc, timeout=8) - сколько секунд ждали, для фразы про таймаут.
"""
import re
import socket
import ssl
import urllib.error

from .i18n import t
from .remnawave import PanelError

DEFAULT_TIMEOUT = 30
SSL_MARKS = ("ssl", "certificate", "tls", "eof occurred in violation")
TIMEOUT_MARKS = ("timed out", "timeout", "10060", "errno 110")
REFUSED_MARKS = ("refused", "10061", "errno 111")
DNS_MARKS = ("getaddrinfo", "name or service not known", "nodename nor servname", "11001", "11004",
             "name resolution", "no address associated")
TOKEN_MARKS = ("http 401", "401 unauthorized", "нет доступа", "access denied")
PANEL_MARKS = ("панел", "panel")
HTTP_STATUS = re.compile(r"^http (\d{3})\b")


def _reason(error):
    """Исключение, которое на самом деле случилось: URLError прячет его в reason."""
    while isinstance(error, urllib.error.URLError) and not isinstance(error, urllib.error.HTTPError):
        reason = error.reason
        if not isinstance(reason, BaseException):
            break
        error = reason
    return error


def kind(error):
    """ssl / timeout / refused / dns / token / panel_token или "" - по типу исключения, иначе по тексту.
    Токен не подошёл у панели Remnawave - panel_token: совет другой, чем для сервера агентов."""
    found = _kind(error)
    text = str(error or "").lower()
    if found == "token" and (isinstance(error, PanelError) or any(mark in text for mark in PANEL_MARKS)):
        return "panel_token"
    return found


def _kind(error):
    error = _reason(error)
    if isinstance(error, urllib.error.HTTPError):
        return "token" if error.code == 401 else ""
    if isinstance(error, ssl.SSLError):
        return "ssl"
    if isinstance(error, (socket.timeout, TimeoutError)):
        return "timeout"
    if isinstance(error, ConnectionRefusedError):
        return "refused"
    if isinstance(error, socket.gaierror):
        return "dns"
    text = str(error or "").lower()
    status = HTTP_STATUS.match(text)
    if status:
        return "token" if status.group(1) == "401" else ""
    for name, marks in (("token", TOKEN_MARKS), ("dns", DNS_MARKS), ("refused", REFUSED_MARKS),
                        ("ssl", SSL_MARKS), ("timeout", TIMEOUT_MARKS)):
        if any(mark in text for mark in marks):
            return name
    return ""


def explain(error, timeout=DEFAULT_TIMEOUT):
    """Понятная фраза о сетевой ошибке на языке интерфейса; "" - ошибка не сетевая или не узнана."""
    found = kind(error)
    if found == "ssl":
        return t("сбой защищённого соединения (HTTPS) - проверьте адрес и сертификат")
    if found == "timeout":
        return t("нет ответа за %d с") % int(timeout or DEFAULT_TIMEOUT)
    if found == "refused":
        return t("соединение отклонено - сервер не запущен или порт закрыт")
    if found == "dns":
        return t("адрес не найден")
    if found == "token":
        return t("токен не подошёл - возьмите его из вывода install.sh или agent.json")
    if found == "panel_token":
        return t("API-токен панели не подошёл - проверьте его в Файл → Подключения")
    return ""
