"""Карта центра открывается со своей схемы vpncheck://assets/…, а не с file://.

Страница с file:// могла бы читать любые файлы компьютера (connections.json, ключ подписи).
Со своей схемы ей отдаются только файлы папки assets с известными расширениями, а file://
для неё чужой источник - браузер его не откроет.
"""
import os

from PySide6.QtCore import QBuffer, QByteArray, QIODevice, QUrl
from PySide6.QtWebEngineCore import (
    QWebEngineProfile,
    QWebEngineUrlRequestJob,
    QWebEngineUrlScheme,
    QWebEngineUrlSchemeHandler,
)

SCHEME = b"vpncheck"
HOST = "assets"
ASSETS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")
TYPES = {".html": b"text/html", ".js": b"application/javascript", ".css": b"text/css", ".png": b"image/png",
         ".svg": b"image/svg+xml", ".geojson": b"application/json", ".json": b"application/json"}

_handler = None


def register():
    """Схема регистрируется до первого QWebEngineView (лучше - до QApplication)."""
    if QWebEngineUrlScheme.schemeByName(SCHEME).name() == SCHEME:
        return
    scheme = QWebEngineUrlScheme(SCHEME)
    scheme.setSyntax(QWebEngineUrlScheme.Syntax.Host)
    scheme.setFlags(QWebEngineUrlScheme.Flag.SecureScheme)
    QWebEngineUrlScheme.registerScheme(scheme)


def asset_path(url_path):
    """Файл из assets по пути URL или None: выход из папки и чужие расширения не отдаются."""
    if not url_path or ":" in url_path:
        return None
    relative = os.path.normpath(url_path.lstrip("/"))
    if not relative or relative.startswith("..") or os.path.isabs(relative):
        return None
    full = os.path.join(ASSETS, relative)
    try:
        inside = os.path.commonpath([os.path.abspath(full), ASSETS]) == ASSETS
    except ValueError:
        return None
    if not inside:
        return None
    if os.path.splitext(full)[1].lower() not in TYPES or not os.path.isfile(full):
        return None
    return full


class AssetHandler(QWebEngineUrlSchemeHandler):
    def requestStarted(self, job):
        url = job.requestUrl()
        path = asset_path(url.path()) if url.host() == HOST else None
        if path is None:
            job.fail(QWebEngineUrlRequestJob.Error.UrlNotFound)
            return
        try:
            with open(path, "rb") as handle:
                data = handle.read()
        except OSError:
            job.fail(QWebEngineUrlRequestJob.Error.UrlNotFound)
            return
        buffer = QBuffer(job)
        buffer.setData(QByteArray(data))
        buffer.open(QIODevice.ReadOnly)
        job.reply(TYPES[os.path.splitext(path)[1].lower()], buffer)


def install():
    global _handler
    register()
    profile = QWebEngineProfile.defaultProfile()
    if profile.urlSchemeHandler(SCHEME) is None:
        _handler = AssetHandler()
        profile.installUrlSchemeHandler(SCHEME, _handler)


def url(name, query=""):
    result = QUrl("%s://%s/%s" % (SCHEME.decode(), HOST, name))
    if query:
        result.setQuery(query)
    return result
