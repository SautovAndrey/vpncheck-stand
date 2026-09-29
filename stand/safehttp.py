"""HTTP-запросы с секретами в заголовках (токен панели, админ-токен сервера агентов).

urllib при редиректе переносит заголовки запроса на новый адрес - токен ушёл бы на чужой хост.
Здесь редирект в пределах того же адреса (схема, хост, порт) идёт как обычно, на другой адрес -
без заголовков доступа, а с https на http не идём вовсе.
"""
import urllib.error
import urllib.parse
import urllib.request

SAFE_HEADERS = {"user-agent", "accept", "accept-encoding", "accept-language"}


def _origin(url):
    parts = urllib.parse.urlsplit(url)
    port = parts.port or {"http": 80, "https": 443}.get(parts.scheme)
    return parts.scheme.lower(), (parts.hostname or "").lower(), port


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is None:
            return None
        old_scheme, _host, _port = _origin(req.full_url)
        if old_scheme == "https" and _origin(new.full_url)[0] != "https":
            raise urllib.error.HTTPError(newurl, code, "redirect from https to http refused", headers, fp)
        if _origin(new.full_url) != _origin(req.full_url):
            for name in list(new.headers):
                if name.lower() not in SAFE_HEADERS:
                    del new.headers[name]
            new.unredirected_hdrs.clear()
        return new


def urlopen(request, timeout=30, context=None, https_handler=None):
    """Как urllib.request.urlopen, но с SafeRedirect."""
    handlers = [SafeRedirect()]
    if https_handler is not None:
        handlers.append(https_handler)
    elif context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=context))
    return urllib.request.build_opener(*handlers).open(request, timeout=timeout)
