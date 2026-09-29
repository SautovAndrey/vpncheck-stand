"""Push через Firebase Cloud Messaging (HTTP v1) без google-auth: JWT сервисного аккаунта подписываем сами.

Файл сервисного аккаунта - service-account.json в каталоге данных VPNAGENT_DATA (по умолчанию рядом;
из консоли Firebase: Project settings → Service accounts → Generate new private key). Без него send() тихо
возвращает 0.
"""
import base64
import json
import os
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, wait

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("VPNAGENT_DATA") or HERE
SA_PATH = os.path.join(DATA_DIR, "service-account.json")
_token = {"value": "", "expires": 0.0}


def _b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def project_id():
    if not os.path.exists(SA_PATH):
        return ""
    with open(SA_PATH, encoding="utf-8") as handle:
        return json.load(handle).get("project_id", "")


def access_token():
    """OAuth2-токен по JWT сервисного аккаунта; кэш на 50 минут."""
    if _token["value"] and time.time() < _token["expires"]:
        return _token["value"]
    if not os.path.exists(SA_PATH):
        return ""
    with open(SA_PATH, encoding="utf-8") as handle:
        account = json.load(handle)
    now = int(time.time())
    header = _b64(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    claims = _b64(json.dumps({"iss": account["client_email"],
                              "scope": "https://www.googleapis.com/auth/firebase.messaging",
                              "aud": account["token_uri"], "iat": now, "exp": now + 3600}).encode())
    key = serialization.load_pem_private_key(account["private_key"].encode(), password=None)
    signature = key.sign(("%s.%s" % (header, claims)).encode(), padding.PKCS1v15(), hashes.SHA256())
    assertion = "%s.%s.%s" % (header, claims, _b64(signature))
    body = ("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=" + assertion).encode()
    request = urllib.request.Request(account["token_uri"], data=body,
                                     headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(request, timeout=15) as response:
        data = json.load(response)
    _token["value"] = data["access_token"]
    _token["expires"] = time.time() + int(data.get("expires_in", 3600)) - 600
    return _token["value"]


SEND_WORKERS = 8
SEND_DEADLINE = 40


def dead_token(code, body):
    """FCM отверг сам токен: удалён (404/410, UNREGISTERED) или это вообще не токен (400 INVALID_ARGUMENT
    про registration token) - такие из базы убираем, иначе мусор копится и тормозит рассылку."""
    text = body.decode("utf-8", "replace") if isinstance(body, bytes) else str(body or "")
    if code in (404, 410) or "UNREGISTERED" in text:
        return True
    return code == 400 and "INVALID_ARGUMENT" in text and "token" in text.lower()


def _send_one(project, bearer, token, data):
    """(отправлен, умер) для одного токена."""
    message = {"message": {"token": token, "data": data, "android": {"priority": "high", "ttl": "900s"}}}
    request = urllib.request.Request("https://fcm.googleapis.com/v1/projects/%s/messages:send" % project,
                                     data=json.dumps(message).encode(),
                                     headers={"Authorization": "Bearer " + bearer,
                                              "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=15):
            return True, False
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read()
        except Exception:  # noqa: BLE001
            body = b""
        return False, dead_token(exc.code, body)
    except Exception:  # noqa: BLE001
        return False, False


def send(tokens, action):
    """Разослать data-push с высоким приоритетом: параллельно (SEND_WORKERS) и не дольше SEND_DEADLINE
    на всю рассылку. Возвращает (отправлено, список умерших токенов)."""
    project = project_id()
    if not project or not tokens:
        return 0, []
    try:
        bearer = access_token()
    except Exception:  # noqa: BLE001 - нет доступа к Google с сервера: просто без пушей
        return 0, []
    data = {"action": action, "ts": str(int(time.time()))}
    pool = ThreadPoolExecutor(max_workers=SEND_WORKERS, thread_name_prefix="fcm")
    futures = {pool.submit(_send_one, project, bearer, token, data): token for token in tokens}
    done, _pending = wait(futures, timeout=SEND_DEADLINE)
    pool.shutdown(wait=False, cancel_futures=True)
    sent, dead = 0, []
    for future in done:
        ok, gone = future.result()
        sent += ok
        if gone:
            dead.append(futures[future])
    return sent, dead
