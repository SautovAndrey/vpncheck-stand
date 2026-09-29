"""Проверка узлов из дата-центра: свой Linux-сервер по SSH как точка отсчёта.

Колонка «ДЦ» отвечает на вопрос «жив ли узел вообще» - без мобильного оператора и домашнего
провайдера. Лучше всего сервер в той же стране, что и телефоны: тогда разница между ДЦ и
оператором показывает, что режет именно оператор.

Что нужно на сервере: python3 и curl (есть почти везде). xray стенд ставит сам в
/opt/vpncheck-stand - официальный релиз Xray-core с GitHub, контрольная сумма сверяется с
файлом .dgst из того же релиза. Можно указать уже стоящее ядро (xray_path).

Настройка - раздел «probe» в connections.json:
    {"host": "203.0.113.10", "port": 22, "user": "root", "key": "~/.ssh/id_ed25519",
     "password": "", "xray_path": "", "xray_version": "26.6.27", "host_key": "ssh-ed25519 AAAA…"}

host_key - ключ сервера, запомненный при первом входе (TOFU); при несовпадении стенд отказывается заходить.
"""
import base64
import json
import os
import re
import time

from .i18n import t

REMOTE_DIR = "/opt/vpncheck-stand"
XRAY_VERSION = "26.6.27"
RESULT_MARK = "VPNCHECK_RESULT "


class ProbeError(Exception):
    """Сервер-пробник недоступен или не готов - текст понятен человеку."""


class HostKeyMismatch(ProbeError):
    """Сервер предъявил не тот ключ, что был запомнен при первом входе."""


def host_key_line(key):
    """Ключ хоста paramiko → строка «тип base64», как в known_hosts."""
    return "%s %s" % (key.get_name(), key.get_base64())


class TofuPolicy:
    """Первый вход - запоминаем ключ сервера, дальше пускаем только с ним же."""

    def __init__(self, spec):
        self.spec = spec
        self.seen = ""

    def missing_host_key(self, _client, hostname, key):
        line = host_key_line(key)
        expected = (self.spec.get("host_key") or "").strip()
        if expected and expected != line:
            raise HostKeyMismatch(t("ключ SSH-сервера %s не совпадает с запомненным - возможна подмена сервера. "
                                    "Если сервер переустановили, сотрите у пробника адрес в «Подключениях», "
                                    "сохраните и введите заново") % hostname)
        self.seen = line


def remember_host_key(spec, line):
    """Записать ключ в spec и в connections.json, если там этот же пробник (адрес и порт)."""
    if not line or spec.get("host_key") == line:
        return
    spec["host_key"] = line
    from . import storage

    def change(data):
        saved = data.get("probe") or {}
        if saved.get("host") != spec.get("host") or int(saved.get("port") or 22) != int(spec.get("port") or 22):
            return False
        saved["host_key"] = line
        data["probe"] = saved
        return True
    storage.update_connections(change)


def connect(spec):
    """SSH к пробнику: ключ (key) или пароль (password). Ключ сервера проверяется по host_key (TOFU)."""
    try:
        import paramiko
    except ImportError as exc:
        raise ProbeError(t("для проверки из ДЦ нужен пакет paramiko: pip install paramiko")) from exc
    if not spec.get("host"):
        raise ProbeError(t("у пробника не указан адрес (host)"))
    client = paramiko.SSHClient()
    policy = TofuPolicy(spec)
    client.set_missing_host_key_policy(policy)
    kwargs = {"hostname": spec["host"], "port": int(spec.get("port") or 22), "username": spec.get("user") or "root",
              "timeout": 30, "banner_timeout": 40, "auth_timeout": 40, "allow_agent": False}
    if spec.get("key"):
        kwargs["key_filename"] = os.path.expanduser(spec["key"])
    else:
        kwargs["password"] = spec.get("password", "")
        kwargs["look_for_keys"] = False
    try:
        client.connect(**kwargs)
    except ProbeError:
        client.close()
        raise
    except Exception as exc:  # noqa: BLE001 - paramiko бросает разное, человеку нужна причина
        client.close()
        raise ProbeError(t("не удалось зайти на пробник %s: %s") % (spec["host"], exc)) from exc
    remember_host_key(spec, policy.seen)
    return client


def run(client, command, timeout=180, data=None):
    """Команда на пробнике. data (bytes) - на её stdin: большие списки узлов не влезают в аргумент
    командной строки (предел Linux на один аргумент - 128 КиБ)."""
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    if data is not None:
        stdin.write(data)
        stdin.flush()
        stdin.channel.shutdown_write()
    out = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace")
    return out, err, stdout.channel.recv_exit_status()


def shell_quote(text):
    return "'" + text.replace("'", "'\"'\"'") + "'"


INSTALL_SCRIPT = r'''
import hashlib, io, os, platform, sys, urllib.request, zipfile
version, target = sys.argv[1], sys.argv[2]
arch = {"x86_64": "64", "amd64": "64", "aarch64": "arm64-v8a", "arm64": "arm64-v8a",
        "armv7l": "arm32-v7a"}.get(platform.machine().lower())
if not arch:
    sys.exit("архитектура %s не поддерживается" % platform.machine())
base = "https://github.com/XTLS/Xray-core/releases/download/v%s/Xray-linux-%s.zip" % (version, arch)
blob = urllib.request.urlopen(base, timeout=120).read()
digest = urllib.request.urlopen(base + ".dgst", timeout=60).read().decode()
want = [l.split("=")[-1].strip().lower() for l in digest.splitlines() if l.upper().startswith("SHA2-256")]
if not want or hashlib.sha256(blob).hexdigest() != want[0]:
    sys.exit("контрольная сумма архива xray не совпала - не ставлю")
os.makedirs(os.path.dirname(target), exist_ok=True)
with zipfile.ZipFile(io.BytesIO(blob)) as archive, open(target, "wb") as out:
    out.write(archive.read("xray"))
os.chmod(target, 0o755)
print("ok")
'''

PROBE_SCRIPT = r'''
import glob, ipaddress, json, os, signal, socket, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor

os.umask(0o077)
RUN = os.environ["VPNCHECK_RUN"]
XRAY = os.environ["VPNCHECK_XRAY"]
for stale in glob.glob("/tmp/vpncheck_*"):
    try:
        if RUN not in os.path.basename(stale) and time.time() - os.path.getmtime(stale) > 6 * 3600:
            os.remove(stale)
    except OSError:
        pass
for own in (sys.argv[0], "/tmp/vpncheck_targets_%s.json" % RUN):
    if own.endswith(".json"):
        with open(own) as handle:
            targets = json.load(handle)
    try:
        os.remove(own)
    except OSError:
        pass
BATCH, WAIT = int(sys.argv[1]), int(sys.argv[2])
running = []
signal.signal(signal.SIGTERM, lambda *_: sys.exit(1))


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def listening(port, proc, seconds=3.0):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if proc.poll() is not None:
            return False
        with socket.socket() as sock:
            sock.settimeout(0.3)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.1)
    return proc.poll() is None


def launch(target):
    for _attempt in range(3):
        port = free_port()
        path = "/tmp/vpncheck_%s_%d.json" % (RUN, port)
        with open(path, "w") as handle:
            json.dump({"log": {"loglevel": "error"},
                       "inbounds": [{"port": port, "listen": "127.0.0.1", "protocol": "socks",
                                     "settings": {"udp": True}}],
                       "outbounds": [target["outbound"]] + list(target.get("extra_outbounds") or [])
                       + [{"protocol": "freedom", "tag": "direct"}]},
                      handle)
        proc = subprocess.Popen([XRAY, "run", "-c", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        item = (port, proc, path, target)
        running.append(item)
        if listening(port, proc):
            return item
        stop([item])
    return None


def start(batch):
    return [item for item in (launch(target) for target in batch) if item]


def stop(items):
    for item in items:
        _port, proc, path, _target = item
        proc.kill()
        proc.wait()
        if os.path.exists(path):
            os.remove(path)
        if item in running:
            running.remove(item)


def probe_one(item):
    port, _proc, _path, target = item
    socks = "127.0.0.1:%d" % port
    ip = subprocess.run(["curl", "-s", "-f", "-m", "15", "--socks5-hostname", socks, "https://api.ipify.org"],
                        capture_output=True, text=True).stdout.strip()
    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        ip = ""
    latency = ""
    if ip:
        timed = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{time_total}", "-m", "15",
                                "--socks5-hostname", socks, "https://www.google.com/generate_204"],
                               capture_output=True, text=True)
        latency = timed.stdout.strip() if timed.returncode == 0 else ""
    return target["key"], {"exit_ip": ip, "latency": latency}


def collect(started, wait):
    if not started:
        return {}
    time.sleep(wait)
    with ThreadPoolExecutor(max_workers=max(1, len(started))) as pool:
        outcome = dict(pool.map(probe_one, started))
    stop(started)
    return outcome


try:
    results = {}
    for first in range(0, len(targets), BATCH):
        results.update(collect(start(targets[first:first + BATCH]), WAIT))
    retry = [target for target in targets if not results.get(target["key"], {}).get("exit_ip")]
    for first in range(0, len(retry), BATCH):
        for key, value in collect(start(retry[first:first + BATCH]), WAIT + 7).items():
            if value.get("exit_ip"):
                results[key] = value
    print("VPNCHECK_RESULT " + json.dumps(results))
finally:
    stop(list(running))
    for path in glob.glob("/tmp/vpncheck_%s_*.json" % RUN):
        try:
            os.remove(path)
        except OSError:
            pass
'''


def cleanup_command(run_id):
    """Убить скрипт прогона и его xray и стереть файлы прогона на пробнике."""
    return ("pkill -f '[/]tmp/vpncheck_probe_{0}[.]py'; pkill -f '[/]tmp/vpncheck_{0}_'; "
            "rm -f /tmp/vpncheck_targets_{0}.json /tmp/vpncheck_probe_{0}.py /tmp/vpncheck_out_{0}.txt "
            "/tmp/vpncheck_{0}_*.json; true").format(run_id)


def ensure_xray(client, spec, log=None):
    """Путь к рабочему xray на сервере; при необходимости ставит его. Бросает ProbeError."""
    say = log or (lambda text: None)
    out, _err, _code = run(client, "command -v python3 >/dev/null && command -v curl >/dev/null && echo ok", 30)
    if "ok" not in out:
        raise ProbeError(t("на пробнике нужны python3 и curl"))
    custom = (spec.get("xray_path") or "").strip()
    if custom:
        out, _err, _code = run(client, "%s version 2>&1 | head -1" % shell_quote(custom), 30)
        if "Xray" in out:
            return custom
        raise ProbeError(t("на пробнике нет рабочего xray по пути %s") % custom)
    version = spec.get("xray_version") or XRAY_VERSION
    path = "%s/xray-%s/xray" % (REMOTE_DIR, version)
    out, _err, _code = run(client, "%s version 2>&1 | head -1" % shell_quote(path), 30)
    if "Xray" in out:
        return path
    say(t("ставлю xray %s на пробник (с GitHub, со сверкой контрольной суммы)…") % version)
    script = base64.b64encode(INSTALL_SCRIPT.encode()).decode()
    out, err, code = run(client, "echo %s | base64 -d | python3 - %s %s"
                          % (script, shell_quote(version), shell_quote(path)), 300)
    if code != 0 or "ok" not in out:
        raise ProbeError(t("не удалось поставить xray на пробник: %s") % (err or out).strip()[-300:])
    return path


def probe_target(target):
    """Узел для пробника: ключ, outbound и связанные outbound'ы (цепочка dialerProxy), если есть."""
    item = {"key": target["key"], "outbound": target["outbound"]}
    if target.get("extra_outbounds"):
        item["extra_outbounds"] = target["extra_outbounds"]
    return item


def probe(spec, targets, batch=8, wait=13, log=None, should_stop=None):
    """Проверить узлы с сервера. targets - [{"key", "outbound"}]. Результат: {key: {"exit_ip", "latency"}}.

    Каждый прогон со своим префиксом файлов и свободными портами - параллельные проверки не мешают
    друг другу. should_stop() → True прерывает ожидание; скрипт, его xray и файлы на пробнике убираются всегда.
    """
    stop = should_stop or (lambda: False)
    client = connect(spec)
    run_id = ""
    try:
        xray = ensure_xray(client, spec, log)
        run_id = "%d" % int(time.time() * 1000 % 10 ** 9)
        payload = json.dumps([probe_target(target) for target in targets], ensure_ascii=False).encode("utf-8")
        run(client, "umask 077; cat > /tmp/vpncheck_targets_%s.json" % run_id, data=payload)
        run(client, "umask 077; cat > /tmp/vpncheck_probe_%s.py" % run_id, data=PROBE_SCRIPT.encode("utf-8"))
        run(client, "umask 077; rm -f /tmp/vpncheck_out_%s.txt; VPNCHECK_RUN=%s VPNCHECK_XRAY=%s nohup python3 "
                    "/tmp/vpncheck_probe_%s.py %d %d > /tmp/vpncheck_out_%s.txt 2>&1 &"
                    % (run_id, run_id, shell_quote(xray), run_id, batch, wait, run_id))
        deadline = time.time() + 90 + len(targets) * (wait + 8)
        while time.time() < deadline:
            for _ in range(10):
                if stop():
                    raise ProbeError(t("проверка из ДЦ остановлена"))
                time.sleep(1)
            out, _err, _code = run(client, "cat /tmp/vpncheck_out_%s.txt 2>/dev/null" % run_id)
            if RESULT_MARK in out:
                return json.loads(out.split(RESULT_MARK, 1)[1].strip().splitlines()[0])
            if "Traceback" in out:
                raise ProbeError(t("проверка на пробнике упала: %s") % out.strip()[-300:])
        raise ProbeError(t("пробник не ответил вовремя"))
    finally:
        if run_id:
            try:
                run(client, cleanup_command(run_id), 30)
            except Exception:  # noqa: BLE001
                pass
        client.close()


DIAGNOSE_SCRIPT = r"""
import json, socket, ssl, sys
from concurrent.futures import ThreadPoolExecutor

def check(node):
    out = {"key": node["key"], "ip": "", "tcp": "", "tls": ""}
    try:
        found = socket.getaddrinfo(node["address"], node["port"], socket.AF_UNSPEC, socket.SOCK_STREAM)
        found.sort(key=lambda item: item[0] != socket.AF_INET)
        out["ip"] = found[0][4][0]
    except Exception as exc:
        out["tcp"] = "dns: %s" % exc.__class__.__name__
        return out
    try:
        sock = socket.create_connection((out["ip"], int(node["port"])), timeout=6)
        out["tcp"] = "ok"
    except socket.timeout:
        out["tcp"] = "timeout"
        return out
    except ConnectionRefusedError:
        out["tcp"] = "refused"
        return out
    except OSError as exc:
        out["tcp"] = "error: %s" % (exc.strerror or exc.__class__.__name__)
        return out
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock.settimeout(8)
        with ctx.wrap_socket(sock, server_hostname=node.get("sni") or node["address"]):
            out["tls"] = "ok"
    except socket.timeout:
        out["tls"] = "timeout"
    except (ConnectionResetError, ssl.SSLEOFError, ssl.SSLZeroReturnError):
        out["tls"] = "reset"
    except Exception as exc:
        out["tls"] = "error: %s" % exc.__class__.__name__
    finally:
        sock.close()
    return out

nodes = json.load(sys.stdin)
with ThreadPoolExecutor(max_workers=16) as pool:
    print("VPNCHECK_RESULT " + json.dumps({r["key"]: r for r in pool.map(check, nodes)}))
"""


KEY_RE = re.compile(r"^(.*):(\d+)(?: · .*)?$")


def is_site(target):
    """Псевдо-узел «сайт без VPN» (subscription.site_targets): в диагноз узлов он не идёт."""
    return bool(target.get("site_url")) or str(target.get("key") or "").startswith("🌐")


def node_address(target):
    """(адрес, порт) узла: из полей цели, а у сохранённого или склеенного прогона их нет - из ключа
    «адрес:порт» или «адрес:порт · SNI» (после dedupe_keys). Не разобрать - None."""
    address, port = target.get("address"), target.get("port")
    if address and port:
        try:
            return str(address), int(port)
        except (TypeError, ValueError):
            return None
    match = KEY_RE.match(str(target.get("key") or ""))
    if not match or not match.group(1):
        return None
    return match.group(1).strip("[]"), int(match.group(2))


def diagnose(spec, targets):
    """{key: {"ip", "tcp", "tls"}} по мёртвым узлам - с пробника, то есть из той же страны, что и ДЦ-колонка.
    Сайты и цели, у которых не понять адрес и порт, пропускаются."""
    nodes = []
    for target in targets:
        found = None if is_site(target) else node_address(target)
        if found:
            nodes.append({"key": target["key"], "address": found[0], "port": found[1],
                          "sni": target.get("sni") or ""})
    if not nodes:
        return {}
    client = connect(spec)
    try:
        script = base64.b64encode(DIAGNOSE_SCRIPT.encode()).decode()
        out, err, _code = run(client, "python3 -c %s %s"
                              % (shell_quote("import base64, sys; exec(base64.b64decode(sys.argv[1]))"), script),
                              60 + len(nodes) * 2, data=json.dumps(nodes).encode("utf-8"))
    finally:
        client.close()
    if RESULT_MARK not in out:
        raise ProbeError(t("диагноз на пробнике не удался: %s") % (err or out).strip()[-200:])
    return json.loads(out.split(RESULT_MARK, 1)[1].strip().splitlines()[0])


def dead_everywhere(run_record):
    """Узлы, мёртвые во всех рабочих колонках прогона, включая ДЦ, - кандидаты на диагноз.

    Колонки в белых списках и с ошибкой не в счёт: там узел мёртв не по своей вине. Узел, не проверенный
    хоть в одной колонке из-за пропавшей сети телефона, тоже не диагностируем. Без колонки
    ДЦ диагноз не ставим - «мёртв у операторов» ещё не значит «мёртв вообще».
    """
    modes = [mode for mode in run_record.get("modes", []) if not mode.get("error") and not mode.get("whitelist")
             and mode.get("results")]
    if not any(mode.get("kind") == "dc" for mode in modes):
        return []
    return [target for target in run_record.get("targets", [])
            if not is_site(target) and all(dead_in(mode, target["key"]) for mode in modes)]


def dead_in(mode, key):
    """Узел в колонке проверен и не ответил. Нет в результатах колонки (кусок упал, прогон остановлен) или
    не проверен до конца (пропала сеть телефона, стоп до перепроверки) - не мёртв."""
    results = mode["results"]
    return key in results and not results[key].get("exit_ip") and not results[key].get("unchecked")


def diagnose_run(spec, run_record):
    """Диагноз по мёртвым везде узлам прогона: {key: {ip, tcp, tls, verdict, detail}}."""
    checks = diagnose(spec, dead_everywhere(run_record))
    for check in checks.values():
        check["verdict"], check["detail"] = verdict(check)
    return checks


def verdict(check):
    """Короткий вердикт и пояснение по результату diagnose() для одного узла."""
    tcp, tls = check.get("tcp", ""), check.get("tls", "")
    if tcp.startswith("dns"):
        return "имя не разрешается", t("DNS не отдаёт адрес узла - проверьте домен")
    if tcp != "ok":
        return ("не достучаться из РФ",
                t("TCP до %s не открывается (%s): адрес выжжен в РФ или нода выключена. Отличить можно "
                  "только проверкой из-за границы") % (check.get("ip") or "?", tcp or "?"))
    if tls != "ok":
        return ("рвут рукопожатие",
                t("TCP открывается, но TLS с SNI узла обрывается (%s): блок по SNI/отпечатку или нода "
                  "не слушает TLS на этом порту") % (tls or "?"))
    return ("ключ или DPI",
            t("сеть и TLS в порядке, а VPN не проходит: нода не приняла ключ (учётка не доехала, узел "
              "не в скваде) или DPI режет уже после рукопожатия"))


def display(verdict_text):
    """Вердикт для показа. В записи прогона хранится русский текст (по нему считают и красят),
    переводим только при выводе: «имя не разрешается», «не достучаться из РФ», «рвут рукопожатие», «ключ или DPI»."""
    return t(verdict_text)
