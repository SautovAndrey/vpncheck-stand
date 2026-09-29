"""Запуск xray на телефоне по ADB и проверка выхода через проброшенный socks-порт.

Схема: xray слушает socks на 127.0.0.1:PORT телефона, `adb forward` отдаёт этот порт
на 127.0.0.1:PORT компьютера, а curl.exe с компьютера ходит через него. Весь трафик
уходит в сеть телефона (LTE или Wi-Fi), curl на самом телефоне не нужен.
"""
import hashlib
import ipaddress
import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

from .adb import CREATE_NO_WINDOW, AdbError
from .i18n import t

REMOTE_DIR = "/data/local/tmp/vpnstand"
REMOTE_XRAY = REMOTE_DIR + "/xray"
BIN_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bin")
LOCAL_XRAY = os.path.join(BIN_DIR, "xray")
CURL = (os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "curl.exe")
        if sys.platform == "win32" else "curl")
IP_URL = "https://api.ipify.org"
IP_URLS = (IP_URL, "https://checkip.amazonaws.com")
LATENCY_URL = "https://www.google.com/generate_204"
WHITELIST_URL = "http://ya.ru/"
PORT_LOW, PORT_HIGH = 10800, 10999
PHONE_PORT_STEP = PORT_HIGH - PORT_LOW + 1
CHECK_PORT, RETRY_PORT, CHECK_PORT_SPAN = 10810, 10910, 90
NET_PORT = 10800
NET_WAIT = 60
RETRY_ATTEMPTS = 3
UNCHECKED_NET = {"exit_ip": "", "latency": None, "unchecked": "net"}
UNCHECKED_STOP = {"exit_ip": "", "latency": None, "unchecked": "stop"}


def port_shift(index):
    """Сдвиг локальных портов для телефона №index (0, 1, 2…)."""
    return index * PHONE_PORT_STEP


def whitelist_reachable(port, timeout=8):
    """Российский сайт по HTTP отвечает, а зарубежное нет → SIM в белых списках (период охлаждения)."""
    code = curl(["-o", os.devnull, "-w", "%{http_code}", "-m", str(timeout),
                 "--socks5-hostname", "127.0.0.1:%d" % port, WHITELIST_URL], timeout + 3)
    return code.isdigit() and 200 <= int(code) < 400


def socks_config(port, outbound=None, extra=None):
    """Конфиг xray: socks-вход на port, узел (outbound) и связанные с ним outbound'ы (extra - цепочка
    dialerProxy/proxySettings), последним - прямой выход."""
    outbounds = [outbound] if outbound else []
    outbounds += list(extra or []) if outbound else []
    outbounds.append({"protocol": "freedom", "tag": "direct"})
    return {"log": {"loglevel": "warning"},
            "inbounds": [{"port": port, "listen": "127.0.0.1", "protocol": "socks",
                          "settings": {"udp": True}}],
            "outbounds": outbounds}


def curl_status(args, timeout=20):
    """(код выхода curl, вывод). Нет ответа за timeout или curl не запустился - код -1."""
    try:
        proc = subprocess.run([CURL, "-s"] + args, capture_output=True, text=True,
                              timeout=timeout, creationflags=CREATE_NO_WINDOW)
    except (subprocess.TimeoutExpired, OSError):
        return -1, ""
    return proc.returncode, proc.stdout.strip()


def curl(args, timeout=20):
    return curl_status(args, timeout)[1]


def exit_ip_via_socks(port, timeout=15, url=IP_URL):
    """IP выхода через socks или "": ответ сервиса с ошибкой (403, 429 - страница текста) узел живым не делает."""
    out = curl(["-f", "-m", str(timeout), "--socks5-hostname", "127.0.0.1:%d" % port, url], timeout + 3)
    try:
        return str(ipaddress.ip_address(out))
    except ValueError:
        return ""


def direct_ip_via_socks(port, timeout=8):
    """IP прямого выхода телефона по двум независимым сервисам: осечка одного - ещё не пропажа сети."""
    for url in IP_URLS:
        ip = exit_ip_via_socks(port, timeout, url)
        if ip:
            return ip
    return ""


def fetch_via_socks(port, url, timeout=15):
    """Запросить произвольный URL через socks телефона (для эха whoami - куда пойдёт РФ-трафик)."""
    return curl(["-m", str(timeout), "--socks5-hostname", "127.0.0.1:%d" % port, url], timeout + 3)


def timed_total(code, out):
    """Время запроса в мс из "http_code time_total" или None. curl печатает time_total и при таймауте (-m):
    такое число - предел ожидания, а не скорость узла, поэтому нужен нулевой код выхода и ответ 2xx/3xx."""
    status, _, total = out.partition(" ")
    if code != 0 or not status.isdigit() or not 200 <= int(status) < 400:
        return None
    try:
        return int(float(total) * 1000)
    except ValueError:
        return None


def latency_via_socks(port, timeout=15):
    """Задержка в мс; None - замер не уложился в timeout или оборвался (узел при этом может быть жив)."""
    code, out = curl_status(["-o", os.devnull, "-w", "%{http_code} %{time_total}", "-m", str(timeout),
                             "--socks5-hostname", "127.0.0.1:%d" % port, LATENCY_URL], timeout + 3)
    return timed_total(code, out)


def node_value(exit_ip, latency):
    """Результат узла: живой без замера задержки помечен slow - «медленно», а не «мёртв» и не «N мс»."""
    value = {"exit_ip": exit_ip, "latency": latency}
    if exit_ip and latency is None:
        value["slow"] = True
    return value


class PhoneXray:
    def __init__(self, adb, log=None, shift=0, should_stop=None):
        self.adb = adb
        self.whitelisted_now = False
        self.log = log or (lambda text: None)
        self.shift = shift
        self.should_stop = should_stop or (lambda: False)

    def local(self, port):
        """Локальный порт компьютера, через который виден socks-порт port на телефоне."""
        return port + self.shift

    def installed_version(self):
        return self.adb.shell("%s version 2>/dev/null | head -1" % REMOTE_XRAY).strip()

    def ensure_installed(self):
        if not os.path.exists(LOCAL_XRAY):
            raise AdbError(t("нет bin/xray (Android arm64) рядом с программой - "
                             "запустите python tools/fetch_binaries.py"))
        with open(LOCAL_XRAY, "rb") as handle:
            local_md5 = hashlib.md5(handle.read(), usedforsecurity=False).hexdigest()
        self.adb.shell("mkdir -p %s" % REMOTE_DIR)
        remote = self.adb.shell("md5sum %s 2>/dev/null" % REMOTE_XRAY).split()
        if remote and remote[0] == local_md5:
            return self.installed_version()
        self.log(t("заливаю xray на телефон (%.0f МБ)…") % (os.path.getsize(LOCAL_XRAY) / 1e6))
        self.adb.push(LOCAL_XRAY, REMOTE_XRAY)
        self.adb.shell("chmod 755 %s" % REMOTE_XRAY)
        version = self.installed_version()
        if "Xray" not in version:
            raise AdbError(t("xray на телефоне не запускается: %s") % (version or t("пустой ответ")))
        self.log(t("xray на телефоне: %s") % version)
        return version

    def ensure_geodata(self):
        """Залить geoip.dat/geosite.dat на телефон - без них xray не поднимет конфиг с geosite:*/geoip:* правилами.
        Нужно только для проверки геомаршрута. Возвращает True, если оба файла на месте."""
        ok = True
        for name in ("geoip.dat", "geosite.dat"):
            local = os.path.join(BIN_DIR, name)
            if not os.path.exists(local):
                ok = False
                continue
            with open(local, "rb") as handle:
                local_md5 = hashlib.md5(handle.read(), usedforsecurity=False).hexdigest()
            remote = self.adb.shell("md5sum %s/%s 2>/dev/null" % (REMOTE_DIR, name)).split()
            if remote and remote[0] == local_md5:
                continue
            self.log(t("заливаю %s на телефон (%.0f МБ)…") % (name, os.path.getsize(local) / 1e6))
            self.adb.push(local, "%s/%s" % (REMOTE_DIR, name))
        return ok

    def start(self, port, outbound=None, extra=None):
        self._launch(port, socks_config(port, outbound, extra))

    def start_full(self, port, config):
        """Запустить ПОЛНЫЙ конфиг из подписки (dns + routing + аутбаунды) - для проверки геомаршрута.
        Меняем только socks-вход на наш порт, остальное как у настоящего клиента."""
        cfg = json.loads(json.dumps(config))
        cfg["inbounds"] = [{"port": port, "listen": "127.0.0.1", "protocol": "socks",
                            "settings": {"udp": True}}]
        cfg["log"] = {"loglevel": "warning"}
        self._launch(port, cfg)

    def _launch(self, port, config):
        remote_cfg = "%s/cfg_%d.json" % (REMOTE_DIR, port)
        self.adb.run("shell", "cat > %s" % remote_cfg, input_text=json.dumps(config, ensure_ascii=False))
        self.adb.shell("cd %s && (nohup ./xray run -c cfg_%d.json > log_%d.txt 2>&1 &)"
                       % (REMOTE_DIR, port, port))
        self.adb.forward(self.local(port), port)

    def stop_all(self):
        self.adb.shell("pkill -f 'xray run -c cfg_' 2>/dev/null; sleep 0.3; "
                       "pkill -9 -f 'xray run -c cfg_' 2>/dev/null; true")
        self.adb.forward_remove_ports(self.local(PORT_LOW), self.local(PORT_HIGH))

    def direct_ip(self, port=10800, wait=4):
        """IP телефона в текущей сети: xray с прямым выходом, curl через проброс."""
        self.stop_all()
        self.start(port)
        time.sleep(wait)
        ip = exit_ip_via_socks(self.local(port), timeout=10)
        whitelist = False if ip else whitelist_reachable(self.local(port))
        self.stop_all()
        return ip, whitelist

    def wait_for_internet(self, timeout=45, port=10800):
        """(ip, whitelist): ip пустой и whitelist=True - сеть есть, но только белые списки."""
        deadline = time.time() + timeout
        self.stop_all()
        self.start(port)
        time.sleep(3)
        ip = ""
        whitelist = False
        while time.time() < deadline and not self.should_stop():
            ip = direct_ip_via_socks(self.local(port), timeout=8)
            if ip:
                break
            if whitelist_reachable(self.local(port)):
                whitelist = True
                if time.time() > deadline - timeout / 2:
                    break
            time.sleep(3)
        self.stop_all()
        return ip, whitelist

    def net_ok(self, whitelist=False, timeout=8, classify=True):
        """Прямой интернет телефона сейчас есть: ответил хоть один из двух сервисов IP. В колонке белых
        списков хватает ответа российского сайта. Отвечает только он - SIM ушла в белые списки (whitelisted_now)."""
        self.whitelisted_now = False
        self.stop_all()
        self.start(NET_PORT)
        time.sleep(3)
        try:
            port = self.local(NET_PORT)
            if whitelist:
                return whitelist_reachable(port, timeout) or bool(direct_ip_via_socks(port, timeout))
            if direct_ip_via_socks(port, timeout):
                return True
            self.whitelisted_now = classify and whitelist_reachable(port, timeout)
            return False
        finally:
            self.stop_all()

    def net_back(self, whitelist=False, timeout=NET_WAIT):
        """Интернета нет - ждать его до timeout секунд. True - вернулся."""
        if self.whitelisted_now:
            self.log(t("  SIM ушла в белые списки: зарубежное не открывается - жду до %d с") % timeout)
        else:
            self.log(t("  у телефона пропал интернет - жду до %d с") % timeout)
        ip, reachable = self.wait_for_internet(timeout=timeout, port=NET_PORT)
        back = bool(ip) or (whitelist and reachable)
        if back:
            self.log(t("  интернет вернулся - повторяю пачку"))
        elif reachable:
            self.log(t("  SIM в белых списках - неподтверждённые узлы не проверены"))
        else:
            self.log(t("  интернет не вернулся - неподтверждённые узлы не проверены"))
        return back

    def check_targets(self, targets, batch=4, wait=7, on_result=None, should_stop=None, whitelist=False):
        """Узлы пачками, не ответившие - ещё раз с большей паузой. «Мёртв» - только узел, не ответивший и в
        перепроверке при живой сети. Пропал интернет - unchecked="net", прогон остановлен до перепроверки -
        unchecked="stop"."""
        stop = should_stop or (lambda: False)
        results = {}
        for start in range(0, len(targets), batch):
            if stop():
                break
            chunk = targets[start:start + batch]
            results.update(self._check_chunk(chunk, CHECK_PORT, start, wait, on_result))
        retry = [target for target in targets
                 if target["key"] in results and not results[target["key"]].get("exit_ip")]
        if not retry:
            return results
        if stop():
            return self._mark(results, retry, UNCHECKED_STOP, on_result)
        self.log(t("перепроверяю с большей паузой, узлов: %d") % len(retry))
        lost = not self.net_ok(whitelist) and not self.net_back(whitelist)
        for start in range(0, len(retry), batch):
            if stop():
                self._mark(results, retry[start:], UNCHECKED_STOP, on_result)
                break
            chunk = retry[start:start + batch]
            if lost and start and self.net_ok(whitelist, timeout=5, classify=False):
                self.log(t("  интернет вернулся - продолжаю перепроверку"))
                lost = False
            if lost:
                second = {target["key"]: dict(UNCHECKED_NET) for target in chunk}
            else:
                second, lost = self._retry_chunk(chunk, start, wait + 6, on_result, whitelist, stop)
            results.update(second)
            if on_result:
                for key, value in second.items():
                    if not value.get("exit_ip"):
                        on_result(key, value)
        return results

    @staticmethod
    def _mark(results, targets, value, on_result):
        for target in targets:
            results[target["key"]] = dict(value)
            if on_result:
                on_result(target["key"], dict(value))
        return results

    def _retry_chunk(self, chunk, first_index, wait, on_result, whitelist, stop):
        """Пачка перепроверки: не ответившие узлы мертвы, если в этой же пачке кто-то ответил или прямой интернет
        телефона после неё есть. Пропал - ждём его и повторяем пачку. Возвращает (результаты, интернет не вернулся)."""
        outcome = {}
        pending = chunk
        for _attempt in range(RETRY_ATTEMPTS):
            second = self._check_chunk(pending, RETRY_PORT, first_index, wait, on_result, pending_mark=False)
            outcome.update(second)
            silent = [target for target in pending if not second[target["key"]].get("exit_ip")]
            if len(silent) < len(pending):
                return outcome, False
            pending = silent
            if stop():
                outcome.update({target["key"]: dict(UNCHECKED_STOP) for target in pending})
                return outcome, False
            if self.net_ok(whitelist):
                return outcome, False
            if not self.net_back(whitelist):
                mark = UNCHECKED_STOP if stop() else UNCHECKED_NET
                outcome.update({target["key"]: dict(mark) for target in pending})
                return outcome, mark is UNCHECKED_NET
        outcome.update({target["key"]: dict(UNCHECKED_NET) for target in pending})
        return outcome, False

    def _check_chunk(self, chunk, base_port, first_index, wait, on_result, pending_mark=True):
        self.stop_all()
        ports = []
        for offset, target in enumerate(chunk):
            port = base_port + (first_index + offset) % CHECK_PORT_SPAN
            self.start(port, target.get("outbound"), target.get("extra_outbounds"))
            ports.append((port, target))
        time.sleep(wait)
        outcome = {}

        def probe(port, target):
            if target.get("site_url"):
                code, out = curl_status(["-k", "-L", "-o", os.devnull, "-w", "%{http_code} %{time_total}",
                                         "-m", "12", "--socks5-hostname", "127.0.0.1:%d" % self.local(port),
                                         target["site_url"]], 16)
                status = out.partition(" ")[0]
                ok = status.isdigit() and 200 <= int(status) < 400
                return ("HTTP " + status if ok else ""), timed_total(code, out)
            ip = exit_ip_via_socks(self.local(port), timeout=12)
            return ip, (latency_via_socks(self.local(port), timeout=12) if ip else None)

        with ThreadPoolExecutor(max_workers=len(ports) or 1) as pool:
            probed = list(pool.map(lambda pair: probe(*pair), ports))
        for (_port, target), (ip, latency) in zip(ports, probed, strict=True):
            outcome[target["key"]] = node_value(ip, latency)
            if on_result:
                if ip:
                    on_result(target["key"], outcome[target["key"]])
                elif pending_mark:
                    on_result(target["key"], {"exit_ip": "", "latency": None, "retrying": True})
        self.stop_all()
        return outcome
