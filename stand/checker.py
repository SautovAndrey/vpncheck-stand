"""Прогон проверки: по очереди переключаем телефон в каждую сеть и гоняем все узлы.

Работает в отдельном потоке Qt, наружу отдаёт сигналы - интерфейс рисует по ним таблицу.
"""
import os
import threading
import time
from dataclasses import asdict, dataclass

from PySide6.QtCore import QThread, Signal

from . import errorlog, runlock
from .adb import AdbError
from .i18n import t
from .phone import PhoneControl, whitelist_verdict
from .xray import PhoneXray, node_value

WHITELIST_IP = "белые списки"


def unchecked_count(results):
    """Узлы колонки, не проверенные до конца (пропала сеть телефона или прогон остановлен): не живые и не мёртвые."""
    return sum(1 for value in (results or {}).values() if value.get("unchecked"))


def unchecked_note(results):
    """Сколько узлов колонки не проверено и почему; "" - таких нет."""
    stopped = sum(1 for value in (results or {}).values() if value.get("unchecked") == "stop")
    lost = unchecked_count(results) - stopped
    if not stopped:
        return t("не проверено %d (пропала сеть телефона)") % lost if lost else ""
    if not lost:
        return t("не проверено %d (прогон остановлен)") % stopped
    return t("не проверено %d (пропала сеть телефона - %d, прогон остановлен - %d)") % (lost + stopped, lost, stopped)


def run_target(target):
    """Узел в записи прогона. Адрес, порт и адрес сайта - чтобы «Почему мёртв» работал и по сохранённому прогону."""
    item = {"location": target["location"], "key": target["key"], "sni": target.get("sni")}
    item.update({key: target[key] for key in ("address", "port", "site_url") if target.get(key)})
    return item


@dataclass
class Mode:
    id: str
    kind: str
    label: str
    sub_id: int = -1
    slot: int = -1

    def to_dict(self):
        return asdict(self)


class CheckWorker(QThread):
    log = Signal(str)
    mode_started = Signal(str, str)
    mode_failed = Signal(str, str)
    node_result = Signal(str, str, dict)
    mode_finished = Signal(str, dict)
    run_finished = Signal(dict)
    failed = Signal(str)

    def __init__(self, targets, modes, adb, settings, connections=None, shift=0, tag="", mode_targets=None,
                 raw=None):
        super().__init__()
        self.targets = targets
        self.modes = modes
        self.adb = adb
        self.settings = settings
        self.connections = connections or {}
        self.shift = shift
        self.tag = tag
        self.mode_targets = mode_targets or {}
        self.raw = raw
        self._stop = threading.Event()
        self._auto_wifi_was = None
        self.whitelist_notes = {}

    def stop(self):
        self._stop.set()

    def stopping(self):
        return self._stop.is_set()

    def emit_log(self, text):
        prefix = "[%s] " % t(self.tag) if self.tag else ""
        self.log.emit(time.strftime("%H:%M:%S  ") + prefix + text)

    def targets_for(self, mode):
        return self.mode_targets.get(mode.id, self.targets)

    def lock_key(self):
        """Серийник телефона для его личного лока. Один телефон без серийника - узнаём сами."""
        if self.adb.serial:
            return self.adb.serial
        try:
            serials = self.adb.serials()
        except AdbError:
            return ""
        return serials[0] if len(serials) == 1 else ""

    def run(self):
        run = {"started": time.strftime("%Y-%m-%d %H:%M:%S"), "modes": [],
               "targets": [run_target(target) for target in self.targets]}
        phone = PhoneControl(self.adb, should_stop=self.stopping)
        xray = PhoneXray(self.adb, self.emit_log, shift=self.shift, should_stop=self.stopping)
        phone_modes = [m for m in self.modes if m.kind != "dc"]
        original = None
        locked = False
        key = self.lock_key() if phone_modes else ""
        try:
            if phone_modes:
                if not runlock.acquire(key):
                    msg = (t("телефон занят другим прогоном (PID %d) - дождитесь его окончания")
                           % (runlock.holder(key) or os.getpid()))
                    self.failed.emit(msg)
                    self.emit_log("✖ %s" % msg)
                    return
                locked = True
                original = phone.read_state()
                if not original.connected:
                    raise AdbError(original.error or t("телефон не подключён"))
                self._auto_wifi_was = phone.auto_wifi()
                if self._auto_wifi_was:
                    phone.set_auto_wifi(False)
                    self.emit_log(t("автовключение Wi-Fi отключено на время прогона"))
                xray.ensure_installed()
            for mode in self.modes:
                if self.stopping():
                    break
                record = mode.to_dict()
                record.update({"ip": "", "results": {}, "error": ""})
                try:
                    if mode.kind == "dc":
                        record["ip"] = str((self.connections.get("probe") or {}).get("host") or "")
                        record["results"] = self.run_dc(mode)
                    else:
                        record["ip"], record["results"] = self.run_phone_mode(mode, phone, xray)
                        if record["ip"] == WHITELIST_IP:
                            record["whitelist"] = True
                            record["whitelist_note"] = self.whitelist_notes.get(mode.id, "")
                except AdbError as exc:
                    record["error"] = str(exc)
                    self.mode_failed.emit(mode.id, str(exc))
                    self.emit_log("✖ %s: %s" % (mode.label, exc))
                except Exception as exc:  # noqa: BLE001 - любая ошибка режима не должна ронять прогон
                    errorlog.record("mode:%s" % mode.label, exc)
                    record["error"] = "%s: %s" % (type(exc).__name__, exc)
                    self.mode_failed.emit(mode.id, record["error"])
                    self.emit_log("✖ %s: %s" % (mode.label, record["error"]))
                run["modes"].append(record)
                self.mode_finished.emit(mode.id, record["results"])
            if self.settings.get("geo_check") and phone_modes and not self.stopping():
                run["geo"] = self.geo_probe(xray, run)
        except Exception as exc:  # noqa: BLE001
            errorlog.record("прогон", exc)
            self.failed.emit(str(exc))
            self.emit_log(t("✖ прогон прерван: %s") % exc)
        finally:
            try:
                if original is not None and self.settings.get("restore_network", True):
                    self.restore(phone, xray, original)
            finally:
                if locked:
                    runlock.release(key)
                run["finished"] = time.strftime("%Y-%m-%d %H:%M:%S")
                run["stopped"] = self.stopping()
                self.run_finished.emit(run)

    GEO_ECHOES = ["https://ifconfig.me/ip", "https://checkip.amazonaws.com", "https://api.ipify.org"]

    def probe_one_geo(self, xray, full, node_exit, phone_ip):
        """Одна локация: поднять полный конфиг узла и спросить эхо из белого списка.

        Напрямую - True, утечка в туннель - False, не ответило - None.
        """
        from .xray import fetch_via_socks
        try:
            xray.start_full(10950, full)
            seen = ""
            deadline = time.time() + 22
            while not seen and time.time() < deadline and not self.stopping():
                for url in self.GEO_ECHOES:
                    seen = fetch_via_socks(xray.local(10950), url, timeout=12)
                    if seen:
                        break
                if not seen:
                    time.sleep(3)
        finally:
            xray.stop_all()
        if seen and phone_ip and seen == phone_ip:
            return True, t("напрямую"), seen
        if seen and seen == node_exit:
            return False, t("утечка в VPN (эхо = IP узла)"), seen
        if seen:
            return False, t("через VPN (эхо %s)") % seen, seen
        return None, t("эхо не ответило"), ""

    def geo_probe(self, xray, run):
        """Живая проверка split-tunnel по КАЖДОЙ локации: применяет ли узел РФ-whitelist.
        Один живой узел на локацию: эхо из белого списка вышло IP телефона → напрямую; IP узла → утечка."""
        from . import subscription
        per_loc = {}
        for mode_record in run["modes"]:
            if mode_record.get("kind") == "dc":
                continue
            for key, value in (mode_record.get("results") or {}).items():
                if not value.get("exit_ip"):
                    continue
                target = next((item for item in self.targets if item["key"] == key), None)
                if target and target["location"] not in per_loc:
                    per_loc[target["location"]] = (target, value["exit_ip"])
        if not per_loc:
            self.emit_log(t("геомаршрут: нет живых узлов для проверки"))
            return {"available": False, "reason": t("нет живого узла")}
        if not xray.ensure_geodata():
            self.emit_log(t("геомаршрут: нет geoip.dat/geosite.dat в bin/ - конфиг с geosite-правилами не поднять"))
            return {"available": False, "reason": t("нет geo-файлов")}
        phone_ip = xray.direct_ip(port=10951)[0]
        self.emit_log(t("▶ геомаршрут: проверяю локации, локаций: %d (IP телефона %s)")
                      % (len(per_loc), phone_ip or "?"))
        per_location, ok = [], 0
        for location, (target, node_exit) in sorted(per_loc.items()):
            if self.stopping():
                break
            raw = self.raw if self.raw is not None else subscription.LAST_RAW
            full = subscription.full_config_for(raw, target["address"], target["port"])
            if not full:
                per_location.append({"location": location, "direct": None, "note": t("нет полного конфига")})
                continue
            expect_ru, _ = subscription.config_ru_direct(full)
            direct, note, seen = self.probe_one_geo(xray, full, node_exit, phone_ip)
            if direct:
                ok += 1
            per_location.append({"location": location, "direct": direct, "expect_ru": expect_ru,
                                 "node_ip": node_exit, "echo_seen": seen, "note": note})
            self.emit_log("  %s %s: %s" % ("✅" if direct else "⚠" if direct is False else "…", location, note))
        total = len(per_location)
        leaks = [r["location"] for r in per_location if r["direct"] is False]
        fails = [r["location"] for r in per_location if r["direct"] is None]
        if total and ok == total:
            summary = t("✅ РФ идёт напрямую на всех локациях, локаций: %d") % total
        elif leaks:
            summary = t("⚠ РФ утекает в VPN на: %s (напрямую %d из %d)") % (", ".join(leaks), ok, total)
        else:
            summary = t("напрямую %d из %d, не удалось проверить: %s") % (ok, total, ", ".join(fails) or "-")
        self.emit_log(t("геомаршрут ИТОГ: %s") % summary)
        return {"available": True, "per_location": per_location, "ok": ok, "total": total,
                "direct": total > 0 and ok == total, "phone_ip": phone_ip, "verdict": summary}


    def recover_sim_internet(self, phone, xray, mode, wait):
        """Мобильная сеть после смены SIM часто поднимается не сразу или залипает. Эскалация:
        1) передёрнуть мобильные данные, 2) полный сброс радио режимом полёта, 3) ещё раз с бОльшей паузой.
        Возвращает (ip, whitelist). Каждый шаг проверяет реальный выход в интернет."""
        steps = [
            (t("передёргиваю мобильные данные"), lambda: self._toggle_data(phone)),
            (t("сбрасываю радио (режим полёта)"), lambda: self._toggle_airplane(phone, mode)),
            (t("повторный сброс радио, жду дольше"), lambda: self._toggle_airplane(phone, mode)),
        ]
        for attempt, (label, action) in enumerate(steps):
            if self.stopping():
                break
            self.emit_log(t("  интернета нет - %s (попытка %d из %d)") % (label, attempt + 1, len(steps)))
            action()
            phone.wait_active_sub(mode.sub_id, timeout=wait)
            ip, whitelist = xray.wait_for_internet(timeout=wait + attempt * 20)
            if ip or whitelist:
                return ip, whitelist
        return "", False

    def _toggle_data(self, phone):
        phone.set_wifi(False)
        phone.set_mobile_data(False)
        time.sleep(3)
        phone.set_mobile_data(True)

    def _toggle_airplane(self, phone, mode):
        phone.set_airplane(True)
        time.sleep(4)
        phone.set_airplane(False)
        time.sleep(6)
        phone.set_wifi(False)
        phone.set_mobile_data(True)
        if phone.read_state().data_sub_id != mode.sub_id:
            phone.set_data_sim(mode.sub_id)

    def raise_if_stopped(self):
        """Стоп посреди подготовки сети: колонка не мерилась, а не «интернета нет»."""
        if self.stopping():
            raise AdbError(t("прогон остановлен"))

    def run_phone_mode(self, mode, phone, xray):
        self.emit_log(t("▶ %s: переключаю сеть") % mode.label)
        wait = int(self.settings.get("net_wait", 90))
        if mode.kind == "wifi":
            phone.set_airplane(False)
            phone.set_wifi(True)
            if not phone.wait_transport("wifi", timeout=30):
                self.emit_log(t("  Wi-Fi не стал сетью по умолчанию - временно глушу сотовую"))
                phone.set_mobile_data(False)
                phone.wait_transport("wifi", timeout=25)
        else:
            phone.set_airplane(False)
            phone.set_wifi(False)
            phone.set_mobile_data(True)
            state = phone.read_state()
            if state.data_sub_id != mode.sub_id:
                for attempt in range(3):
                    if phone.set_data_sim(mode.sub_id):
                        break
                    self.raise_if_stopped()
                    self.emit_log(t("  SIM не переключилась (попытка %d из 3), повторяю") % (attempt + 1))
                    time.sleep(3)
                else:
                    raise AdbError(t("SIM не переключилась на %s - переключите рукой в «Диспетчере SIM»")
                                   % mode.label)
            if not phone.wait_active_sub(mode.sub_id, timeout=wait):
                self.raise_if_stopped()
                raise AdbError(t("интернет не переехал на %s (идёт через другую SIM)") % mode.label)
        ip, whitelist = xray.wait_for_internet(timeout=wait)
        if not ip and not whitelist and mode.kind == "sim":
            ip, whitelist = self.recover_sim_internet(phone, xray, mode, wait)
        self.raise_if_stopped()
        if mode.kind == "sim":
            if not phone.wait_transport("cellular", timeout=20):
                self.emit_log(t("  трафик идёт не через сотовую - глушу Wi-Fi"))
                phone.set_wifi(False)
                if not phone.wait_transport("cellular", timeout=30):
                    self.raise_if_stopped()
                    raise AdbError(t("трафик идёт мимо %s (через Wi-Fi) - замер был бы неверным") % mode.label)
                ip, whitelist = xray.wait_for_internet(timeout=wait)
                self.raise_if_stopped()
        if not ip and whitelist:
            ip = WHITELIST_IP
            self.emit_log(t("  сеть в режиме белых списков: наружу пускает только на разрешённые сайты"))
            if mode.kind == "sim":
                balance = phone.sim_balance(mode.label.split(" · ")[0], mode.sub_id)
                self.whitelist_notes[mode.id] = whitelist_verdict(balance)
                self.emit_log("  %s" % self.whitelist_notes[mode.id])
            if self.settings.get("whitelist_mode", "skip") == "skip":
                self.emit_log(t("  колонку не проверяю (Настройки → «Если SIM в белых списках»)"))
                self.mode_started.emit(mode.id, ip)
                return ip, {}
            self.emit_log(t("  проверяю узлы: ищу обходы, которые пробивают белые списки"))
        elif not ip:
            raise AdbError(t("нет интернета в сети %s") % mode.label)
        else:
            self.emit_log(t("  сеть готова, IP %s") % ip)
        self.mode_started.emit(mode.id, ip)
        results = xray.check_targets(
            self.targets_for(mode), batch=int(self.settings.get("batch", 4)), wait=int(self.settings.get("wait", 7)),
            on_result=lambda key, value: self.node_result.emit(mode.id, key, value),
            should_stop=self.stopping, whitelist=ip == WHITELIST_IP)
        alive = sum(1 for v in results.values() if v.get("exit_ip"))
        share = self.targets_for(mode)
        part = t(" (своя часть общей колонки)") if mode.id in self.mode_targets else ""
        self.emit_log(t("  %s: живых %d из %d%s") % (mode.label, alive, len(share), part))
        note = unchecked_note(results)
        if note:
            self.emit_log("  %s: %s" % (mode.label, note))
        return ip, results

    def run_dc(self, mode):
        from . import dcprobe
        spec = self.connections.get("probe") or {}
        if not spec.get("host"):
            raise AdbError(t("сервер-пробник для ДЦ не настроен: Файл → Подключения"))
        self.emit_log(t("▶ %s: запускаю пробник %s") % (mode.label, spec.get("host")))
        self.mode_started.emit(mode.id, spec.get("host", ""))
        nodes = [target for target in self.targets if not target.get("site_url")]
        try:
            results = dcprobe.probe(spec, nodes, int(self.settings.get("dc_batch", 8)),
                                    int(self.settings.get("dc_wait", 13)), log=self.emit_log,
                                    should_stop=self.stopping) if nodes else {}
        except dcprobe.ProbeError as exc:
            raise AdbError(str(exc)) from exc
        for key, value in results.items():
            latency = value.get("latency")
            try:
                latency = int(float(latency) * 1000) if latency else None
            except ValueError:
                latency = None
            results[key] = node_value(value.get("exit_ip", ""), latency)
            self.node_result.emit(mode.id, key, results[key])
        alive = sum(1 for v in results.values() if v.get("exit_ip"))
        self.emit_log(t("  %s: живых %d из %d") % (mode.label, alive, len(nodes)))
        return results

    def restore(self, phone, xray, original):
        """Вернуть сеть как была до прогона: режим полёта, мобильные данные, Wi-Fi, SIM для данных."""
        phone.should_stop = xray.should_stop = lambda: False
        try:
            xray.stop_all()
            if self._auto_wifi_was is not None:
                phone.set_auto_wifi(self._auto_wifi_was)
            if not original.airplane:
                phone.set_airplane(False)
            phone.set_mobile_data(original.mobile_data_on)
            phone.set_wifi(original.wifi_on)
            if original.data_sub_id > 0:
                phone.set_data_sim(original.data_sub_id, verify_seconds=3)
            if original.airplane:
                phone.set_airplane(True)
            self.emit_log(t("сеть телефона возвращена как была (Wi-Fi %s)")
                          % (t("вкл") if original.wifi_on else t("выкл")))
        except AdbError as exc:
            self.emit_log(t("не удалось вернуть сеть: %s") % exc)
        except Exception as exc:  # noqa: BLE001 - возврат сети не должен оставлять прогон незавершённым
            errorlog.record("возврат сети", exc)
            self.emit_log(t("не удалось вернуть сеть: %s") % ("%s: %s" % (type(exc).__name__, exc)))
