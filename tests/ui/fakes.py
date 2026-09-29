"""Подставной поток проверки: те же сигналы, что у CheckWorker, узлы «проверяются» с задержкой."""
import threading
import time
import zlib

from PySide6.QtCore import QThread, Signal


class FakeWorker(QThread):
    log = Signal(str)
    mode_started = Signal(str, str)
    mode_failed = Signal(str, str)
    node_result = Signal(str, str, dict)
    mode_finished = Signal(str, dict)
    run_finished = Signal(dict)
    failed = Signal(str)
    delay = 0.0005
    ignore_stop = False
    value_for = None
    instances = []

    def __init__(self, targets, modes, adb, settings, connections=None, shift=0, tag="", mode_targets=None, raw=None):
        super().__init__()
        self.targets, self.modes, self.shift, self.tag = targets, modes, shift, tag
        self.mode_targets = mode_targets or {}
        self._stop = threading.Event()
        FakeWorker.instances.append(self)

    def stop(self):
        self._stop.set()

    @staticmethod
    def ok(mode_id, key):
        return zlib.crc32(("%s|%s" % (mode_id, key)).encode()) % 10 < 7

    def stopped(self):
        return self._stop.is_set() and not self.ignore_stop

    def run(self):
        run = {"started": time.strftime("%Y-%m-%d %H:%M:%S"), "modes": [],
               "targets": [{"location": t["location"], "key": t["key"], "sni": t.get("sni")} for t in self.targets]}
        for mode in self.modes:
            if self.stopped():
                break
            self.mode_started.emit(mode.id, "192.0.2.1")
            results = {}
            for target in self.mode_targets.get(mode.id, self.targets):
                if self.stopped():
                    break
                if mode.kind == "dc" and target.get("site_url"):
                    continue
                time.sleep(self.delay)
                if FakeWorker.value_for:
                    value = FakeWorker.value_for(mode.id, target["key"])
                else:
                    value = {"exit_ip": "198.51.100.1" if self.ok(mode.id, target["key"]) else "", "latency": 120}
                results[target["key"]] = value
                self.node_result.emit(mode.id, target["key"], value)
            run["modes"].append({**mode.to_dict(), "ip": "192.0.2.1", "results": results, "error": ""})
            self.mode_finished.emit(mode.id, results)
        run["finished"] = time.strftime("%Y-%m-%d %H:%M:%S")
        run["stopped"] = self._stop.is_set()
        self.run_finished.emit(run)
