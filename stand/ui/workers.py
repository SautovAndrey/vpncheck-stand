"""Фоновые потоки Qt: разовая задача с результатом и опрос состояния телефона."""
import time

from PySide6.QtCore import QThread, Signal

from .. import errorlog
from ..i18n import t
from ..phone import PhoneControl, PhoneState

TRANSIENT = ("HTTP 502", "HTTP 503", "HTTP 504", "WinError 10054", "WinError 10061", "timed out",
             "Connection aborted", "Connection refused", "Remote end closed", "нет связи")


def _transient(text):
    return any(mark.lower() in str(text).lower() for mark in TRANSIENT)


class Task(QThread):
    done = Signal(object)
    error = Signal(str)
    progress = Signal(str)

    def __init__(self, fn, *args):
        super().__init__()
        self.fn, self.args = fn, args

    def run(self):
        try:
            self.done.emit(self.fn(*self.args))
        except (Exception, SystemExit) as exc:  # noqa: BLE001 - sys.exit из библиотеки (vpncheck) не должен ронять окно
            self.error.emit(str(exc) or t("задача прервана"))


def run_task(owner, fn, on_done, on_error, on_progress=None):
    """Запустить fn в потоке; owner.tasks держит ссылки, чтобы поток не собрал GC до финиша.
    Любая ошибка попадает и в файл ошибок стенда - чтобы было что править.

    fn может принимать один аргумент - функцию «сказать, где я сейчас»; подписка на прогресс
    делается ДО старта потока, иначе первые сообщения потерялись бы.
    """
    if on_progress is not None:
        task = Task(lambda: fn(task.progress.emit))
        task.progress.connect(on_progress)
    else:
        task = Task(fn)
    task.done.connect(on_done)
    task.error.connect(on_error)
    task.error.connect(lambda text: errorlog.record("задача", text) if not _transient(text) else None)
    task.finished.connect(lambda: owner.tasks.remove(task) if task in owner.tasks else None)
    owner.tasks.append(task)
    task.start()
    return task


class PhonePoller(QThread):
    """Опрос всех телефонов на кабеле. Отдаёт список [{"serial", "state"}] в порядке серийников -
    окно само выбирает, какой показывать в панели, а в «Что проверять» кладёт сети всех."""
    states = Signal(object)

    def __init__(self, adb, interval):
        super().__init__()
        self.adb = adb
        self.interval = interval
        self.slow = False
        self._running = True

    def stop(self):
        self._running = False

    def snapshot(self):
        from ..adb import Adb
        try:
            devices = self.adb.devices()
        except Exception as exc:  # noqa: BLE001
            return [{"serial": "", "state": PhoneState(error=str(exc))}]
        result = []
        for device in sorted(devices, key=lambda item: item["serial"]):
            try:
                state = PhoneControl(Adb(path=self.adb.path, serial=device["serial"])).read_state()
            except Exception as exc:  # noqa: BLE001
                state = PhoneState(serial=device["serial"], state=device["state"], error=str(exc))
            result.append({"serial": device["serial"], "state": state})
        return result

    def run(self):
        while self._running:
            self.states.emit(self.snapshot())
            waited = 0.0
            pause = self.interval * (3 if self.slow else 1)
            while self._running and waited < pause:
                time.sleep(0.25)
                waited += 0.25
