"""Межпроцессный лок на телефон: два прогона (окно и консоль) не должны драться за один ADB.

Мы это уже ловили - параллельные run_check переключали SIM друг у друга. Занятость держит блокировка ОС
на открытом лок-файле (stand/oslock, как portlock), в самом файле - PID и время старта держателя для сообщений.
Взяли блокировку ОС - телефон наш, что бы ни было записано в файле: PID из файла учитывается только в старом
формате без метки старта (версии без блокировки ОС).
Только для прогонов, которые реально трогают телефон.
"""
import os
import threading

from . import oslock, storage

LOCK_PATH = os.path.join(storage.APP_DIR, "phone.lock")


def lock_path(serial=""):
    """Свой лок на каждый телефон: прогоны на разных телефонах друг другу не мешают,
    а два прогона на ОДНОМ - по-прежнему не пускаем. Без серийника - старое общее имя."""
    if not serial:
        return LOCK_PATH
    safe = "".join(ch for ch in serial if ch.isalnum() or ch in "-_.")
    return os.path.join(storage.APP_DIR, "phone-%s.lock" % safe)


def process_started(pid):
    """Метка старта процесса (число, одинаковое для одного процесса и разное для процессов с тем же PID)
    или None, если узнать нельзя."""
    return oslock.process_info(pid)[1]


def _read_lock(path):
    """(PID, метка старта или None) из лок-файла; старый формат - только PID."""
    try:
        with open(path, encoding="utf-8") as handle:
            parts = handle.read().split()
        pid = int(parts[0]) if parts else 0
        started = int(parts[1]) if len(parts) > 1 else None
        return pid, started
    except (OSError, ValueError):
        return 0, None


def owner_alive(pid, started=None):
    """Жив ли процесс, записанный в лок: PID есть и, если метка старта записана, это тот же процесс."""
    alive, current = oslock.process_info(pid)
    if not alive:
        return False
    return started is None or current is None or current == started


_held = {}
_guard = threading.Lock()


def _locked_by_other(path):
    """Файл держит блокировкой ОС другой процесс (или другой прогон этого процесса)."""
    try:
        handle = open(path, "a+", encoding="utf-8")
    except OSError:
        return False
    try:
        if oslock.lock(handle):
            oslock.unlock(handle)
            return False
        return True
    finally:
        handle.close()


def holder(serial=""):
    """PID держателя лока или 0. Держатель - процесс с блокировкой ОС на файле или (старый формат - только
    PID, без метки старта: так писали версии без блокировки ОС) живой процесс, записанный в файл. Свой процесс
    не считается: внутри процесса телефон стерегут acquire/release."""
    path = lock_path(serial)
    pid, started = _read_lock(path)
    if pid == os.getpid():
        return 0
    if pid and os.path.exists(path) and _locked_by_other(path):
        return pid
    if started is None and owner_alive(pid):
        return pid
    return 0


def acquire(serial=""):
    """True - заняли телефон, False - уже занят живым процессом или другим прогоном этого процесса.
    Занятость решает блокировка ОС на открытом файле: проверка и захват атомарны, упавший процесс
    отпускает телефон сам."""
    try:
        os.makedirs(storage.APP_DIR, exist_ok=True)
    except OSError:
        return False
    path = lock_path(serial)
    with _guard:
        if serial in _held:
            return False
        try:
            handle = open(path, "a+", encoding="utf-8")
        except OSError:
            return False
        if not oslock.lock(handle):
            handle.close()
            return False
        pid, started = _read_lock(path)
        if started is None and pid and pid != os.getpid() and owner_alive(pid):
            oslock.unlock(handle)
            handle.close()
            return False
        try:
            mark = process_started(os.getpid())
            handle.seek(0)
            handle.truncate()
            handle.write("%d %d" % (os.getpid(), mark) if mark is not None else str(os.getpid()))
            handle.flush()
        except OSError:
            oslock.unlock(handle)
            handle.close()
            return False
        _held[serial] = handle
        return True


def release(serial=""):
    """Отпустить телефон. Файл не удаляем (иначе другой процесс мог бы заблокировать уже удалённый
    файл, а третий - создать новый), только очищаем PID."""
    with _guard:
        handle = _held.pop(serial, None)
    if handle is None:
        return
    try:
        handle.seek(0)
        handle.truncate()
        handle.flush()
    except OSError:
        pass
    oslock.unlock(handle)
    handle.close()
