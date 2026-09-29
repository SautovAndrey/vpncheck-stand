"""Межпроцессные окна локальных портов: у каждого прогона и действия окна - своё окно.

Окно N - это сдвиг xray.port_shift(N) для adb forward. Его держит открытый лок-файл
locks/ports-N.lock с блокировкой ОС за концом файла (oslock): процесс упал - ОС сама снимает
блокировку, перезапуск с тем же PID ничего не путает, а PID в файле остаётся читаемым.
Окно, консольный run_check и кнопки окна берут окна отсюда,
поэтому два прогона на разных телефонах никогда не делят один локальный порт.
"""
import os
import threading

from . import oslock, storage
from .xray import port_shift

WINDOWS = 16

_held = {}
_guard = threading.Lock()


def lock_dir():
    return os.path.join(storage.APP_DIR, "locks")


def lock_path(index):
    return os.path.join(lock_dir(), "ports-%d.lock" % index)


def acquire(first=0):
    """Номер свободного окна (оно занято за нами до release) или None, если все заняты."""
    try:
        os.makedirs(lock_dir(), exist_ok=True)
    except OSError:
        return None
    with _guard:
        for index in range(first, WINDOWS):
            if index in _held:
                continue
            try:
                handle = open(lock_path(index), "a+", encoding="utf-8")
            except OSError:
                continue
            if not oslock.lock(handle):
                handle.close()
                continue
            try:
                handle.seek(0)
                handle.truncate()
                handle.write("%-12d" % os.getpid())
                handle.flush()
            except OSError:
                pass
            _held[index] = handle
            return index
    return None


def release(index):
    if index is None:
        return
    with _guard:
        handle = _held.pop(index, None)
    if handle is None:
        return
    oslock.unlock(handle)
    handle.close()


def release_all(indexes):
    for index in list(indexes or ()):
        release(index)


def shift(index):
    """Сдвиг портов занятого окна. Без окна - ошибка: молча взятое окно 0 делило бы порты с чужим прогоном."""
    if index is None:
        raise ValueError("port window is not held")
    return port_shift(index)


def held():
    with _guard:
        return sorted(_held)
