"""Журнал ошибок стенда: %APPDATA%\\VPNCheckStand\\errors.log (одна запись - JSON-строка).

Сюда попадают ошибки фоновых задач, прогонов и необработанные исключения - чтобы центр показывал их
рядом с ошибками агентов и было что править.
"""
import json
import os
import sys
import threading
import time
import traceback

from .storage import APP_DIR

LOG_PATH = os.path.join(APP_DIR, "errors.log")
MAX_LINES = 500
_lock = threading.Lock()


def record(kind, error):
    """error - исключение или строка; для исключения сохраняется трассировка."""
    text = "".join(traceback.format_exception(error)) if isinstance(error, BaseException) else str(error)
    entry = {"ts": time.time(), "kind": str(kind)[:40], "text": text[-4000:]}
    with _lock:
        try:
            os.makedirs(APP_DIR, exist_ok=True)
            with open(LOG_PATH, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except OSError:
            pass
        _trim()


def _trim():
    try:
        with open(LOG_PATH, encoding="utf-8") as handle:
            lines = handle.readlines()
        if len(lines) > MAX_LINES:
            with open(LOG_PATH, "w", encoding="utf-8") as handle:
                handle.writelines(lines[-MAX_LINES:])
    except OSError:
        pass


def read(limit=300):
    if not os.path.exists(LOG_PATH):
        return []
    entries = []
    try:
        with open(LOG_PATH, encoding="utf-8", errors="replace") as handle:
            for line in handle:
                try:
                    entries.append(json.loads(line))
                except ValueError:
                    continue
    except OSError:
        return []
    return entries[-limit:]


def clear():
    try:
        os.remove(LOG_PATH)
    except OSError:
        pass


def install_excepthook():
    previous = sys.excepthook

    def hook(exc_type, exc, tb):
        record("падение", exc)
        previous(exc_type, exc, tb)
    sys.excepthook = hook

    prev_thread = threading.excepthook

    def thread_hook(args):
        record("падение потока", args.exc_value or args.exc_type)
        prev_thread(args)
    threading.excepthook = thread_hook
