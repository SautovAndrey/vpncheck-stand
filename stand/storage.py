"""Настройки, подключения и история прогонов: %APPDATA%\\VPNCheckStand (Windows) или ~/VPNCheckStand.

settings.json    - вид окна и параметры прогона, ничего секретного;
connections.json - панели Remnawave (адрес и API-токен) и сервер-пробник для ДЦ (SSH).
                   Секреты живут только здесь, вне папки программы, и в репозиторий не попадают.
"""
import contextlib
import json
import os
import threading
import time

from .i18n import t

APP_DIR = os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~"), "VPNCheckStand")
RUNS_DIR = os.path.join(APP_DIR, "runs")
SETTINGS_PATH = os.path.join(APP_DIR, "settings.json")
CONNECTIONS_PATH = os.path.join(APP_DIR, "connections.json")

DEFAULTS = {
    "batch": 4,
    "wait": 7,
    "net_wait": 90,
    "dc_batch": 16,
    "dc_wait": 13,
    "restore_network": True,
    "only_443": True,
    "whitelist_mode": "skip",
    "panel": "",
    "squad": "",
    "url": "",
    "file": "",
    "poll_seconds": 5,
    "log_visible": True,
    "window": None,
    "window_maximized": False,
    "sim_numbers": {},
    "language": "auto",
}


def load_settings():
    data = dict(DEFAULTS)
    if os.path.exists(SETTINGS_PATH):
        try:
            with open(SETTINGS_PATH, encoding="utf-8") as handle:
                data.update(json.load(handle))
        except (ValueError, OSError):
            pass
    return data


_connections_lock = threading.RLock()


def write_json(path, data, indent=2, mode=None):
    """Атомарная запись: во временный файл рядом, затем подмена. Оборванная запись (os._exit, выключение)
    оставляет прежний файл целым, а не пустой или полуфайл. На Windows подмену открытого кем-то файла
    ОС ненадолго запрещает - тогда несколько повторов."""
    folder = os.path.dirname(path)
    os.makedirs(folder, exist_ok=True)
    tmp = "%s.%d.%d.tmp" % (path, os.getpid(), threading.get_ident())
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode or 0o666)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=indent)
            handle.flush()
            os.fsync(handle.fileno())
        if mode is not None:
            with contextlib.suppress(OSError):
                os.chmod(tmp, mode)
        for attempt in range(20):
            try:
                os.replace(tmp, path)
                break
            except PermissionError:
                if attempt == 19:
                    raise
                time.sleep(0.05)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.remove(tmp)


def save_settings(data):
    write_json(SETTINGS_PATH, data)


def load_connections():
    """{"panels": {имя: {"url", "token", "headers", "verify_tls"}}, "probe": {"host", …}}."""
    data = {"panels": {}, "probe": {}}
    if os.path.exists(CONNECTIONS_PATH):
        try:
            with open(CONNECTIONS_PATH, encoding="utf-8") as handle:
                loaded = json.load(handle)
            data["panels"] = dict(loaded.get("panels") or {})
            data["probe"] = dict(loaded.get("probe") or {})
        except (ValueError, OSError):
            pass
    return data


def save_connections(data):
    """Токены и пароли - только владельцу файла (на Windows права наследуются от профиля)."""
    clean = {"panels": dict(data.get("panels") or {}), "probe": dict(data.get("probe") or {})}
    with _connections_lock:
        write_json(CONNECTIONS_PATH, clean, mode=0o600)


def update_connections(change):
    """Прочитать-изменить-записать connections.json под замком: поток прогона (ключ пробника) и окно
    не затирают правки друг друга. change(data) правит data на месте; вернуть False - не сохранять."""
    with _connections_lock:
        data = load_connections()
        if change(data) is not False:
            save_connections(data)
        return data


def has_probe(connections):
    """Настроен ли сервер-пробник для колонки «ДЦ»."""
    return bool((connections or {}).get("probe", {}).get("host"))


def save_run(run):
    """Новый файл прогона. Имя занимается атомарно (O_EXCL): окно и консоль, закончившие в одну
    секунду, не пишут в один файл; содержимое - через write_json."""
    os.makedirs(RUNS_DIR, exist_ok=True)
    stamp = time.strftime("%Y-%m-%d_%H-%M-%S")
    suffix = 1
    while True:
        path = os.path.join(RUNS_DIR, (stamp if suffix == 1 else "%s_%d" % (stamp, suffix)) + ".json")
        try:
            os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL))
            break
        except FileExistsError:
            suffix += 1
    write_json(path, run, indent=1)
    return path


def update_run(path, run):
    """Дописать в уже сохранённый прогон (например, диагноз мёртвых узлов, который приходит позже)."""
    write_json(path, run, indent=1)


def list_runs(limit=50):
    if not os.path.isdir(RUNS_DIR):
        return []
    names = sorted((n for n in os.listdir(RUNS_DIR) if n.endswith(".json")), reverse=True)
    runs = []
    for name in names[:limit]:
        path = os.path.join(RUNS_DIR, name)
        try:
            with open(path, encoding="utf-8") as handle:
                run = json.load(handle)
        except (ValueError, OSError):
            continue
        runs.append({"path": path, "started": run.get("started", name), "run": run,
                     "label": run_label(run)})
    return runs


def source_name(panel):
    """Имя панели для показа; у подписки там код источника (url, file, старое «подписка») - его словами."""
    names = {"url": t("URL подписки"), "file": t("Файл"), "подписка": t("подписка")}
    return names.get(panel, panel)


def run_label(run):
    parts = []
    total = len(run.get("targets", []))
    for mode in run.get("modes", []):
        results = mode.get("results", {})
        alive = sum(1 for v in results.values() if v.get("exit_ip"))
        unchecked = sum(1 for v in results.values() if v.get("unchecked"))
        parts.append("%s %d/%d%s" % (mode.get("label", mode.get("id")), alive, total,
                                     (" ?%d" % unchecked) if unchecked else ""))
    prefix = ""
    if run.get("panel"):
        prefix = "%s/%s · " % (source_name(run["panel"]), run.get("squad", ""))
    return "%s%s - %s" % (prefix, run.get("started", "?"), ", ".join(parts) or t("пусто"))
