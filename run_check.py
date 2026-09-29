#!/usr/bin/env python3
"""Прогон из консоли, без окна - тот же движок, результат ложится в историю программы.

    python run_check.py mypanel Default                    # все сети: ДЦ, SIM-карты, Wi-Fi
    python run_check.py mypanel Default --modes dc,wifi    # только часть
    python run_check.py mypanel Default --modes sim2,mts   # SIM во втором слоте и SIM МТС
    python run_check.py --list-modes                       # какие сети есть сейчас
    python run_check.py mypanel Default --location Германия  # фильтр по локации
    python run_check.py --url https://sub.example.com/abc  # чужая подписка по ссылке

Панели и сервер-пробник для колонки ДЦ настраиваются в окне: Файл → Подключения
(хранятся в connections.json рядом с настройками, вне папки программы).

Несколько телефонов на кабеле гоняются одновременно, отчёт - один (колонки «MTS RUS · A075F»).
    python run_check.py mypanel Default --phone A075F      # только этот телефон (тег или серийник)
"""
import argparse
import contextlib
import os
import signal
import sys
import time
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from PySide6.QtCore import QCoreApplication, QTimer  # noqa: E402

from stand import dcprobe, multiphone, portlock, storage, subscription  # noqa: E402
from stand.adb import Adb, AdbError  # noqa: E402
from stand.checker import unchecked_note  # noqa: E402
from stand.i18n import t  # noqa: E402
from stand.remnawave import PanelError  # noqa: E402


def build_modes(wanted, phones, has_dc):
    """Сети всех подключённых телефонов. wanted - токены --modes (multiphone.resolve_modes): с несколькими
    телефонами «sim1» значит «слот 1 на каждом», а «sim1@ТЕГ» - на конкретном. Непонятный токен - выход
    с перечнем доступных сетей."""
    modes = [m for _, group in multiphone.mode_groups(phones, has_dc) for m in group]
    for mode in modes:
        owners = multiphone.mode_serials(mode.id)
        if len(owners) > 1:
            print(t("   %s - общая колонка, узлы делятся поровну, телефонов: %d") % (mode.label, len(owners)),
                  flush=True)
    if not wanted:
        return modes
    try:
        modes, picks = multiphone.resolve_modes(wanted, modes, phones)
    except ValueError as exc:
        sys.exit(str(exc))
    for token, found in picks:
        print("   %s -> %s" % (token, ", ".join(chosen_name(mode) for mode in found)), flush=True)
    return modes


def chosen_name(mode):
    if mode.kind == "sim" and mode.slot >= 0:
        return "%s (%s)" % (mode.label, t("слот %d") % (mode.slot + 1))
    return mode.label


def list_modes(phones, has_dc):
    """--list-modes: что можно передать в --modes прямо сейчас."""
    groups = multiphone.mode_groups(phones, has_dc)
    modes = [m for _, group in groups for m in group]
    if not modes:
        print(t("сетей нет: телефон не подключён, пробник ДЦ не настроен в «Подключениях»"))
        return
    print(t("сети для --modes (можно и имя оператора, например mts или билайн):"))
    for title, group in groups:
        if title:
            print("  %s" % title)
        for mode in group:
            print("   %s" % multiphone.describe_mode(mode, phones))


def connected_phones(only=None):
    """Телефоны на кабеле (готовые к работе). only - тег или серийник, чтобы взять один."""
    try:
        serials = Adb().serials()
    except AdbError as exc:
        print("adb: %s" % exc, flush=True)
        return []
    phones = multiphone.describe_phones(lambda serial: Adb(serial=serial), serials)
    phones = [p for p in phones if p["state"].connected]
    if only:
        phones = [p for p in phones if only.lower() in (p["serial"].lower(), p["tag"].lower())]
    return multiphone.assign_port_windows(phones, serials)


def merge_into_previous(run):
    """Колонки нового прогона заменяют одноимённые в последнем прогоне той же панели/сквада за сегодня."""
    today = run["started"][:10]
    new_ids = {mode["id"] for mode in run["modes"]}
    for entry in storage.list_runs(limit=30):
        old = entry["run"]
        if old.get("panel") == run["panel"] and old.get("squad") == run["squad"] \
                and old.get("started", "")[:10] == today:
            keep = [mode for mode in old.get("modes", []) if mode["id"] not in new_ids]
            merged = dict(old)
            merged["modes"] = keep + run["modes"]
            merged["finished"] = run["finished"]
            merged["merged_from"] = old.get("started")
            if len(run["targets"]) >= len(old.get("targets", [])):
                merged["targets"] = run["targets"]
            return merged, entry["path"]
    return run, None


def print_table(run):
    modes = run["modes"]
    width = max([len(target["location"]) for target in run["targets"]] + [10])
    header = "%-*s  %-22s" % (width, t("Локация"), t("Узел")) + "".join("  %-16s" % m["label"][:16] for m in modes)
    print(header)
    print("-" * len(header))
    for target in sorted(run["targets"], key=lambda target: (target["location"], target["key"])):
        cells = []
        for mode in modes:
            if mode.get("error"):
                cells.append("? " + mode["error"][:14])
                continue
            value = mode["results"].get(target["key"], {})
            if value.get("exit_ip") or value.get("unchecked"):
                cells.append(node_cell(value))
            elif mode.get("whitelist"):
                cells.append(t("✕ БС") if mode["results"] else t("- БС"))
            else:
                cells.append(t("✕ мёртв"))
        print("%-*s  %-22s" % (width, target["location"], target["key"]) + "".join("  %-16s" % c for c in cells))
    print()
    for mode in modes:
        alive = sum(1 for v in mode["results"].values() if v.get("exit_ip"))
        note = mode.get("error") or ((t("белые списки - %s") % mode.get("whitelist_note", "")) if mode.get("whitelist")
                                     else "IP " + mode.get("ip", ""))
        unchecked = unchecked_note(mode["results"])
        if unchecked:
            note += "   " + unchecked
        print(t("%-18s живых %d из %d   %s") % (mode["label"], alive, len(run["targets"]), note))


def node_cell(value):
    """Ячейка узла в консоли: задержка, «медленно» (замер не уложился), «нет сети» (не проверен) или «мёртв»."""
    if value.get("unchecked") == "stop":
        return t("? остановлен")
    if value.get("unchecked"):
        return t("? нет сети")
    if not value.get("exit_ip"):
        return t("✕ мёртв")
    if value.get("slow"):
        return t("● медленно")
    return t("● %s мс") % value["latency"] if value.get("latency") else t("● жив")


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("panel", nargs="?",
                        help=t("имя панели из «Подключений»; не нужна, если задан --url или --file"))
    parser.add_argument("squad", nargs="?", help=t("сквад панели: под ним создаётся временный пользователь"))
    parser.add_argument("--url", help=t("ссылка на подписку (в том числе чужую) вместо панели"))
    parser.add_argument("--file", help=t("файл с подпиской вместо панели"))
    parser.add_argument("--title", help=t("как назвать прогон в истории (по умолчанию - хост ссылки)"))
    parser.add_argument("--modes", help=t("через запятую: dc, wifi, sim1/sim2 (слот) или имя оператора; "
                                          "по умолчанию все"))
    parser.add_argument("--list-modes", action="store_true", help=t("показать доступные сети и выйти"))
    parser.add_argument("--location", help=t("только локации с подстрокой"))
    parser.add_argument("--phone", help=t("только этот телефон: тег (A075F) или серийник"))
    parser.add_argument("--no-restore", action="store_true",
                        help=t("не возвращать сеть телефона как была после прогона"))
    parser.add_argument("--all-ports", action="store_true", help=t("не только 443 - узлы на всех портах"))
    parser.add_argument("--ports", help=t("только эти порты через запятую, например 443,2053"))
    parser.add_argument("--merge", action="store_true",
                        help=t("дописать колонки в последний сегодняшний прогон этой панели/сквада"))
    parser.add_argument("--geo", action="store_true",
                        help=t("живьём проверить геомаршрут: идут ли РФ-сайты мимо VPN или утекают в туннель"))
    args = parser.parse_args()
    if not args.list_modes and not args.url and not args.file and not (args.panel and args.squad):
        parser.error(t("нужны панель и сквад, либо --url / --file"))
    return args


def load_error(exc):
    """Причина, понятная человеку: нет файла, сайт не ответил, подписка не разобралась."""
    if isinstance(exc, FileNotFoundError):
        return t("файл не найден")
    if isinstance(exc, urllib.error.HTTPError):
        return "HTTP %d" % exc.code
    if isinstance(exc, urllib.error.URLError):
        return str(exc.reason)
    if isinstance(exc, (PanelError, OSError)):
        return str(exc) or type(exc).__name__
    return t("подписка не разобралась (%s)") % exc


def load_targets(args, connections, only_443):
    """Узлы из подписки (--url/--file) или из панели, с фильтрами --ports и --location.

    Для подписки args.panel/args.squad подменяются на код источника («url» или «file», как пишет окно)
    и её название - под ними прогон ляжет в историю.
    """
    if args.url or args.file:
        where = args.url or args.file
        print(t("подписка %s - загружаю узлы…") % where, flush=True)
        try:
            if args.url:
                targets, release = subscription.from_url(args.url, only_443=only_443)
            else:
                targets, release = subscription.from_file(args.file, only_443=only_443)
        except (OSError, ValueError) as exc:
            sys.exit(t("не удалось загрузить узлы из %s: %s") % (where, load_error(exc)))
        label = args.title or (args.url.split("//", 1)[-1].split("/")[0] if args.url
                               else os.path.basename(args.file))
        args.panel, args.squad = ("url" if args.url else "file"), label
    else:
        panel = connections["panels"].get(args.panel)
        if not panel:
            sys.exit(t("панель «%s» не настроена; есть: %s") % (args.panel, ", ".join(connections["panels"]) or "-"))
        print(t("панель %s, сквад %s - загружаю узлы…") % (args.panel, args.squad), flush=True)
        try:
            targets, release = subscription.from_panel(panel, args.squad, only_443=only_443)
        except (PanelError, OSError, ValueError) as exc:
            sys.exit(t("не удалось загрузить узлы из %s: %s") % (args.panel, load_error(exc)))
    if args.ports:
        wanted = {int(p) for p in args.ports.split(",") if p.strip().isdigit()}
        targets = [target for target in targets if target["port"] in wanted]
    if args.location:
        targets = [target for target in targets if args.location.lower() in target["location"].lower()]
    return targets, release


def print_plan(args, targets, modes, raw):
    """Что будет проверяться: пропущенные протоколы, геомаршрут подписки, сколько узлов и какие сети."""
    skipped = subscription.unsupported(raw) if (args.url or args.file) else []
    for item in skipped:
        print(t("   пропускаю %s - протокол %s, наш xray его не поднимает") % (item["location"], item["protocol"]),
              flush=True)
    routing = subscription.routing_summary(raw)
    print(t("   геомаршрут: %s %s") % ("✅" if routing["ru_direct"] else "⚠", routing["verdict"]), flush=True)
    print(t("узлов %d, локаций %d; сети: %s") % (len(targets), len({target["location"] for target in targets}),
                                              ", ".join(m.label for m in modes)), flush=True)


def print_node_result(mode_id, key, value):
    """Строка в консоль по каждому проверенному узлу, пока прогон идёт."""
    print("   %-14s %-22s %s" % (mode_id[:14], key, "↻" if value.get("retrying") else node_cell(value)), flush=True)


def run_jobs(app, modes, phones, targets, settings, connections, raw=None):
    """Сам прогон: по потоку на каждый телефон и на ДЦ, как в окне; ждём всех и склеиваем в один отчёт.

    Возвращает (отчёт, потоки). Потоки вызывающий держит до выхода: поток, не закончившийся
    за 5 с ожидания, нельзя уничтожать - Qt уронит процесс раньше, чем прогон сохранится.
    Ctrl+C останавливает прогон мягко (сеть телефона возвращается, отчёт сохраняется), второй - сразу.
    """
    jobs = multiphone.plan(modes, phones, targets)
    if not jobs:
        return multiphone.merge_runs([], targets), []
    jobs, windows = multiphone.lease_port_windows(jobs)
    if jobs is None:
        sys.exit(t("все окна локальных портов заняты другими прогонами - дождитесь их окончания"))
    result, workers = _run_leased(app, jobs, targets, settings, connections, raw)
    if not any(worker.isRunning() for worker in workers):
        portlock.release_all(windows)
    return result, workers


def _run_leased(app, jobs, targets, settings, connections, raw):
    results = [None] * len(jobs)
    workers = []
    left = [len(jobs)]

    def finished(slot, tag, run):
        run["phone_tag"] = tag
        results[slot] = run
        left[0] -= 1
        if left[0] == 0:
            app.quit()

    for slot, job in enumerate(jobs):
        serial, tag = job.serial, job.tag
        worker = multiphone.make_worker(job, targets, settings, connections,
                                        adb=Adb(serial=serial) if serial else None, raw=raw)
        worker.log.connect(lambda text: print(text, flush=True))
        worker.node_result.connect(print_node_result)
        shown = tag if tag != multiphone.DC_TAG else ""
        worker.run_finished.connect(lambda run, slot=slot, tag=shown: finished(slot, tag, run))
        workers.append(worker)
    previous = signal.signal(signal.SIGINT, lambda *_: stop_workers(workers))
    ticker = QTimer()
    ticker.timeout.connect(lambda: None)
    ticker.start(200)
    for worker in workers:
        worker.start()
    try:
        app.exec()
    finally:
        ticker.stop()
        signal.signal(signal.SIGINT, previous)
    for worker in workers:
        worker.wait(5000)
    return multiphone.merge_runs(results, targets), workers


def stop_workers(workers):
    """Первый Ctrl+C: остановить потоки прогона. Python ловит сигнал между тиками таймера,
    пока крутится цикл Qt; повторный Ctrl+C снова обычный - прерывает сразу."""
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    print(t("\nостанавливаю прогон и возвращаю сеть телефона… (ещё раз Ctrl+C - прервать сразу)"), flush=True)
    for worker in workers:
        worker.stop()


def diagnose_dead(result, path, connections):
    """Узлы, мёртвые везде, включая ДЦ: пробник выясняет почему, ответ дописывается в сохранённый прогон."""
    dead = dcprobe.dead_everywhere(result)
    if not (dead and storage.has_probe(connections)):
        return
    print(t("\nмертвы везде, включая ДЦ: %d - выясняю почему…") % len(dead), flush=True)
    try:
        result["diagnosis"] = dcprobe.diagnose_run(connections["probe"], result)
        storage.update_run(path, result)
        for key, check in sorted(result["diagnosis"].items(), key=lambda kv: kv[1]["verdict"]):
            print("   %-38s %-22s %s" % (key, dcprobe.display(check["verdict"]), check["detail"][:70]))
    except Exception as exc:
        print(t("   не вышло: %s") % (str(exc) or type(exc).__name__))


def main():
    args = parse_args()
    settings = storage.load_settings()
    settings["restore_network"] = not args.no_restore
    settings["geo_check"] = args.geo
    connections = storage.load_connections()
    phones = connected_phones(args.phone)
    if len(phones) > 1:
        print(t("телефонов на кабеле: %d - %s") % (len(phones), ", ".join(
            "%s (%s)" % (p["tag"], p["serial"]) for p in phones)), flush=True)
    has_dc = multiphone.dc_label(connections) if storage.has_probe(connections) else ""
    if args.list_modes:
        list_modes(phones, has_dc)
        return
    modes = build_modes(args.modes.split(",") if args.modes else None, phones, has_dc)
    if not modes:
        sys.exit(t("нет сетей для проверки (телефон подключён? пробник настроен в «Подключениях»?)"))

    only_443 = not (args.all_ports or args.ports) and bool(settings.get("only_443", True))
    targets, release = load_targets(args, connections, only_443)
    raw = getattr(release, "raw", None)
    try:
        if not targets:
            sys.exit(t("после фильтров не осталось ни одного узла - проверять нечего"))
        print_plan(args, targets, modes, raw if raw is not None else subscription.LAST_RAW)
        app = QCoreApplication(sys.argv)
        result, _workers = run_jobs(app, modes, phones, targets, settings, connections, raw=raw)
        result["panel"], result["squad"] = args.panel, args.squad
        replaced = None
        if args.merge:
            result, replaced = merge_into_previous(result)
        path = storage.save_run(result)
        if replaced and os.path.abspath(replaced) != os.path.abspath(path):
            with contextlib.suppress(OSError):
                os.remove(replaced)
        print(t("\nсохранено: %s\n") % path)
        print_table(result)
        diagnose_dead(result, path, connections)
        if result.get("geo", {}).get("available"):
            print(t("\nГЕОМАРШРУТ: %s") % result["geo"]["verdict"])
    finally:
        try:
            release()
        except Exception as exc:  # noqa: BLE001
            print(t("временный пользователь не удалён (%s) - истечёт сам через сутки") % exc)


if __name__ == "__main__":
    started = time.time()
    main()
    print(t("\n%.0f с") % (time.time() - started))
