"""Главное окно: прогон с сортировкой, Стоп, выход посреди прогона, история, диагноз, демо."""
import json
import os
import time

import pytest
from fakes import FakeWorker
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QMessageBox

import stand.ui.main_window as mw
from stand import dcprobe, errorlog, geo, multiphone, portlock, runlock, storage
from stand.checker import Mode
from stand.phone import PhoneState, Sim

N = 300


def make_targets(n=N):
    return [{"location": "L%02d" % (i % 37), "key": "10.%d.%d.%d:443" % (i // 65536, (i // 256) % 256, i % 256),
             "address": "10.0.0.1", "port": 443, "sni": "apple.com", "outbound": {}} for i in range(n)]


@pytest.fixture
def window(qtbot, monkeypatch, quit_calls):
    FakeWorker.instances.clear()
    FakeWorker.ignore_stop = False
    FakeWorker.delay = 0.0005
    monkeypatch.setattr(FakeWorker, "value_for", None)
    monkeypatch.setattr(multiphone, "CheckWorker", FakeWorker)
    w = mw.MainWindow()
    qtbot.addWidget(w)
    w.show()
    yield w
    FakeWorker.ignore_stop = False
    for worker in FakeWorker.instances:
        worker.stop()
        worker.wait(10000)
    for task in list(w.tasks):
        task.wait(10000)
    portlock.release_all(list(portlock.held()))


def fake_phone(w, monkeypatch):
    state = PhoneState(connected=True, serial="R58X1", state="device", model="SM-A075F", android="15")
    state.sims = [Sim(1, 0, "MegaFon", "MegaFon", "LTE", 3, True)]
    phones = [{"serial": "R58X1", "index": 0, "tag": "A075F", "state": state, "model": "SM-A075F"}]
    monkeypatch.setattr(w, "connected_phones", lambda: phones)
    modes = [Mode("dc", "dc", "ДЦ"), Mode("sim1", "sim", "MegaFon", 1), Mode("wifi", "wifi", "Wi-Fi")]
    monkeypatch.setattr(w.networks, "selected", lambda: modes)
    return modes


def inconsistencies(w, modes, finished=True):
    bad = []
    for row in range(w.table.rowCount()):
        key = w.table.item(row, mw.COL_KEY).data(Qt.UserRole)
        if w.row_by_key.get(key) != row:
            bad.append(("row_by_key", key, row, w.row_by_key.get(key)))
        for mode in modes:
            text = w.table.item(row, w.mode_columns[mode.id]).text()
            if finished and key in (w.mode_results.get(mode.id) or {}):
                if not text.startswith("●" if FakeWorker.ok(mode.id, key) else "✕"):
                    bad.append(("cell", mode.id, key, text))
    return bad


def history_run(targets, modes):
    for mode in modes:
        mode["results"] = {t["key"]: {"exit_ip": "1.1.1.1" if FakeWorker.ok(mode["id"], t["key"]) else "",
                                      "latency": 100} for t in targets}
        mode.update(ip="192.0.2.1", error="")
    return {"started": "2026-09-28 10:00:00", "finished": "2026-09-28 11:00:00",
            "targets": [{"location": t["location"], "key": t["key"], "sni": "x"} for t in targets], "modes": modes}


def test_launch_and_close_no_leaks(window, qtbot, quit_calls):
    assert window.poller is None
    window.close()
    qtbot.waitUntil(lambda: bool(quit_calls), timeout=5000)
    assert not window.history_timer.isActive()
    assert not window.threads_running()
    assert portlock.held() == []


def test_history_reads_each_file_once(window, monkeypatch):
    targets = make_targets(200)
    run = history_run(targets, [{"id": m, "kind": k, "label": m} for m, k in (("dc", "dc"), ("sim1", "sim"))])
    os.makedirs(storage.RUNS_DIR, exist_ok=True)
    for day in range(1, 6):
        with open(os.path.join(storage.RUNS_DIR, "2026-09-%02d_10-00-00.json" % day), "w", encoding="utf-8") as h:
            json.dump(run, h)
    reads = []
    original = mw.read_run
    monkeypatch.setattr(mw, "read_run", lambda path: (reads.append(path), original(path))[1])
    window.reload_history()
    window.reload_history()
    assert window.history.count() == 6
    assert len(reads) == 5
    window.history.setCurrentIndex(1)
    assert window.shown_run_path.endswith("2026-09-05_10-00-00.json")
    alive = sum(FakeWorker.ok("sim1", t["key"]) for t in targets)
    assert window.totals.item(0, window.mode_columns["sim1"]).text() == "%d из %d" % (alive, len(targets))
    assert not inconsistencies(window, [Mode("dc", "dc", "dc"), Mode("sim1", "sim", "sim1")], finished=False)


def test_run_with_sorting_midway(window, qtbot, monkeypatch):
    window.targets = make_targets()
    modes = fake_phone(window, monkeypatch)
    FakeWorker.delay = 0.002
    window.start_check()
    assert window.worker is not None
    assert len(portlock.held()) == 1
    flips = [window.mode_columns["sim1"], window.mode_columns["dc"], 0]
    for col in flips:
        qtbot.wait(150)
        window.table.sortItems(col, Qt.DescendingOrder)
    qtbot.waitUntil(lambda: window.worker is None, timeout=60000)
    qtbot.waitUntil(lambda: window.table.isSortingEnabled(), timeout=5000)
    assert not inconsistencies(window, modes)
    for mode in modes:
        keys = window.mode_rows(mode.id)
        alive = sum(FakeWorker.ok(mode.id, k) for k in keys)
        assert window.totals.item(0, window.mode_columns[mode.id]).text() == "%d из %d" % (alive, len(keys))
    assert portlock.held() == []
    assert window.run_button.isVisible() and window.run_button.isEnabled()


def test_results_do_not_resort_every_cell(window, qtbot, monkeypatch):
    window.targets = make_targets()
    modes = fake_phone(window, monkeypatch)
    window.mode_keys = mw.mode_keys(modes, window.targets)
    window.fill_table(window.targets, modes)
    window.final_cells, window.total_cells = set(), N * 3
    col = window.mode_columns["wifi"]
    window.table.sortItems(col, Qt.AscendingOrder)
    sorts = []
    window.table.model().layoutChanged.connect(lambda *_a: sorts.append(1))
    for target in window.targets:
        key = target["key"]
        window.show_result("wifi", key, {"exit_ip": "1" if FakeWorker.ok("wifi", key) else "", "latency": 1})
    assert not window.table.isSortingEnabled()
    assert sorts == []
    qtbot.waitUntil(lambda: window.table.isSortingEnabled(), timeout=5000)
    assert window.table.horizontalHeader().sortIndicatorSection() == col
    assert not inconsistencies(window, modes, finished=False)
    texts = [window.table.item(row, col).text() for row in range(window.table.rowCount())]
    assert texts == sorted(texts)
    for row in range(window.table.rowCount()):
        key = window.table.item(row, mw.COL_KEY).data(Qt.UserRole)
        assert window.table.item(row, col).text().startswith("●" if FakeWorker.ok("wifi", key) else "✕")


def test_stop_midway_leaves_clean_columns(window, qtbot, monkeypatch):
    window.targets = make_targets()
    fake_phone(window, monkeypatch)
    FakeWorker.delay = 0.005
    window.start_check()
    qtbot.waitUntil(lambda: len(window.final_cells) > 50, timeout=20000)
    window.stop_check()
    qtbot.waitUntil(lambda: window.worker is None, timeout=20000)
    texts = {window.table.item(r, c).text() for r in range(window.table.rowCount())
             for c in window.mode_columns.values()}
    assert "…" not in texts and "↻ ещё раз" not in texts
    assert not any(label.text().endswith("идёт проверка") for label in window.mode_chips.values())
    assert portlock.held() == []
    newest = mw.read_run(mw.run_paths(limit=1)[0])
    assert newest["stopped"] is True


def test_close_during_run(window, qtbot, monkeypatch, quit_calls):
    window.targets = make_targets()
    fake_phone(window, monkeypatch)
    FakeWorker.delay = 0.005
    monkeypatch.setattr(QMessageBox, "question", staticmethod(lambda *a, **k: QMessageBox.Yes))
    window.start_check()
    qtbot.waitUntil(lambda: len(window.final_cells) > 20, timeout=20000)
    window.close()
    assert window.closing
    qtbot.waitUntil(lambda: bool(quit_calls), timeout=30000)
    assert window.worker is None
    assert portlock.held() == []
    assert not any(worker.isRunning() for worker in FakeWorker.instances)
    assert mw.read_run(mw.run_paths(limit=1)[0])["stopped"] is True


def test_close_with_stuck_worker_exits(window, qtbot, monkeypatch):
    window.targets = make_targets()
    fake_phone(window, monkeypatch)
    FakeWorker.delay = 0.05
    FakeWorker.ignore_stop = True
    exits = []
    monkeypatch.setattr(os, "_exit", lambda code: exits.append(code))
    monkeypatch.setattr(QMessageBox, "question", staticmethod(lambda *a, **k: QMessageBox.Yes))
    window.start_check()
    qtbot.wait(300)
    window.close()
    window.close_deadline = time.time() + 1
    qtbot.waitUntil(lambda: bool(exits), timeout=10000)
    FakeWorker.ignore_stop = False


def slow_diagnosis(monkeypatch, verdicts):
    def diagnose(_spec, run):
        time.sleep(0.8)
        return {target["key"]: {"verdict": "не достучаться из РФ", "detail": "x"} for target in run["targets"]
                if target["key"] in verdicts}
    monkeypatch.setattr(dcprobe, "diagnose_run", diagnose)


def dead_run(targets):
    dead = {t["key"]: {"exit_ip": ""} for t in targets}
    return {"started": "A", "targets": targets,
            "modes": [{"id": "dc", "kind": "dc", "label": "ДЦ", "results": dead, "ip": "", "error": ""}]}


def headers(window):
    return [window.table.horizontalHeaderItem(c).text() for c in range(window.table.columnCount())]


def test_diagnosis_of_old_run_stays_off_new_run(window, qtbot, monkeypatch):
    window.connections = {"panels": {}, "probe": {"host": "192.0.2.9"}}
    targets = make_targets(50)
    run_a = dead_run(targets)
    slow_diagnosis(monkeypatch, {t["key"] for t in targets})
    path = storage.save_run(run_a)
    window.start_diagnosis(run_a, path)
    fake_phone(window, monkeypatch)
    monkeypatch.setattr(mw.MainWindow, "start_diagnosis", lambda *_a: None)
    window.targets = targets
    FakeWorker.delay = 0.03
    window.start_check()
    qtbot.wait(1500)
    assert window.worker is not None
    assert "Почему мёртв" not in headers(window)
    qtbot.waitUntil(lambda: window.worker is None, timeout=60000)
    qtbot.waitUntil(lambda: not window.tasks, timeout=10000)
    assert "Почему мёртв" not in headers(window)
    assert "diagnosis" in mw.read_run(path)


def test_diagnosis_lands_on_shown_run(window, qtbot, monkeypatch):
    window.connections = {"panels": {}, "probe": {"host": "192.0.2.9"}}
    targets = make_targets(20)
    run_a = dead_run(targets)
    slow_diagnosis(monkeypatch, {targets[0]["key"]})
    path = storage.save_run(run_a)
    window.reload_history()
    window.history.setCurrentIndex(1)
    assert window.shown_run_path == path
    window.start_diagnosis(run_a, path)
    qtbot.waitUntil(lambda: "Почему мёртв" in headers(window), timeout=10000)


def test_nodes_loaded_while_closing_release_account(window, qtbot):
    released = []
    window.closing = True
    window.on_subscription_loaded((make_targets(5), lambda: released.append(1), None))
    qtbot.waitUntil(lambda: bool(released), timeout=5000)
    assert window.release_subscription is None
    assert window.targets == []


def test_demo_does_not_touch_network(window, monkeypatch):
    calls = []
    monkeypatch.setattr(geo, "lookup_many", lambda hosts, workers=8: calls.append(hosts) or {})
    monkeypatch.setattr(geo, "cached", lambda host: calls.append(host) or {})
    window.load_demo()
    assert calls == []
    assert not window.tasks
    hosters = {window.table.item(row, mw.COL_HOSTER).text() for row in range(window.table.rowCount())}
    assert "Example Hosting GmbH · DE" in hosters
    assert not os.path.exists(geo.CACHE_PATH)
    assert "Почему мёртв" in headers(window)
    col = headers(window).index("Почему мёртв")
    verdicts = {window.table.item(row, mw.COL_IP).text(): window.table.item(row, col).text()
                for row in range(window.table.rowCount()) if window.table.item(row, col)}
    assert verdicts == {mw.DEMO_DEAD: "не достучаться из РФ"}


def test_save_run_failure_does_not_hang(window, qtbot, monkeypatch):
    window.targets = make_targets(20)
    fake_phone(window, monkeypatch)
    warnings = []
    monkeypatch.setattr(window, "warn", warnings.append)

    def broken(_run):
        raise PermissionError("disk is read-only")
    monkeypatch.setattr(storage, "save_run", broken)
    window.start_check()
    qtbot.waitUntil(lambda: window.worker is None, timeout=30000)
    assert window.run_button.isVisible() and not window.stop_button.isVisible()
    assert warnings and "disk is read-only" in warnings[0]
    assert any("disk is read-only" in entry["text"] for entry in errorlog.read())
    assert portlock.held() == []


def test_phone_task_respects_busy_phone_and_windows(window, qtbot):
    window.selected_serial = "R58X1"
    calls, done = [], []
    assert runlock.acquire("R58X1")
    window.phone_task(lambda shift: calls.append(shift), done.append, done.append, ports=True, quiet=True)
    assert calls == [] and not window.phone_busy
    runlock.release("R58X1")
    windows = [portlock.acquire() for _ in range(portlock.WINDOWS)]
    try:
        window.phone_task(lambda shift: calls.append(shift), done.append, done.append, ports=True, quiet=True)
        assert calls == [] and not window.phone_busy
        assert runlock.acquire("R58X1")
        runlock.release("R58X1")
    finally:
        portlock.release_all(windows)
    window.phone_task(lambda shift: calls.append(shift) or "ok", done.append, done.append, ports=True, quiet=True)
    qtbot.waitUntil(lambda: bool(done), timeout=5000)
    assert done == ["ok"] and len(calls) == 1
    assert portlock.held() == [] and not window.phone_busy


def test_port_shift_needs_a_window():
    with pytest.raises(ValueError):
        portlock.shift(None)


def test_network_columns_follow_location(window, monkeypatch):
    modes = fake_phone(window, monkeypatch)
    window.fill_table(make_targets(5), modes)
    header = window.table.horizontalHeader()
    assert header.visualIndex(mw.COL_IP) == 1
    assert [header.visualIndex(window.mode_columns[mode.id]) for mode in modes] == [2, 3, 4]
    assert not window.table.isColumnHidden(mw.COL_IP) and window.table.isColumnHidden(mw.COL_SNI)
    window.detail_toggle.setChecked(True)
    assert not window.table.isColumnHidden(mw.COL_IP)
    headers, _rows, _totals = window.table_rows()
    assert headers[:5] == ["Локация", "IP", "ДЦ", "MegaFon", "Wi-Fi"]


def test_cells_sort_by_number_not_text(window, monkeypatch):
    modes = fake_phone(window, monkeypatch)
    targets = make_targets(4)
    window.fill_table(targets, modes)
    for target, latency in zip(targets, (1050, 372, None, 95), strict=True):
        value = {"exit_ip": "198.51.100.1", "latency": latency} if latency else {"exit_ip": ""}
        window.show_result("sim1", target["key"], value)
    col = window.mode_columns["sim1"]
    window.table.setSortingEnabled(True)
    window.table.sortItems(col, Qt.AscendingOrder)
    texts = [window.table.item(row, col).text() for row in range(window.table.rowCount())]
    assert texts == ["● 95 мс", "● 372 мс", "● 1050 мс", "✕ мёртв"]


def netdrop_value(mode_id, key):
    """sim1: у каждого 4-го узла пропала сеть при перепроверке, у каждого 4-го+1 замер задержки не уложился,
    4-й+3 мёртв. Прочие сети: живы, кроме 4-го и 4-го+3."""
    kind = int(key.split(":")[0].rsplit(".", 1)[1]) % 4
    if mode_id != "sim1":
        return {"exit_ip": "" if kind in (0, 3) else "198.51.100.1", "latency": 120}
    return [{"exit_ip": "", "latency": None, "unchecked": "net"},
            {"exit_ip": "198.51.100.1", "latency": None, "slow": True},
            {"exit_ip": "198.51.100.1", "latency": 200},
            {"exit_ip": "", "latency": None}][kind]


def sim1_cells(window):
    col = window.mode_columns["sim1"]
    return {window.table.item(row, mw.COL_KEY).data(Qt.UserRole): window.table.item(row, col).text()
            for row in range(window.table.rowCount())}


def test_net_drop_and_slow_through_run_history_and_copy(window, qtbot, monkeypatch):
    targets = make_targets(12)
    window.targets = targets
    fake_phone(window, monkeypatch)
    monkeypatch.setattr(FakeWorker, "value_for", netdrop_value)
    window.start_check()
    qtbot.waitUntil(lambda: window.worker is None, timeout=60000)
    expected = {t["key"]: ["? нет сети", "● медленно", "● 200 мс", "✕ мёртв"][i % 4] for i, t in enumerate(targets)}
    assert sim1_cells(window) == expected
    col = window.mode_columns["sim1"]
    assert window.totals.item(0, col).text() == "6 из 12 · не проверено 3"
    assert "не проверено 3" in window.mode_chips["sim1"].text()
    unchecked = window.table.item(window.row_by_key[targets[0]["key"]], col)
    assert "пропал интернет" in unchecked.toolTip()
    window.table.setSortingEnabled(True)
    window.table.sortItems(col, Qt.AscendingOrder)
    order = [window.table.item(row, col).text() for row in range(window.table.rowCount())]
    assert order == ["● 200 мс"] * 3 + ["● медленно"] * 3 + ["? нет сети"] * 3 + ["✕ мёртв"] * 3
    window.copy_table("text")
    copied = mw.QApplication.clipboard().text()
    assert "? нет сети" in copied and "● медленно" in copied and "6 из 12 · не проверено 3" in copied
    saved = storage.list_runs()[0]
    results = next(mode for mode in saved["run"]["modes"] if mode["id"] == "sim1")["results"]
    assert results[targets[0]["key"]] == {"exit_ip": "", "latency": None, "unchecked": "net"}
    assert results[targets[1]["key"]]["slow"] is True
    assert "MegaFon 6/12 ?3" in saved["label"]
    dead = {t["key"] for t in dcprobe.dead_everywhere(saved["run"])}
    assert dead == {t["key"] for i, t in enumerate(targets) if i % 4 == 3}
    window.fill_table(targets, [])
    window.reload_history()
    window.history.setCurrentIndex(1)
    assert sim1_cells(window) == expected
    assert window.totals.item(0, window.mode_columns["sim1"]).text() == "6 из 12 · не проверено 3"


def stopped_value(mode_id, key):
    """sim1: 4-й узел не перепроверен из-за стопа, 4-й+1 - из-за пропавшей сети, 4-й+2 жив, 4-й+3 мёртв."""
    kind = int(key.split(":")[0].rsplit(".", 1)[1]) % 4
    if mode_id != "sim1":
        return {"exit_ip": "" if kind in (0, 3) else "198.51.100.1", "latency": 120}
    return [{"exit_ip": "", "latency": None, "unchecked": "stop"},
            {"exit_ip": "", "latency": None, "unchecked": "net"},
            {"exit_ip": "198.51.100.1", "latency": 200},
            {"exit_ip": "", "latency": None}][kind]


def test_stopped_before_recheck_is_not_dead_live_and_in_history(window, qtbot, monkeypatch):
    targets = make_targets(12)
    window.targets = targets
    fake_phone(window, monkeypatch)
    monkeypatch.setattr(FakeWorker, "value_for", stopped_value)
    window.start_check()
    qtbot.waitUntil(lambda: window.worker is None, timeout=60000)
    expected = {t["key"]: ["? остановлен", "? нет сети", "● 200 мс", "✕ мёртв"][i % 4] for i, t in enumerate(targets)}
    assert sim1_cells(window) == expected
    col = window.mode_columns["sim1"]
    assert window.totals.item(0, col).text() == "3 из 12 · не проверено 6"
    assert "пропала сеть телефона - 3, прогон остановлен - 3" in window.mode_chips["sim1"].text()
    assert "прогон остановлен" in window.table.item(window.row_by_key[targets[0]["key"]], col).toolTip()
    saved = storage.list_runs()[0]
    assert "MegaFon 3/12 ?6" in saved["label"]
    assert {t["key"] for t in dcprobe.dead_everywhere(saved["run"])} == {t["key"] for i, t in enumerate(targets)
                                                                         if i % 4 == 3}
    window.fill_table(targets, [])
    window.reload_history()
    window.history.setCurrentIndex(1)
    assert sim1_cells(window) == expected
    assert window.totals.item(0, col).text() == "3 из 12 · не проверено 6"


def test_totals_show_unchecked_when_whole_column_lost_network(window, qtbot, monkeypatch):
    targets = make_targets(8)
    window.targets = targets
    fake_phone(window, monkeypatch)
    monkeypatch.setattr(FakeWorker, "value_for", lambda mode_id, key: {"exit_ip": "", "latency": None,
                                                                       "unchecked": "net"}
                        if mode_id == "sim1" else {"exit_ip": "198.51.100.1", "latency": 100})
    window.start_check()
    qtbot.waitUntil(lambda: window.worker is None, timeout=60000)
    assert window.totals.item(0, window.mode_columns["sim1"]).text() == "0 из 8 · не проверено 8"
    window.fill_table(targets, [])
    window.reload_history()
    window.history.setCurrentIndex(1)
    assert window.totals.item(0, window.mode_columns["sim1"]).text() == "0 из 8 · не проверено 8"


def test_dead_in_needs_the_node_in_column_results():
    mode = {"results": {"a:443": {"exit_ip": "", "latency": None}}}
    assert dcprobe.dead_in(mode, "a:443") is True
    assert dcprobe.dead_in(mode, "b:443") is False
    mode["results"]["a:443"]["unchecked"] = "stop"
    assert dcprobe.dead_in(mode, "a:443") is False


def test_first_start_without_adb_says_what_to_install(window):
    assert window.phone.status.text() == "не найдена программа adb"
    assert "winget install Google.PlatformTools" in window.phone.sub.text()
    assert window.networks.hint.text().startswith("Сетей пока нет")
