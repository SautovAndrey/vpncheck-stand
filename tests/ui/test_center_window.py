"""Центр агентов: agent.json только владельцу, ключ Яндекс Карт, кнопки без сервера, выкладка узлов и APK."""
import json
import os
import threading
import time
import zipfile

import pytest
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QInputDialog, QMessageBox

from stand import agentapi, subscription
from stand.ui import center, mapscheme
from stand.ui.agent_dialog import AgentDialog


class FakeApi:
    def __init__(self):
        self.calls = []
        self.gate = threading.Event()
        self.gate.set()

    def set_state(self, **patch):
        self.calls.append(("set_state", patch))
        return {"ok": True}

    def set_nodes(self, targets, expire=None, user=""):
        self.gate.wait(10)
        self.calls.append(("set_nodes", len(targets), expire, user))
        return {"ok": True, "nodes": len(targets)}

    def __getattr__(self, name):
        def call(*args, **kwargs):
            self.calls.append((name, args, kwargs))
            return {} if name != "agents" else []
        return call


@pytest.fixture
def window(qtbot):
    w = center.CenterWindow({"squads_cache": {}, "squad": "S1"},
                            {"panels": {"demo": {"url": "https://p", "token": "x"}}})
    qtbot.addWidget(w)
    yield w
    w.timer.stop()
    for task in list(w.tasks):
        task.wait(10000)


@pytest.fixture
def messages(monkeypatch):
    shown = []
    for name in ("information", "warning"):
        monkeypatch.setattr(QMessageBox, name, staticmethod(lambda _parent, title, text, *a, **k:
                                                            shown.append((title, text)) or QMessageBox.Ok))
    return shown


def test_map_provider_saved_atomically_for_owner_only(window, monkeypatch):
    agentapi.save_agent_config("http://127.0.0.1:1", "secret")
    with open(agentapi.AGENT_CONFIG, encoding="utf-8") as handle:
        cfg = json.load(handle)
    cfg["yandex_key"] = "k"
    with open(agentapi.AGENT_CONFIG, "w", encoding="utf-8") as handle:
        json.dump(cfg, handle)
    window.set_map_provider("yandex")
    with open(agentapi.AGENT_CONFIG, encoding="utf-8") as handle:
        saved = json.load(handle)
    assert saved["map_provider"] == "yandex" and saved["token"] == "secret"
    assert not [name for name in os.listdir(os.path.dirname(agentapi.AGENT_CONFIG)) if name.endswith(".tmp")]
    if os.name == "posix":
        assert os.stat(agentapi.AGENT_CONFIG).st_mode & 0o777 == 0o600
    assert window.provider_button.text() == "Карта: Яндекс"


def test_yandex_key_saved_and_sent_to_server(window, qtbot, monkeypatch):
    monkeypatch.setattr(QInputDialog, "getText", staticmethod(lambda *a, **k: ("  KEY-123 ", True)))
    window.api = FakeApi()
    window.ask_yandex_key()
    qtbot.waitUntil(lambda: not window.tasks, timeout=5000)
    with open(agentapi.AGENT_CONFIG, encoding="utf-8") as handle:
        saved = json.load(handle)
    assert saved["yandex_key"] == "KEY-123" and saved["map_provider"] == "yandex"
    assert ("set_state", {"yandex_key": "KEY-123"}) in window.api.calls
    assert window.map_provider() == "yandex"


def test_yandex_without_key_asks_for_it(window, monkeypatch):
    asked = []
    monkeypatch.setattr(QInputDialog, "getText", staticmethod(lambda *a, **k: asked.append(1) or ("", False)))
    window.set_map_provider("yandex")
    assert asked
    assert window.map_provider() == "leaflet"


def test_buttons_without_server_explain(window, messages, monkeypatch):
    monkeypatch.setattr(center.QFileDialog, "getOpenFileName", staticmethod(lambda *a, **k: pytest.fail("файл")))
    for action in (window.run_now_all, window.update_now_all, window.push_sites, window.push_settings,
                   window.push_params, window.publish_apk, window.push_nodes):
        action()
    assert len(messages) == 7
    assert all("Сначала подключитесь" in text for _title, text in messages)
    assert not window.tasks


def test_push_nodes_button_off_while_publishing(window, qtbot, monkeypatch):
    api = FakeApi()
    api.gate.clear()
    window.api = api
    window.panel.setCurrentText("demo")
    window.squad.setEditText("S1")
    release = subscription.Release(b"raw")
    release.agent_user = {"username": "vpnagent_x", "uuid": "u-1", "expire": 1234.0}
    other = {"username": "чужая", "uuid": "u-9", "expire": 1}
    monkeypatch.setattr(subscription, "LAST_AGENT_USER", other, raising=False)
    monkeypatch.setattr(subscription, "from_panel", lambda *a, **k: ([{"location": "L", "key": "k:443"}], release))
    window.push_nodes()
    assert not window.push_nodes_button.isEnabled()
    api.gate.set()
    qtbot.waitUntil(lambda: window.push_nodes_button.isEnabled(), timeout=5000)
    assert ("set_nodes", 1, 1234.0, "vpnagent_x") in api.calls


def test_agent_user_falls_back_to_old_global(monkeypatch):
    monkeypatch.setattr(subscription, "LAST_AGENT_USER", {"username": "old"}, raising=False)
    assert center.agent_user(object()) == {"username": "old"}
    assert center.agent_user(subscription.Release(agent_user=None)) == {}


def make_apk(folder, with_core=True, metadata=None):
    path = os.path.join(folder, "app-release.apk")
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"x")
        if with_core:
            archive.writestr(center.XRAY_LIB, b"elf")
    if metadata is not None:
        with open(os.path.join(folder, "output-metadata.json"), "w", encoding="utf-8") as handle:
            json.dump(metadata, handle)
    return path


def test_apk_without_core_refused(tmp_path):
    assert "fetch_binaries" in center.apk_problem(make_apk(str(tmp_path), with_core=False))
    assert center.apk_problem(make_apk(str(tmp_path))) == ""
    broken = tmp_path / "broken.apk"
    broken.write_bytes(b"not a zip")
    assert center.apk_problem(str(broken))


def test_apk_version_from_gradle_metadata(tmp_path):
    meta = {"elements": [{"outputFile": "app-release.apk", "versionCode": 14, "versionName": "0.14.0"}]}
    assert center.apk_metadata(make_apk(str(tmp_path), metadata=meta)) == {"version_code": 14,
                                                                           "version_name": "0.14.0"}
    (tmp_path / "output-metadata.json").write_text("{broken", encoding="utf-8")
    assert center.apk_metadata(str(tmp_path / "app-release.apk")) == {}


def test_publish_apk_prefills_versions(window, qtbot, monkeypatch, tmp_path):
    meta = {"elements": [{"outputFile": "app-release.apk", "versionCode": 14, "versionName": "0.14.0"}]}
    path = make_apk(str(tmp_path), metadata=meta)
    api = FakeApi()
    window.api = api
    monkeypatch.setattr(center, "signing_key", lambda: "ab")
    monkeypatch.setattr(center.QFileDialog, "getOpenFileName", staticmethod(lambda *a, **k: (path, "")))
    defaults = []

    def answer(_parent, _title, _prompt, _mode, default):
        defaults.append(default)
        return default, True
    monkeypatch.setattr(QInputDialog, "getText", staticmethod(answer))
    window.publish_apk()
    qtbot.waitUntil(lambda: not window.tasks, timeout=5000)
    assert defaults == ["0.14.0", "14"]
    manifest = [call for call in api.calls if call[0] == "publish_manifest"][0]
    assert manifest[2]["app"]["version_code"] == 14 and manifest[2]["app"]["version_name"] == "0.14.0"


def test_thread_crash_is_red_and_named():
    assert center.error_kind("падение потока") == "падение потока"
    assert center.is_crash("падение потока") and center.is_crash("crash") and not center.is_crash("check")


def test_status_thresholds():
    now = time.time()
    assert center.agent_status({"last_seen": now - 3600}, now)[0] == "● на связи"
    assert center.agent_status({"last_seen": now - 5 * 3600}, now)[0] == "● был недавно"
    assert center.agent_status({"last_seen": now - 13 * 3600}, now)[0] == "● молчит"
    assert center.agent_status({"last_seen": now - 8 * 86400}, now)[0] == "● не выходит"


def test_asset_path_other_drive_is_refused():
    for bad in ("/C:x.json", "/C:/Windows/win.ini", "C:foo.json", "/..%2f/x.json"):
        assert mapscheme.asset_path(bad) is None, bad


def test_agent_card_opens(window, qtbot):
    agent = {"agent_id": "0123456789abcdef", "last_seen": time.time() - 9 * 86400, "push": True}
    dialog = AgentDialog(agent, [], window)
    qtbot.addWidget(dialog)
    texts = [label.text() for label in dialog.findChildren(center.QWidget) if hasattr(label, "text")
             and isinstance(label.text(), str)]
    assert any(text.startswith("● не выходит, был 9 дн назад") for text in texts)
    dialog.close()


def test_stale_answer_is_dropped_after_reconnect(window, qtbot):
    gate, seen = threading.Event(), []
    window.run_once("probe", lambda: gate.wait(10) and "old", seen.append, seen.append)
    window._generation += 1
    window.run_once("probe", lambda: "new", seen.append, seen.append)
    qtbot.waitUntil(lambda: seen == ["new"], timeout=5000)
    gate.set()
    qtbot.wait(300)
    assert seen == ["new"]


def test_agent_table_sorts_by_meaning(window):
    now = time.time()
    agents = [{"agent_id": "a%015d" % i, "last_seen": now - ago, "alive": alive, "total": 10, "app_version": ver}
              for i, (ago, alive, ver) in enumerate(((600, 3, "0.9.1"), (7200, 10, "0.10.0"), (60, 0, "0.12.0")))]
    window.on_agents(agents)
    table = window.agents_table
    table.sortItems(7)
    assert [table.item(row, 7).text() for row in range(3)] == ["только что", "10 мин назад", "2 ч назад"]
    table.sortItems(8)
    assert [table.item(row, 8).text().split(" ")[0] for row in range(3)] == ["0.9.1", "0.10.0", "0.12.0"]


def test_push_nodes_removes_agent_account_when_release_fails(window, qtbot, monkeypatch):
    window.api = FakeApi()
    window.panel.setCurrentText("demo")
    window.squad.setEditText("S1")

    class Broken:
        agent_user = {"username": "vpnagent_x", "uuid": "u-1", "expire": 1234.0}

        def __call__(self):
            raise OSError("panel is down")
    deleted = []

    class Panel:
        def delete_user(self, uuid):
            deleted.append(uuid)
    monkeypatch.setattr(subscription, "from_panel", lambda *a, **k: ([{"location": "L", "key": "k:443"}], Broken()))
    monkeypatch.setattr(subscription.Panel, "from_config", staticmethod(lambda _config: Panel()))
    window.push_nodes()
    qtbot.waitUntil(lambda: window.push_nodes_button.isEnabled(), timeout=5000)
    assert deleted == ["u-1"]
    assert not any(call[0] == "set_nodes" for call in window.api.calls)


class MatrixApi(FakeApi):
    def matrix(self, hours):
        self.calls.append(("matrix", hours))
        return {"columns": {"Москва · MTS": {}}, "matrix": {"a:443": {"Москва · MTS": [2, 3]}},
                "unchecked": {"b:443": {"Москва · MTS": "core-exit:23"}, "a:443": {"Москва · MTS": "unsupported"}}}


def matrix_calls(api):
    return [call for call in api.calls if call[0] == "matrix"]


def test_matrix_polled_only_on_its_tab_and_rarely_for_long_periods(window, qtbot):
    window.api = api = MatrixApi()
    window.refresh_matrix(periodic=True)
    assert not matrix_calls(api)
    window.tabs.setCurrentWidget(window.matrix_tab)
    qtbot.waitUntil(lambda: len(matrix_calls(api)) == 1, timeout=5000)
    qtbot.waitUntil(lambda: not window.tasks, timeout=5000)
    window.refresh_matrix(periodic=True)
    qtbot.wait(100)
    assert len(matrix_calls(api)) == 1
    window.hours.setValue(168)
    qtbot.waitUntil(lambda: matrix_calls(api)[-1] == ("matrix", 168), timeout=5000)
    qtbot.waitUntil(lambda: not window.tasks, timeout=5000)
    count = len(matrix_calls(api))
    window._matrix_fetched = (window._matrix_fetched[0], time.time() - 200)
    window.refresh_matrix(periodic=True)
    qtbot.wait(100)
    assert len(matrix_calls(api)) == count
    window._matrix_fetched = (window._matrix_fetched[0], time.time() - center.MATRIX_SLOW_EVERY - 1)
    window.refresh_matrix(periodic=True)
    qtbot.waitUntil(lambda: len(matrix_calls(api)) == count + 1, timeout=5000)


def test_matrix_shows_why_node_was_not_checked(window):
    window.on_matrix(MatrixApi().matrix(24))
    table = window.matrix
    rows = {table.item(row, 0).text(): row for row in range(table.rowCount())}
    cell = table.item(rows["b:443"], 1)
    assert cell.text() == "не проверен"
    assert "ядро xray упало на этом узле (код 23)" in cell.toolTip()
    assert "не поддерживает" in table.item(rows["a:443"], 1).toolTip()


def test_matrix_not_redrawn_when_labels_same(window, monkeypatch):
    window.on_matrix(MatrixApi().matrix(24))
    drawn = []
    monkeypatch.setattr(window, "on_matrix", lambda data: drawn.append(data))
    state = {"nodes": [{"key": "a:443", "location": "Германия"}]}
    window.on_state(state)
    window.on_state(state)
    assert len(drawn) == 1


def test_trends_say_when_cut(window):
    node = {"node": "a:443", "scope": "Москва · MTS", "ok": True, "rate": 1.0, "checks": 5, "changed": 0}
    window.fill_trends([node], total=12)
    assert window.trends_shown.text() == "показано 1 из 12 - самые свежие"
    window.fill_trends([node], total=1)
    assert window.trends_shown.isHidden()


def test_fetch_trends_uses_paged_server_call(monkeypatch):
    server = agentapi.AgentServer("http://127.0.0.1:1", "t")
    asked = []
    monkeypatch.setattr(server, "_request", lambda method, path: asked.append(path)
                        or {"nodes": [{"node": "x"}], "total": 7})
    assert center.fetch_trends(server) == ([{"node": "x"}], 7)
    assert "limit=5000" in asked[0]


def test_trends_weekly_with_all_time_in_tip(window):
    node = {"node": "a:443", "scope": "Москва · MTS", "ok": True, "rate": 0.5, "checks": 4, "changed": 0,
            "checks_all": 200, "ok_checks_all": 150}
    window.fill_trends([node])
    headers = [window.trends_table.horizontalHeaderItem(col).text() for col in range(6)]
    assert "Живучесть за неделю" in headers and "Проверок за неделю" in headers
    assert "150 из 200" in window.trends_table.item(0, 3).toolTip()
    window.fill_trends([{**node, "checks_all": None}])
    assert window.trends_table.item(0, 3).toolTip() == ""


def test_matrix_cell_tip_for_partly_unchecked_and_dns_reason(window):
    data = MatrixApi().matrix(24)
    data["reasons"] = {"a:443": {"Москва · MTS": "dns-sinkhole"}}
    window.on_matrix(data)
    table = window.matrix
    rows = {table.item(row, 0).text(): row for row in range(table.rowCount())}
    tip = table.item(rows["a:443"], 1).toolTip()
    assert "в части отчётов не проверен: приложение не поддерживает настройки этого узла" in tip
    assert "DNS сети подменил адрес" in tip
    data["reasons"] = {"a:443": {"Москва · MTS": "dns-fail"}}
    data["unchecked"] = {}
    window.on_matrix(data)
    tip = window.matrix.item(0, 1).toolTip()
    assert "DNS сети не нашёл имя" in tip and "не проверен" not in tip
    data["reasons"] = {"a:443": {"Москва · MTS": "timeout"}}
    window.on_matrix(data)
    assert window.matrix.item(0, 1).toolTip() == ""


def test_matrix_says_real_span_when_truncated(window):
    now = time.time()
    data = {**MatrixApi().matrix(24), "truncated": True, "since": now - 5 * 86400}
    window.show_matrix_cut(data, now=now)
    assert not window.matrix_cut.isHidden()
    assert "только за 5 дн." in window.matrix_cut.text()
    window.show_matrix_cut({**data, "since": now - 7200}, now=now)
    assert "только за 2 ч" in window.matrix_cut.text()
    window.on_matrix({**data, "truncated": False})
    assert window.matrix_cut.isHidden()


def test_unchecked_reason_core_exit_without_code():
    from stand.ui.agent_dialog import unchecked_reason
    assert unchecked_reason("core-exit") == "ядро xray упало на этом узле"
    assert unchecked_reason("core-exit:") == "ядро xray упало на этом узле"
    assert unchecked_reason("core-exit:7") == "ядро xray упало на этом узле (код 7)"
    assert unchecked_reason("rejected") == "агент отказался: адрес узла ведёт в частную сеть или настройки небезопасны"
    assert unchecked_reason("core-direct") == "ядро xray не вышло в интернет через эту сеть"
    assert unchecked_reason("vpn") == "на телефоне включён VPN"


def test_report_doubt_core_direct_and_bind_ip():
    from stand.ui.agent_dialog import report_doubt
    blind = report_doubt({"payload": {"direct_ok": True, "core_direct_ok": False, "bind": "device"}})
    assert blind == "ядро xray не вышло в интернет через эту сеть, хотя обычный запрос прошёл - узлы не проверены"
    assert "только по адресу" in report_doubt({"bind": "ip", "payload": {}})
    assert report_doubt({"trusted": True, "bind": "device", "core_direct_ok": True, "payload": {}}) == ""


def test_agent_card_says_why_node_is_dead():
    from stand.ui.agent_dialog import dead_reasons
    payload = {"results": {"a:443": {"ok": False, "error": "dns-sinkhole"}, "b:443": {"ok": False, "error": "timeout"},
                           "c:443": {"ok": True}}}
    report = {"ts": time.time(), "alive": 1, "total": 3, "payload": payload}
    assert dead_reasons(report) == {"a:443": "DNS сети подменил адрес"}
    assert dead_reasons({**report, "dead_reasons": {"b:443": "dns-fail"}}) == {
        "b:443": "DNS сети не нашёл имя"}
    table = AgentDialog._build_reports_table([report])
    tip = table.item(0, 4).toolTip()
    assert "a:443 - DNS сети подменил адрес" in tip
    assert "b:443 -" not in tip


def test_agent_card_lists_unchecked_nodes(window, qtbot):
    from stand.ui.agent_dialog import unchecked_nodes
    payload = {"results": {"a:443": {"ok": True}, "b:443": {"ok": False, "unchecked": True, "error": "unsupported"}},
               "unchecked_nodes": {"c:443": "core-exit:9"}}
    assert unchecked_nodes(payload) == {"b:443": "приложение не поддерживает настройки этого узла",
                                        "c:443": "ядро xray упало на этом узле (код 9)"}
    report = {"ts": time.time(), "alive": 1, "total": 1, "payload": payload}
    dialog = AgentDialog({"agent_id": "0123456789abcdef", "last_seen": time.time()}, [report], window)
    qtbot.addWidget(dialog)
    table = AgentDialog._build_reports_table([report])
    assert table.item(0, 4).text() == "1 из 1 · не проверено 2"
    assert "⊘ c:443 - ядро xray упало на этом узле (код 9)" in table.item(0, 4).toolTip()
    dialog.close()


def test_trends_sort_by_name_without_recursion(window):
    nodes = [{"node": name, "scope": "Москва · MTS", "ok": True, "rate": 1.0, "checks": 5, "changed": 0}
             for name in ("b:443", "a:443", "c:443")]
    window.fill_trends(nodes)
    window.trends_table.sortItems(0)
    assert [window.trends_table.item(row, 0).text() for row in range(3)] == ["a:443", "b:443", "c:443"]


def test_server_errors_signed_as_server():
    entry = center._remote_error({"ts": 1, "agent_id": "", "model": "server", "kind": "telegram", "text": "x"})
    assert entry["source"] == "сервер"
    assert center.error_kind("telegram") == "Telegram: не отправлено"
    assert center.error_kind("backup") == "резервная копия"
    assert center._remote_error({"ts": 1, "agent_id": "0123456789", "model": "A07"})["source"] == "агент 01234567 · A07"


def test_silent_agent_is_muted_and_status_header_explains(window):
    now = time.time()
    assert center.agent_status({"last_seen": now - 13 * 3600}, now)[1] == center.theme.MUTED
    tip = window.agents_table.horizontalHeaderItem(0).toolTip()
    assert "молчит - дольше 12 ч" in tip and "дольше 7 дн" in tip


class AlertsApi:
    def __init__(self, answer):
        self.answer = answer
        self.paths = []

    def _request(self, method, path):
        self.paths.append((method, path))
        return self.answer


def test_alerts_fetched_plain_and_newest_first():
    api = AlertsApi({"alerts": [
        {"ts": 10, "kind": "down", "text": "<b>VPNCheck</b> узел &lt;a&gt; перестал отвечать"},
        {"ts": 20, "kind": "up", "text": "снова отвечает\nвторая строка"},
        {"ts": "x", "kind": "expiry", "text": ""}, "junk"]})
    alerts = center.fetch_alerts(api)
    assert api.paths == [("GET", "/v1/admin/alerts?limit=%d" % center.ALERTS_LIMIT)]
    assert [alert["text"] for alert in alerts] == ["снова отвечает\nвторая строка",
                                                   "VPNCheck узел <a> перестал отвечать"]
    assert center.fetch_alerts(AlertsApi({"alerts": None})) == []
    assert center.fetch_alerts(AlertsApi([])) == []


def test_alerts_block_in_stability(window):
    assert not window.alerts_hint.isHidden()
    window.fill_alerts([{"ts": time.time(), "kind": "down", "text": "первая\nвторая"}])
    assert window.alerts_table.rowCount() == 1
    assert window.alerts_table.item(0, 1).text() == "первая  …"
    assert window.alerts_table.item(0, 1).toolTip()
    assert window.alerts_hint.isHidden()


def test_alert_colors_expired_and_fleet_zero_red(window):
    from stand.ui import theme
    window.fill_alerts([{"ts": 3.0, "kind": "expired", "text": "учётка истекла"},
                        {"ts": 2.0, "kind": "expiry", "text": "VPNCheck ⛔ учётка истекла"},
                        {"ts": 1.0, "kind": "expiry", "text": "VPNCheck ⚠ истекает"},
                        {"ts": 0.5, "kind": "fleet_zero", "text": "0 у всех"}])
    colors = [window.alerts_table.item(row, 1).foreground().color().name() for row in range(4)]
    assert colors == [QColor(theme.RED).name(), QColor(theme.RED).name(), QColor(theme.AMBER).name(),
                      QColor(theme.RED).name()]


def test_empty_stability_gives_room_to_alerts(window):
    window.resize(1280, 800)
    window.trends_split.setSizes([500, 500])
    window.trends_empty = False
    window.fill_trends([], 0, 0)
    top, bottom = window.trends_split.sizes()
    assert bottom >= 2 * top
    node = {"node": "a:443", "scope": "Москва", "ok": 1, "rate": 0.5, "checks": 10, "changed": 0}
    window.fill_trends([node], 1)
    top, bottom = window.trends_split.sizes()
    assert abs(top - bottom) <= 2
    assert window.trends_table.item(0, 3).text() == "с перебоями 50%"


def test_pairing_warnings_above_qr_codes(window):
    from stand.ui import pairing
    dialog = pairing.PairingDialog("http://203.0.113.10:8787", "", window, app_missing=True, nodes_missing=True)
    layout = dialog.layout()
    order = [layout.itemAt(i).widget() for i in range(layout.count())]
    texts = [w.text() if isinstance(w, pairing.QLabel) else "" for w in order]
    first_layout = next(i for i in range(layout.count()) if layout.itemAt(i).layout() is not None)
    warns = [i for i, text in enumerate(texts) if text.startswith("⚠")]
    assert len(warns) == 3 and max(warns) < first_layout
    dialog.deleteLater()


def test_pairing_qr_carries_tls_from_agent_json(window, monkeypatch):
    from stand.ui import pairing
    pin = "sha256/" + "G" * 43 + "="
    agentapi.save_agent_config("http://203.0.113.10:8787", "t")
    agentapi.save_tls("203.0.113.10", 8788, pin)
    window.server.setText("http://203.0.113.10:8787")
    shown = []
    monkeypatch.setattr(center, "show_dialog", shown.append)
    window.show_pairing()
    assert "tp=" not in next(w for w in shown[0].findChildren(pairing.QLineEdit)).text()
    window.on_state({"nodes": [], "manifest": {"issued": 777, "tls": {"port": 8788, "pin": pin}, "signature": "s"}})
    shown.clear()
    window.show_pairing()
    field = next(w for w in shown[0].findChildren(pairing.QLineEdit))
    assert "&tp=8788&pin=sha256%2F" in field.text() and field.text().endswith("&ti=777")
    agentapi.save_tls()
    shown.clear()
    window.show_pairing()
    text = next(w for w in shown[0].findChildren(pairing.QLineEdit)).text()
    assert "tp=" not in text and "ti=777" in text
    for dialog in shown:
        dialog.deleteLater()


def test_https_agents_marked_and_counted(window):
    now = time.time()
    agents = [{"agent_id": "a" * 36, "last_seen": now, "app_version": "0.12.11", "https": True},
              {"agent_id": "b" * 36, "last_seen": now, "app_version": "0.12.7", "https": False}]
    window.on_agents(agents)
    versions = sorted(window.agents_table.item(row, 8).text() for row in range(2))
    assert versions[0].endswith(" · https") and not versions[1].endswith("https")
    chips = [window.chips.itemAt(i).widget().text() for i in range(window.chips.count())]
    assert "по https: 1 из 2" in chips


def test_lost_tls_port_is_loud_when_http_answers(window, qtbot, monkeypatch):
    pin = "sha256/" + "H" * 43 + "="
    window.server.setText("http://203.0.113.10:8787")
    window.token.setText("t")
    window.api = agentapi.AgentServer("http://203.0.113.10:8787", "t", tls={"port": 8788, "pin": pin})
    monkeypatch.setattr(agentapi.AgentServer, "health",
                        lambda self: {"ok": True, "tls": False} if not self.tls else None)
    window.health_failed(OSError("connection refused"))
    qtbot.waitUntil(lambda: "TLS-порт 8788" in window.status.text(), timeout=5000)
    assert "python server/deploy.py" in window.status.text()
    window.set_status("ok")
    assert window.status.styleSheet() == ""
    window.api = agentapi.AgentServer("http://203.0.113.10:8787", "t")
    window.health_failed(OSError("connection refused"))
    qtbot.wait(200)
    assert "TLS-порт" not in window.status.text()


def test_empty_matrix_explains_new_agents_wait_a_day(window):
    window.on_matrix({"columns": {}, "matrix": {}, "sites": {}})
    assert "через сутки" in window.matrix_hint.text()
    assert window.trends_hint.text() == window.matrix_hint.text()


def test_pairing_warns_when_app_or_nodes_missing(window, monkeypatch):
    from stand.ui import pairing
    seen = []
    monkeypatch.setattr(center, "show_dialog", lambda dialog: seen.append(dialog) or 0)
    window.server.setText("http://203.0.113.10:8787")
    window.show_pairing()

    def texts(dialog):
        return " ".join(label.text() for label in dialog.findChildren(pairing.QLabel))
    assert "нет приложения" not in texts(seen[-1])
    window.on_state({"nodes": [], "manifest": {}})
    window.show_pairing()
    assert "нет приложения" in texts(seen[-1]) and "Узлы для агентов не выложены" in texts(seen[-1])
    window.on_state({"nodes": [{"key": "a:443"}], "manifest": {"app": {"url": "/files/a.apk", "version_name": "1"}}})
    window.show_pairing()
    assert "нет приложения" not in texts(seen[-1]) and "не выложены" not in texts(seen[-1])
    for dialog in seen:
        dialog.deleteLater()


def test_empty_views_count_new_agents(window):
    window.on_matrix({"columns": {}, "matrix": {}, "sites": {}, "new_agents": 2})
    assert "Новых агентов: 2 - появятся здесь в течение суток после подключения" in window.matrix_hint.text()
    window.on_matrix({"columns": {}, "matrix": {}, "sites": {}, "new_agents": 0})
    assert "Новых агентов" not in window.matrix_hint.text()
    window.fill_trends([], 0, 3)
    assert "Новых агентов: 3" in window.trends_hint.text()


def test_trends_ask_new_agents_only_when_empty():
    class Api:
        def __init__(self, nodes):
            self.nodes, self.paths = nodes, []

        def trends(self, limit):
            return self.nodes, len(self.nodes)

        def _request(self, method, path):
            self.paths.append(path)
            return {"nodes": [], "total": 0, "new_agents": 4}
    empty = Api([])
    assert center.fetch_trends_with_new(empty) == ([], 0, 4)
    full = Api([{"node": "x"}])
    assert center.fetch_trends_with_new(full) == ([{"node": "x"}], 1, 0) and not full.paths


def test_alert_kinds_colored():
    assert center.ALERT_COLORS["flap"] == center.theme.AMBER
    assert center.ALERT_COLORS["more"] == center.theme.MUTED
    assert center.ALERT_COLORS["db_room"] == center.theme.RED
