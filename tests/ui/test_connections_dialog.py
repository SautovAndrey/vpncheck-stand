"""«Подключения»: проверку панели можно не дожидаться - закрытый диалог не роняет программу."""
import threading

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QWidget

from stand import storage
from stand.ui import connections


class Owner(QWidget):
    def __init__(self):
        super().__init__()
        self.tasks = []


class SlowPanel:
    gate = threading.Event()

    @classmethod
    def from_config(cls, _config):
        return cls()

    def squads(self):
        SlowPanel.gate.wait(10)
        return [{"name": "S1"}]


@pytest.fixture
def owner(qtbot):
    widget = Owner()
    qtbot.addWidget(widget)
    yield widget
    SlowPanel.gate.set()
    for task in list(widget.tasks):
        task.wait(10000)


def test_closed_dialog_ignores_late_answer(owner, qtbot, monkeypatch):
    storage.save_connections({"panels": {"main": {"url": "https://p", "token": "t" * 20}}, "probe": {}})
    monkeypatch.setattr(connections, "Panel", SlowPanel)
    SlowPanel.gate.clear()
    dialog = connections.ConnectionsDialog(owner)
    dialog.setAttribute(Qt.WA_DeleteOnClose)
    dialog.show()
    dialog.table.selectRow(0)
    dialog.test_panel()
    assert len(owner.tasks) == 1 and not dialog.tasks
    dialog.close()
    qtbot.wait(50)
    SlowPanel.gate.set()
    qtbot.waitUntil(lambda: not owner.tasks, timeout=5000)
    qtbot.wait(50)


def test_open_dialog_shows_answer(owner, qtbot, monkeypatch):
    storage.save_connections({"panels": {"main": {"url": "https://p", "token": "t" * 20}}, "probe": {}})
    monkeypatch.setattr(connections, "Panel", SlowPanel)
    SlowPanel.gate.set()
    dialog = connections.ConnectionsDialog(owner)
    qtbot.addWidget(dialog)
    dialog.show()
    dialog.table.selectRow(0)
    dialog.test_panel()
    qtbot.waitUntil(lambda: "S1" in dialog.status.text(), timeout=5000)


def test_probe_hint_wraps(owner):
    dialog = connections.ConnectionsDialog(owner)
    dialog.adjustSize()
    assert dialog.sizeHint().width() <= 1000
    dialog.deleteLater()
