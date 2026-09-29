"""Сценарии окон на pytest-qt. Без экрана (offscreen), без adb, сети и настоящей папки настроек."""
import os
import sys
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("QTWEBENGINE_CHROMIUM_FLAGS", "--disable-gpu")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import pytest  # noqa: E402
from PySide6.QtCore import Signal  # noqa: E402
from PySide6.QtWidgets import QApplication, QWidget  # noqa: E402

from stand import agentapi, errorlog, geo, runlock, storage  # noqa: E402
from stand.adb import AdbError  # noqa: E402
from stand.ui import center as center_module  # noqa: E402
from stand.ui import main_window as main_module  # noqa: E402
from stand.ui import mapscheme  # noqa: E402


class NoAdb:
    def __init__(self, *_args, **_kwargs):
        raise AdbError("adb в тестах не нужен")


class FakePage:
    def __init__(self):
        self.scripts = []

    def runJavaScript(self, script):
        self.scripts.append(script)


class FakeWebSettings:
    def setAttribute(self, *_args):
        pass


class FakeView(QWidget):
    """Карта центра без QtWebEngine: на машине без экрана и GPU он не нужен."""
    loadFinished = Signal(bool)
    renderProcessTerminated = Signal(object, int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._page = FakePage()
        self.urls = []

    def settings(self):
        return FakeWebSettings()

    def page(self):
        return self._page

    def load(self, url):
        self.urls.append(url)


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    app_dir = str(tmp_path / "VPNCheckStand")
    os.makedirs(app_dir)
    monkeypatch.setattr(storage, "APP_DIR", app_dir)
    monkeypatch.setattr(storage, "RUNS_DIR", os.path.join(app_dir, "runs"))
    monkeypatch.setattr(storage, "SETTINGS_PATH", os.path.join(app_dir, "settings.json"))
    monkeypatch.setattr(storage, "CONNECTIONS_PATH", os.path.join(app_dir, "connections.json"))
    monkeypatch.setattr(agentapi, "AGENT_CONFIG", os.path.join(app_dir, "agent.json"))
    monkeypatch.setattr(agentapi, "KEY_PATH", os.path.join(app_dir, "keys", "manifest_ed25519.key"))
    monkeypatch.setattr(agentapi, "PUB_PATH", os.path.join(app_dir, "keys", "manifest_ed25519.pub"))
    monkeypatch.setattr(errorlog, "LOG_PATH", os.path.join(app_dir, "errors.log"))
    monkeypatch.setattr(runlock, "LOCK_PATH", os.path.join(app_dir, "phone.lock"))
    monkeypatch.setattr(geo, "CACHE_PATH", os.path.join(app_dir, "geo_cache.json"))
    monkeypatch.setattr(geo, "_cache", None)
    monkeypatch.setattr(geo, "lookup_many", lambda hosts, workers=8: {})
    monkeypatch.setattr(main_module, "Adb", NoAdb)
    monkeypatch.setattr(main_module, "fetch_sites", lambda fallback: fallback)
    monkeypatch.setattr(center_module, "QWebEngineView", FakeView)
    monkeypatch.setattr(mapscheme, "install", lambda: None)
    return app_dir


@pytest.fixture
def quit_calls(monkeypatch):
    calls = []
    monkeypatch.setattr(QApplication, "quit", staticmethod(lambda: calls.append(time.time())))
    return calls
