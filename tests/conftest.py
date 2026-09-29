"""Общее для всех тестов. Язык интерфейса фиксируем (тесты сверяют русские тексты). Папка данных стенда
(%APPDATA%\\VPNCheckStand: история прогонов, настройки, ключи) - временная ещё до импорта stand: пути в
stand.storage считаются при импорте, и поток, переживший свой тест, иначе дописал бы прогон в настоящую
историю. Каждому тесту - своя APPDATA."""
import os
import shutil
import tempfile

import pytest

os.environ["VPNCHECK_LANG"] = "ru"
SESSION_APPDATA = tempfile.mkdtemp(prefix="vpncheck-tests-")
os.environ["APPDATA"] = SESSION_APPDATA


@pytest.fixture(autouse=True)
def isolated_appdata(tmp_path, monkeypatch):
    appdata = tmp_path / "appdata"
    appdata.mkdir()
    monkeypatch.setenv("APPDATA", str(appdata))
    return appdata


def pytest_sessionfinish(session, exitstatus):
    shutil.rmtree(SESSION_APPDATA, ignore_errors=True)
