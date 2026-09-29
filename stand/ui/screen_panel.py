"""Экран телефона внутри программы: окно scrcpy встраивается в панель Qt.

scrcpy рисует экран Android по ADB и передаёт нажатия мыши как касания. Мы запускаем его
с известным заголовком окна, находим окно через WinAPI и «усыновляем» его в наш виджет.
"""
import ctypes
import ctypes.wintypes
import functools
import glob
import os
import shutil
import subprocess
import sys

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QCursor
from PySide6.QtWidgets import QVBoxLayout, QWidget

from ..adb import CREATE_NO_WINDOW
from ..i18n import t
from ..storage import APP_DIR
from .widgets import muted

SCRCPY_LOG = os.path.join(APP_DIR, "scrcpy.log")

WINDOW_TITLE = "VPNCheckStand-PhoneScreen"


def find_scrcpy():
    found = shutil.which("scrcpy")
    if found:
        return found
    local = os.environ.get("LOCALAPPDATA", "")
    hits = glob.glob(os.path.join(local, "Microsoft", "WinGet", "Packages", "Genymobile.scrcpy*", "**", "scrcpy.exe"),
                     recursive=True)
    return hits[0] if hits else None


GWL_STYLE = -16
WS_CHILD = 0x40000000
WS_VISIBLE = 0x10000000
WS_POPUP = 0x80000000
WS_CAPTION = 0x00C00000
WS_THICKFRAME = 0x00040000
SWP_FRAMECHANGED = 0x0020
SWP_NOZORDER = 0x0004
SWP_SHOWWINDOW = 0x0040


@functools.cache
def _user32():
    user32 = ctypes.windll.user32
    types = ctypes.wintypes
    user32.FindWindowW.argtypes = [types.LPCWSTR, types.LPCWSTR]
    user32.FindWindowW.restype = types.HWND
    user32.GetWindowLongW.argtypes = [types.HWND, ctypes.c_int]
    user32.GetWindowLongW.restype = types.LONG
    user32.SetWindowLongW.argtypes = [types.HWND, ctypes.c_int, types.LONG]
    user32.SetWindowLongW.restype = types.LONG
    user32.SetParent.argtypes = [types.HWND, types.HWND]
    user32.SetParent.restype = types.HWND
    user32.SetWindowPos.argtypes = [types.HWND, types.HWND, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                    types.UINT]
    user32.SetWindowPos.restype = types.BOOL
    user32.MoveWindow.argtypes = [types.HWND, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, types.BOOL]
    user32.MoveWindow.restype = types.BOOL
    user32.GetWindowThreadProcessId.argtypes = [types.HWND, ctypes.POINTER(types.DWORD)]
    user32.GetWindowThreadProcessId.restype = types.DWORD
    user32.AttachThreadInput.argtypes = [types.DWORD, types.DWORD, types.BOOL]
    user32.AttachThreadInput.restype = types.BOOL
    user32.SetFocus.argtypes = [types.HWND]
    user32.SetFocus.restype = types.HWND
    user32.GetForegroundWindow.argtypes = []
    user32.GetForegroundWindow.restype = types.HWND
    user32.GetAncestor.argtypes = [types.HWND, types.UINT]
    user32.GetAncestor.restype = types.HWND
    return user32


def focus_window(hwnd):
    """Отдать клавиатуру окну другого процесса: SetFocus работает только после AttachThreadInput."""
    user32 = _user32()
    target = user32.GetWindowThreadProcessId(hwnd, None)
    own = ctypes.windll.kernel32.GetCurrentThreadId()
    if not target or target == own:
        return bool(user32.SetFocus(hwnd))
    user32.AttachThreadInput(own, target, True)
    try:
        return bool(user32.SetFocus(hwnd))
    finally:
        user32.AttachThreadInput(own, target, False)


class ScreenHost(QWidget):
    """Нативный виджет-хозяин: окно scrcpy делается его дочерним окном (SetParent) и растягивается."""

    def __init__(self, hwnd, parent=None):
        super().__init__(parent)
        self.hwnd = hwnd
        self.setAttribute(Qt.WA_NativeWindow)
        self.setMinimumSize(280, 560)
        user32 = _user32()
        style = user32.GetWindowLongW(hwnd, GWL_STYLE) & 0xFFFFFFFF
        style = (style & ~(WS_POPUP | WS_CAPTION | WS_THICKFRAME)) | WS_CHILD | WS_VISIBLE
        user32.SetWindowLongW(hwnd, GWL_STYLE, ctypes.c_int32(style & 0xFFFFFFFF).value)
        user32.SetParent(hwnd, int(self.winId()))
        user32.SetWindowPos(hwnd, None, 0, 0, self.width(), self.height(),
                            SWP_FRAMECHANGED | SWP_NOZORDER | SWP_SHOWWINDOW)

        self.setMouseTracking(True)
        self.hover = QTimer(self)
        self.hover.setInterval(250)
        self.hover.timeout.connect(self._follow_cursor)
        self.hover.start()
        self._focused = False

    def _follow_cursor(self):
        user32 = _user32()
        top = user32.GetForegroundWindow()
        if not top or user32.GetAncestor(self.hwnd, 2) != top:
            self._focused = False
            return
        pos = QCursor.pos()
        inside = self.rect().contains(self.mapFromGlobal(pos))
        if inside and not self._focused:
            self._focused = focus_window(self.hwnd)
        elif not inside and self._focused:
            focus_window(int(self.window().winId()))
            self._focused = False

    def resizeEvent(self, event):
        super().resizeEvent(event)
        _user32().MoveWindow(self.hwnd, 0, 0, self.width(), self.height(), True)


class PhoneScreen(QWidget):
    """Панель с живым экраном телефона. start() запускает scrcpy, stop() закрывает."""

    def __init__(self, adb_path, log=None, parent=None):
        super().__init__(parent)
        self.adb_path = adb_path
        self.serial = ""
        self.log = log or (lambda text: None)
        self.process = None
        self.container = None
        self.hwnd = None
        self.attempts = 0
        self.restarts = 0
        self.wanted = False
        self.log_handle = None
        self.layout_ = QVBoxLayout(self)
        self.layout_.setContentsMargins(0, 0, 0, 0)
        self.layout_.setSpacing(6)
        self.status = muted(t("экран выключен"))
        self.hint = muted(t("курсор над экраном - клавиатура печатает в телефон"))
        self.hint.setAlignment(Qt.AlignCenter)
        self.hint.setWordWrap(True)
        self.hint.setVisible(False)
        self.status.setAlignment(Qt.AlignCenter)
        self.status.setWordWrap(True)
        self.layout_.addWidget(self.status)
        self.layout_.addWidget(self.hint)
        self.layout_.addStretch()
        self.timer = QTimer(self)
        self.timer.setInterval(300)
        self.timer.timeout.connect(self._poll_window)
        self.watchdog = QTimer(self)
        self.watchdog.setInterval(2000)
        self.watchdog.timeout.connect(self._watch_process)
        self.watchdog.start()
        self.setMinimumWidth(300)

    def start(self, max_size=900):
        if self.process and self.process.poll() is None:
            return
        scrcpy = find_scrcpy()
        if not scrcpy:
            self.status.setText(t("scrcpy не найден: winget install Genymobile.scrcpy"))
            return
        env = dict(os.environ)
        if self.adb_path:
            env["ADB"] = self.adb_path
        args = [scrcpy, "--window-title", WINDOW_TITLE, "--window-borderless", "--max-size", str(max_size),
                "--stay-awake", "--no-audio", "--window-x", "-32000", "--window-y", "-32000"]
        if self.serial:
            args += ["--serial", self.serial]
        self.wanted = True
        self._close_log()
        try:
            os.makedirs(APP_DIR, exist_ok=True)
            self.log_handle = open(SCRCPY_LOG, "w", encoding="utf-8")
            self.process = subprocess.Popen(args, env=env, stdout=self.log_handle, stderr=subprocess.STDOUT,
                                            creationflags=CREATE_NO_WINDOW)
        except OSError as exc:
            self._close_log()
            self.status.setText(t("не удалось запустить scrcpy: %s") % exc)
            return
        self.status.setText(t("запускаю экран…"))
        self.attempts = 0
        self.timer.start()
        self.log(t("экран телефона: scrcpy запущен"))

    def stop(self):
        self.wanted = False
        self.restarts = 0
        self.timer.stop()
        if self.container:
            self.layout_.removeWidget(self.container)
            self.container.deleteLater()
            self.container = None
        if self.process and self.process.poll() is None:
            self.process.terminate()
        self.process = None
        self._close_log()
        self.hwnd = None
        self.status.setText(t("экран выключен"))
        self.status.setVisible(True)
        self.hint.setVisible(False)

    def set_serial(self, serial):
        """Переключить экран на другой телефон; если экран открыт - перезапустить на новом."""
        if serial == self.serial:
            return
        self.serial = serial
        if self.is_running():
            self.stop()
            self.start()

    def is_running(self):
        return bool(self.process and self.process.poll() is None)

    def _poll_window(self):
        self.attempts += 1
        if not self.is_running():
            self.timer.stop()
            self.process = None
            reason = self._last_log_line()
            self._close_log()
            self.log(t("экран телефона: scrcpy завершился%s") % ((" - " + reason) if reason else ""))
            if self.wanted and self.restarts < 3:
                self.restarts += 1
                self.status.setText(t("экран оборвался, перезапускаю (%d)…") % self.restarts)
                self.status.setVisible(True)
                QTimer.singleShot(3000, self._restart)
            else:
                self.status.setText(t("scrcpy завершился: %s") % (reason or t("телефон подключён?")))
                self.status.setVisible(True)
            return
        if sys.platform != "win32":
            return
        hwnd = _user32().FindWindowW(None, WINDOW_TITLE)
        if not hwnd:
            if self.attempts > 60:
                self.timer.stop()
                self.status.setText(t("окно scrcpy не появилось за 18 с"))
            return
        self.timer.stop()
        self.restarts = 0
        self.hwnd = hwnd
        self.container = ScreenHost(hwnd, self)
        self.layout_.insertWidget(0, self.container, 1)
        self.status.setVisible(False)
        self.hint.setVisible(True)
        self.log(t("экран телефона встроен в окно"))

    def _watch_process(self):
        if self.wanted and self.process is not None and not self.timer.isActive() and not self.is_running():
            self._poll_window()

    def _restart(self):
        if self.wanted and not self.is_running():
            if self.container:
                self.layout_.removeWidget(self.container)
                self.container.deleteLater()
                self.container = None
            self.start()

    def _close_log(self):
        """Файл журнала scrcpy открыт на время жизни процесса - закрыть, иначе каждый перезапуск его терял."""
        if self.log_handle:
            self.log_handle.close()
            self.log_handle = None

    def _last_log_line(self):
        try:
            if self.log_handle:
                self.log_handle.flush()
            with open(SCRCPY_LOG, encoding="utf-8", errors="replace") as handle:
                lines = [line.strip() for line in handle if line.strip()]
            for line in reversed(lines):
                if "ERROR" in line or "WARN" in line:
                    return line[:160]
            return lines[-1][:160] if lines else ""
        except OSError:
            return ""

    def closeEvent(self, event):
        self.stop()
        super().closeEvent(event)
