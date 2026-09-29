"""Главное окно: телефон слева, таблица узлов справа, журнал снизу."""
import html
import json
import os
import re
import sys
import time
from collections import Counter

from PySide6.QtCore import QProcess, Qt, QTimer
from PySide6.QtGui import QAction, QActionGroup, QColor, QFont
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QComboBox,
    QCompleter,
    QDialog,
    QDockWidget,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from .. import errorlog, geo, i18n, multiphone, portlock, runlock, storage, subscription
from ..adb import Adb, AdbError
from ..checker import WHITELIST_IP, unchecked_count, unchecked_note
from ..i18n import t
from ..phone import PhoneControl, PhoneState, saved_number
from ..xray import PhoneXray
from . import theme
from .dialogs import HistoryCombo, SettingsDialog, TextDialog
from .phone_panel import NetworksPanel, PhonePanel, restyle
from .screen_panel import PhoneScreen
from .widgets import FlowLayout, SortItem, cell_text, chip, fill_squad_combo, muted
from .workers import PhonePoller, run_task

FIXED_COLUMNS = ["Локация", "Узел", "IP", "Хостер", "SNI"]
COL_KEY, COL_IP, COL_HOSTER, COL_SNI = 1, 2, 3, 4
FIXED_WIDTHS = (190, 180, 130, 180, 130)
BRIEF_HIDDEN = (COL_SNI,)
ORDER_ALIVE, ORDER_RETRY, ORDER_WHITELIST, ORDER_DEAD, ORDER_EMPTY = 1e5, 2e5, 3e5, 4e5, 5e5
ORDER_SLOW, ORDER_UNCHECKED = 1.5e5, 3.5e5
SOURCE_NAMES = {"url": "URL подписки", "file": "Файл", "подписка": "подписка"}


DEMO_HOSTERS = {"203.0.113.21": ("Example Hosting GmbH", "DE"), "203.0.113.22": ("Example Hosting GmbH", "DE"),
                "198.51.100.31": ("Sample Cloud B.V.", "NL"), "198.51.100.45": ("Demo Net Sp. z o.o.", "PL"),
                "192.0.2.61": ("Test Datacenter AG", "CH"), "192.0.2.62": ("Test Datacenter AG", "CH"),
                "203.0.113.71": ("Nordic Example Oy", "FI"), "198.51.100.81": ("Alpine Demo GmbH", "AT"),
                "198.51.100.82": ("Alpine Demo GmbH", "AT")}

DEMO_DEAD = "192.0.2.62"
CONTACT_URL = "https://t.me/joodjoy"
REPO_URL = "https://github.com/SautovAndrey/vpncheck-stand"

def fetch_sites(fallback):
    """Сайты для проверки без VPN с сервера агентов; сервер недоступен - прежний список."""
    try:
        from .. import agentapi
        return agentapi.connect_from_config().state().get("sites") or []
    except Exception:  # noqa: BLE001 - сервер недоступен: сайты берём из прошлого раза
        return fallback


def run_paths(limit=50):
    """Файлы прогонов, новые первыми - только имена, без чтения: список истории строится из кэша подписей."""
    if not os.path.isdir(storage.RUNS_DIR):
        return []
    names = sorted((name for name in os.listdir(storage.RUNS_DIR) if name.endswith(".json")), reverse=True)
    return [os.path.join(storage.RUNS_DIR, name) for name in names[:limit]]


def read_run(path):
    try:
        with open(path, encoding="utf-8") as handle:
            run = json.load(handle)
    except (OSError, ValueError):
        return None
    return run if isinstance(run, dict) else None


class RunLabels:
    """Подписи прогонов для списка истории: файл читается заново, только если он изменился."""

    def __init__(self):
        self._cache = {}

    def label(self, path):
        try:
            stat = os.stat(path)
        except OSError:
            return None
        stamp = (stat.st_mtime_ns, stat.st_size)
        cached = self._cache.get(path)
        if cached and cached[0] == stamp:
            return cached[1]
        run = read_run(path)
        if run is None:
            return None
        label = storage.run_label(run)
        self._cache[path] = (stamp, label)
        return label

    def entries(self, limit=50):
        paths = run_paths(limit)
        for stale in set(self._cache) - set(paths):
            del self._cache[stale]
        return [(path, label) for path in paths for label in [self.label(path)] if label is not None]


def is_site(target):
    return bool(target.get("site_url")) or str(target.get("key", "")).startswith("🌐 ")


def mode_keys(modes, targets):
    """Строки, которые проверяет каждая колонка: ДЦ сайты не проверяет, телефоны - всё."""
    every = {target["key"] for target in targets}
    nodes = {target["key"] for target in targets if not is_site(target)}
    result = {}
    for mode in modes:
        kind = mode.get("kind") if isinstance(mode, dict) else mode.kind
        result[mode["id"] if isinstance(mode, dict) else mode.id] = nodes if kind == "dc" else every
    return result


class MainWindow(QMainWindow):
    def __init__(self, demo=False):
        super().__init__()
        self.setWindowTitle(t("VPNCheck Stand - телефон как стенд проверки"))
        self.resize(1380, 860)
        self.settings = storage.load_settings()
        self.connections = storage.load_connections()
        self.targets = []
        self.release_subscription = None
        self.worker = None
        self.tasks = []
        self.phone_busy = False
        self.run_source = ("", "")
        self.mode_keys = {}
        self.closing = False
        self.close_deadline = 0
        self.restart_args = None
        self.phone_state = PhoneState()
        self.mode_columns = {}
        self.mode_kinds = {}
        self.mode_chips = {}
        self.mode_ips = {}
        self.mode_results = {}
        self.row_by_key = {}
        self.whitelisted = set()
        self.final_cells = set()
        self.total_cells = 0
        self.run_parts, self.run_left = [], 0
        self.run_windows = []
        self.loading = False
        self.cell_states = {}
        self.cell_counts = {}
        self.finished_modes = set()
        self.demo = demo
        self.run_labels = RunLabels()
        self.center = None
        self.adb = None
        self.base_adb = None
        self.adb_error = ""
        self.phones = []
        self.selected_serial = self.settings.get("phone_serial", "")
        try:
            if not demo:
                self.base_adb = Adb()
                self.adb = self.base_adb
        except AdbError as exc:
            self.adb_error = str(exc)

        self._build_menu()
        self._build_body()
        self.fit_canvas()
        self.statusBar().showMessage(self.adb_error or ("adb: %s" % self.adb.path if self.adb else ""))
        if not self.base_adb and not demo:
            self.phone.show_adb_missing()
        self.poller = None
        if self.base_adb:
            self.poller = PhonePoller(self.base_adb, int(self.settings["poll_seconds"]))
            self.poller.states.connect(self.on_phone_states)
            self.poller.start()
        self.networks.rebuild(None, self.dc_label())
        self.reload_history()
        self.history_timer = QTimer(self)
        self.history_timer.setInterval(20000)
        self.history_timer.timeout.connect(self.show_newest_run)
        self.history_timer.start()
        runs = run_paths(limit=1)
        self.shown_run_path = runs[0] if runs else None
        if runs:
            self.run_title.setText(
                t("Загрузите узлы и нажмите «Проверить». Прошлые прогоны - в списке «История прогонов»."))


    def _build_menu(self):
        menu = self.menuBar()
        file_menu = menu.addMenu(t("Файл"))
        file_menu.addAction(self._action(t("Подключения (панели, пробник ДЦ)…"), self.open_connections))
        file_menu.addAction(self._action(t("Настройки…"), self.open_settings))
        file_menu.addAction(self._action(t("Папка с историей"), lambda: os.startfile(storage.APP_DIR)
                                         if os.path.isdir(storage.APP_DIR) else None))
        file_menu.addSeparator()
        file_menu.addAction(self._action(t("Выход"), self.close))
        phone_menu = menu.addMenu(t("Телефон"))
        phone_menu.addAction(self._action(t("Диагностика (сырые выводы adb)"), self.run_diagnostics))
        phone_menu.addAction(self._action(t("Залить / обновить xray на телефоне"), self.install_xray))
        phone_menu.addAction(self._action(t("Остановить xray на телефоне"), self.kill_xray))
        phone_menu.addSeparator()
        self.screen_action = QAction(t("Экран телефона"), self)
        self.screen_action.setCheckable(True)
        self.screen_action.toggled.connect(self.toggle_screen)
        phone_menu.addAction(self.screen_action)
        phone_menu.addAction(self._action(t("Открыть капчу оператора (белые списки)"), self.open_captcha))
        center_menu = menu.addMenu(t("Агенты"))
        center_menu.addAction(self._action(t("Центр управления агентами"), self.open_center))
        self._build_language_menu(menu)
        help_menu = menu.addMenu(t("Справка"))
        help_menu.addAction(self._action(t("Как подключить новый телефон"), self.show_new_phone_help))
        help_menu.addSeparator()
        help_menu.addAction(self._action(t("О программе"), self.about))

    def _build_language_menu(self, menu):
        language_menu = menu.addMenu("🌐 Язык / Language")
        group = QActionGroup(self)
        current = self.settings.get("language", "auto")
        for code, label in i18n.LANGUAGES:
            action = QAction(label, self, checkable=True)
            action.setChecked(code == current)
            action.triggered.connect(lambda _checked=False, code=code: self.set_language(code))
            group.addAction(action)
            language_menu.addAction(action)

    def set_language(self, code):
        if code == self.settings.get("language", "auto"):
            return
        self.settings["language"] = code
        storage.save_settings(self.settings)
        answer = QMessageBox.question(self, "VPNCheck Stand",
                                      "Перезапустить программу, чтобы сменить язык?\n"
                                      "Restart the program to change the language?")
        if answer == QMessageBox.Yes:
            self.restart()

    def restart(self):
        self.restart_args = [os.path.abspath(sys.argv[0])] + sys.argv[1:]
        self.close()

    def _action(self, text, handler):
        action = QAction(text, self)
        action.triggered.connect(handler)
        return action

    def _build_body(self):
        central = QWidget()
        central.setMinimumSize(1180, 700)
        scroll = QScrollArea()
        scroll.setObjectName("windowScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setWidget(central)
        self.setCentralWidget(scroll)
        self.setMinimumSize(720, 520)
        self.canvas = central
        root = QHBoxLayout(central)
        root.setContentsMargins(14, 12, 14, 8)
        root.setSpacing(14)
        root.addWidget(self._build_left())
        root.addLayout(self._build_right(), 1)
        self._build_status_bar()
        self._build_screen_dock()
        self.toggle_detail(self.detail_toggle.isChecked())

    def _build_left(self):
        """Левая колонка: карточка телефона (кнопки управления им) и выбор сетей для проверки."""
        left = QVBoxLayout()
        left.setSpacing(12)
        self.phone = PhonePanel()
        self.phone.wifi_clicked.connect(lambda on: self.phone_command("Wi-Fi", lambda c: c.set_wifi(on)))
        self.phone.mobile_data_clicked.connect(
            lambda on: self.phone_command(t("мобильные данные"), lambda c: c.set_mobile_data(on)))
        self.phone.airplane_clicked.connect(
            lambda on: self.phone_command(t("режим полёта"), lambda c: c.set_airplane(on)))
        self.phone.data_sim_requested.connect(self.switch_data_sim)
        self.phone.new_ip_requested.connect(self.new_ip)
        self.phone.check_ip_requested.connect(self.check_ip)
        self.phone.sim_manager_requested.connect(
            lambda: self.phone_command(t("диспетчер SIM"), lambda c: c.open_sim_manager()))
        self.phone.sim_money_requested.connect(self.check_sim_money)
        self.phone.phone_selected.connect(self.select_phone)
        self.networks = NetworksPanel()
        left.addWidget(self.phone)
        left.addWidget(self.networks)
        left.addStretch()
        left_widget = QWidget()
        left_widget.setLayout(left)
        left_widget.setFixedWidth(360)
        return left_widget

    def _build_right(self):
        """Правая часть: панель источника и прогона, прогресс, заголовок, плашки сетей, таблица с журналом."""
        right = QVBoxLayout()
        right.setSpacing(10)
        right.addLayout(self._build_toolbar())
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setFixedHeight(6)
        self.progress.setTextVisible(False)
        right.addWidget(self.progress)
        right.addLayout(self._build_title_row())
        self.chips = FlowLayout()
        right.addLayout(self.chips)
        right.addWidget(self._build_results(), 1)
        return right

    def _build_title_row(self):
        """Заголовок прогона и кнопка «Копировать таблицу» с выбором формата."""
        title_row = QHBoxLayout()
        self.run_title = QLabel("")
        self.run_title.setObjectName("cardTitle")
        title_row.addWidget(self.run_title)
        title_row.addStretch()
        self.copy_button = QPushButton(t("⧉ Копировать таблицу"))
        copy_menu = QMenu(self.copy_button)
        copy_menu.addAction(t("Как текст (для чата)"), lambda: self.copy_table("text"))
        copy_menu.addAction(t("Как Markdown (для заметки)"), lambda: self.copy_table("markdown"))
        copy_menu.addAction(t("Как CSV (для Excel)"), lambda: self.copy_table("csv"))
        self.copy_button.setMenu(copy_menu)
        title_row.addWidget(self.copy_button)
        return title_row

    def _build_results(self):
        """Таблица узлов со строкой «Итого» под ней, ниже - журнал прогона (делятся сплиттером)."""
        splitter = QSplitter(Qt.Vertical)
        self._build_table()
        table_box = QWidget()
        table_layout = QVBoxLayout(table_box)
        table_layout.setContentsMargins(0, 0, 0, 0)
        table_layout.setSpacing(0)
        table_layout.addWidget(self.table, 1)
        self._build_totals()
        table_layout.addWidget(self.totals)
        splitter.addWidget(table_box)
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumBlockCount(3000)
        self.log.setPlaceholderText(t("журнал прогона"))
        splitter.addWidget(self.log)
        splitter.setSizes([600, 160])
        self.log.setVisible(bool(self.settings.get("log_visible", True)))
        return splitter

    def _build_table(self):
        """Таблица узлов: постоянные колонки, колонки сетей добавляются при прогоне; пока пусто - подсказка."""
        self.table = QTableWidget(0, len(FIXED_COLUMNS))
        self.table.setHorizontalHeaderLabels([t(c) for c in FIXED_COLUMNS])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setAlternatingRowColors(False)
        self.table.setShowGrid(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        for col, width in enumerate(FIXED_WIDTHS):
            self.table.setColumnWidth(col, width)
        self.resort_timer = QTimer(self)
        self.resort_timer.setSingleShot(True)
        self.resort_timer.setInterval(300)
        self.resort_timer.timeout.connect(lambda: self.table.setSortingEnabled(True))
        self.placeholder = QLabel(t("Загрузите узлы, отметьте сети слева и нажмите «Проверить».\n"
                                    "Каждая сеть станет отдельной колонкой: зелёное - узел открылся, "
                                    "красное - не ответил из этой сети."),
                                  self.table.viewport())
        self.placeholder.setObjectName("muted")
        self.placeholder.setAlignment(Qt.AlignCenter)
        self.placeholder.setWordWrap(True)
        self.table.viewport().installEventFilter(self)
        self.table.model().layoutChanged.connect(self.reindex_rows)
        self.table.model().rowsMoved.connect(self.reindex_rows)

    def _build_totals(self):
        """Строка «Итого» под таблицей: ширина колонок и прокрутка повторяют таблицу."""
        self.totals = QTableWidget(1, len(FIXED_COLUMNS))
        self.totals.setObjectName("totals")
        self.totals.horizontalHeader().setVisible(False)
        self.totals.verticalHeader().setVisible(False)
        self.totals.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.totals.setSelectionMode(QAbstractItemView.NoSelection)
        self.totals.setShowGrid(False)
        self.totals.setFixedHeight(40)
        self.totals.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.totals.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.totals.setFocusPolicy(Qt.NoFocus)
        self.table.horizontalHeader().sectionResized.connect(
            lambda index, _old, new: self.totals.setColumnWidth(index, new))
        self.table.horizontalScrollBar().valueChanged.connect(self.totals.horizontalScrollBar().setValue)

    def _build_status_bar(self):
        """Переключатели в строке состояния: журнал, подробные колонки узла, экран телефона."""
        status_right = QWidget()
        status_layout = QHBoxLayout(status_right)
        status_layout.setContentsMargins(0, 0, 8, 0)
        self.log_toggle = QPushButton(t("Журнал"))
        self.log_toggle.setObjectName("flat")
        self.log_toggle.setCheckable(True)
        self.log_toggle.setChecked(self.log.isVisible())
        self.log_toggle.toggled.connect(self.toggle_log)
        status_layout.addWidget(self.log_toggle)
        self.detail_toggle = QPushButton(t("Подробные колонки"))
        self.detail_toggle.setObjectName("flat")
        self.detail_toggle.setCheckable(True)
        self.detail_toggle.setToolTip(t("показать колонку «SNI» рядом с «Узел» и «Хостер»"))
        self.detail_toggle.setChecked(bool(self.settings.get("detail_columns", False)))
        self.detail_toggle.toggled.connect(self.toggle_detail)
        status_layout.addWidget(self.detail_toggle)
        self.screen_toggle = QPushButton(t("📱 Экран телефона"))
        self.screen_toggle.setObjectName("flat")
        self.screen_toggle.setCheckable(True)
        self.screen_toggle.toggled.connect(self.screen_action.setChecked)
        status_layout.addWidget(self.screen_toggle)
        self.statusBar().addPermanentWidget(status_right)

    def _build_screen_dock(self):
        """Док с экраном телефона (scrcpy) - справа, по умолчанию скрыт."""
        self.screen = PhoneScreen(self.adb.path if self.adb else None, self.append_log)
        self.screen_dock = QDockWidget(t("Экран телефона"), self)
        self.screen_dock.setObjectName("screenDock")
        self.screen_dock.setWidget(self.screen)
        self.screen_dock.setAllowedAreas(Qt.RightDockWidgetArea | Qt.LeftDockWidgetArea)
        self.screen_dock.setFeatures(QDockWidget.DockWidgetClosable | QDockWidget.DockWidgetMovable)
        self.screen_dock.visibilityChanged.connect(self.on_screen_dock_visibility)
        self.addDockWidget(Qt.RightDockWidgetArea, self.screen_dock)
        self.screen_dock.hide()

    def _build_toolbar(self):
        box = QVBoxLayout()
        box.setSpacing(6)
        bar = QHBoxLayout()
        bar.setSpacing(8)
        bar2 = QHBoxLayout()
        bar2.setSpacing(8)
        box.addLayout(bar)
        box.addLayout(bar2)
        bar.addWidget(muted(t("Источник")))
        self.source = QComboBox()
        self.source.addItem(t("Панель Remnawave"), "panel")
        self.source.addItem(t("URL подписки"), "url")
        self.source.addItem(t("Файл"), "file")
        source = self.settings.get("source") or "panel"
        if source == "panel" and not self.connections["panels"] and not self.settings.get("panel"):
            source = "url"
        self.source.setCurrentIndex(max(0, self.source.findData(source)))
        self.source.currentIndexChanged.connect(self.on_source_changed)
        bar.addWidget(self.source)

        self.panel = QComboBox()
        self.panel.setSizeAdjustPolicy(QComboBox.AdjustToContents)
        self.fill_panels()
        if self.settings.get("panel"):
            self.panel.setCurrentText(self.settings["panel"])
        self.squad = QComboBox()
        self.squad.setEditable(True)
        self.squad.setInsertPolicy(QComboBox.NoInsert)
        squad_hint = t("сквад: выберите или введите")
        self.squad.lineEdit().setPlaceholderText(squad_hint)
        self.squad.setToolTip(squad_hint)
        self.squad.setFixedWidth(max(220, self.squad.fontMetrics().horizontalAdvance(squad_hint) + 64))
        self.squad.completer().setCompletionMode(QCompleter.PopupCompletion)
        self.squad.completer().setFilterMode(Qt.MatchContains)
        self.squad.completer().setCaseSensitivity(Qt.CaseInsensitive)
        self.squad_refresh = QPushButton("↻")
        self.squad_refresh.setFixedWidth(40)
        self.squad_refresh.setToolTip(t("обновить список сквадов из панели"))
        self.squad_refresh.clicked.connect(lambda: self.load_squads(self.panel.currentText()))
        self.squad.setEditText(self.settings.get("squad", ""))
        self.fill_squads(self.panel.currentText())
        self.panel.currentTextChanged.connect(self.fill_squads)
        self.url = QLineEdit(self.settings.get("url", ""))
        self.url.setPlaceholderText("https://sub.example.com/api/sub/xxxx")
        self.url.setMinimumWidth(320)
        self.file = QLineEdit(self.settings.get("file", ""))
        self.file.setPlaceholderText(t("файл с подпиской (json или vless-ссылки)"))
        self.file.setMinimumWidth(260)
        self.browse = QPushButton("…")
        self.browse.setFixedWidth(36)
        self.browse.clicked.connect(self.pick_file)
        for widget in (self.panel, self.squad, self.squad_refresh, self.url, self.file, self.browse):
            bar.addWidget(widget)

        self.all_ports = QCheckBox(t("все порты"))
        self.all_ports.setToolTip(t("не только 443 - узлы на 2053/2087/2096 и других портах тоже"))
        self.all_ports.setChecked(not bool(self.settings.get("only_443", True)))
        bar2.addWidget(self.all_ports)
        self.geo_check = QCheckBox(t("геомаршрут"))
        self.geo_check.setToolTip(t("медленно: живьём проверить, идут ли РФ-сайты мимо VPN или утекают в туннель"))
        self.geo_check.setChecked(bool(self.settings.get("geo_check", False)))
        self.geo_check.toggled.connect(lambda on: self.settings.update({"geo_check": on}))
        bar2.addWidget(self.geo_check)
        self.sites_check = QCheckBox(t("сайты"))
        self.sites_check.setToolTip(t("добавить в прогон проверку сайтов без VPN (по умолчанию не проверяем)"))
        self.sites_check.setChecked(bool(self.settings.get("check_sites", False)))
        self.sites_check.toggled.connect(self.on_sites_toggled)
        bar2.addWidget(self.sites_check)
        self.load_button = QPushButton(t("Загрузить узлы"))
        self.load_button.clicked.connect(self.load_subscription)
        bar.addWidget(self.load_button)
        self.targets_label = muted(t("узлы не загружены"))
        bar.addWidget(self.targets_label)
        bar.addStretch()
        bar2.addStretch()

        self.history = HistoryCombo(self.reload_history)
        self.history.setMinimumWidth(260)
        self.history.setToolTip(t("прошлые прогоны"))
        self.history.currentIndexChanged.connect(self.on_history_selected)
        bar2.addWidget(self.history)
        self.run_button = QPushButton(t("▶  Проверить"))
        self.run_button.setObjectName("primary")
        self.run_button.clicked.connect(self.start_check)
        self.stop_button = QPushButton(t("■  Стоп"))
        self.stop_button.setObjectName("danger")
        self.stop_button.clicked.connect(self.stop_check)
        self.stop_button.setVisible(False)
        bar2.addWidget(self.run_button)
        bar2.addWidget(self.stop_button)
        self.on_source_changed()
        return box


    def on_source_changed(self):
        kind = self.source.currentData()
        self.panel.setVisible(kind == "panel")
        self.squad.setVisible(kind == "panel")
        self.squad_refresh.setVisible(kind == "panel")
        self.url.setVisible(kind == "url")
        self.file.setVisible(kind == "file")
        self.browse.setVisible(kind == "file")

    def fill_panels(self):
        """Список панелей; с подсказкой-заглушкой Qt сам не выбирает первую - выбираем её явно."""
        self.panel.clear()
        for name in sorted(self.connections["panels"]):
            self.panel.addItem(name)
        self.panel.setPlaceholderText("" if self.panel.count() else t("нет панелей - добавьте в Файл → Подключения"))
        if self.panel.count():
            self.panel.setCurrentIndex(0)

    def fill_squads(self, panel):
        """Список сквадов ТОЛЬКО этой панели; чужой сквад не оставляем - иначе грузим узлы не того проекта."""
        if not fill_squad_combo(self.squad, self.settings, panel) and panel:
            QTimer.singleShot(0, self, lambda: self.load_squads(panel))

    def load_squads(self, panel):
        if self.demo or not panel or not self.connections["panels"].get(panel):
            return
        self.squad_refresh.setEnabled(False)

        def done(names):
            cache = self.settings.setdefault("squads_cache", {})
            cache[panel] = names
            storage.save_settings(self.settings)
            self.squad_refresh.setEnabled(True)
            if self.panel.currentText() == panel:
                self.fill_squads(panel)
            self.append_log(t("сквады %s: %s") % (panel, ", ".join(names)))

        def failed(error):
            self.squad_refresh.setEnabled(True)
            self.append_log(t("✖ список сквадов %s: %s") % (panel, error))
        self.run_task(lambda: subscription.list_squads(self.connections["panels"][panel]), done, failed)

    def pick_file(self):
        path, _ = QFileDialog.getOpenFileName(self, t("Файл подписки"), "", t("Все файлы (*)"))
        if path:
            self.file.setText(path)

    def load_subscription(self):
        if self.worker:
            return
        kind = self.source.currentData()
        self.settings["only_443"] = not self.all_ports.isChecked()
        only_443 = bool(self.settings.get("only_443", True))
        if kind == "panel":
            panel, squad = self.panel.currentText(), self.squad.currentText().strip()
            if not self.connections["panels"].get(panel):
                return self.warn(t("Панель не настроена - добавьте её: Файл → Подключения"))
            if not squad:
                return self.warn(t("Укажите сквад"))
            panel_config = self.connections["panels"][panel]
            fn = lambda: subscription.from_panel(panel_config, squad, only_443=only_443)  # noqa: E731
            self.append_log(t("загружаю подписку с панели %s, сквад %s…") % (panel, squad))
        elif kind == "url":
            url = self.url.text().strip()
            if not url:
                return self.warn(t("Укажите URL подписки"))
            fn = lambda: subscription.from_url(url, only_443=only_443)  # noqa: E731
            self.append_log(t("загружаю подписку по URL…"))
        else:
            path = self.file.text().strip()
            if not os.path.exists(path):
                return self.warn(t("Файл не найден"))
            fn = lambda: subscription.from_file(path, only_443=only_443)  # noqa: E731
        self.settings.update({"source": kind, "panel": self.panel.currentText(), "squad": self.squad.currentText(),
                              "url": self.url.text(), "file": self.file.text()})
        storage.save_settings(self.settings)
        self.set_loading(True)
        self.targets_label.setText(t("загружаю…"))
        want_sites, known_sites = self.sites_check.isChecked(), self.settings.get("sites") or []

        def work():
            targets, release = fn()
            return targets, release, (fetch_sites(known_sites) if want_sites else None)
        self.run_task(work, self.on_subscription_loaded, self.on_subscription_failed)

    def set_loading(self, loading):
        """Пока узлы грузятся, прогон не запустить: он взял бы прежние узлы и учётку, которую сейчас сменят."""
        self.loading = loading
        self.load_button.setEnabled(not loading and not self.worker)
        self.run_button.setEnabled(not loading)
        self.sites_check.setEnabled(not loading and not self.worker)

    def release_in_background(self):
        """Удалить временную учётку проверки фоном: панель может думать до 30 с, окно ждать не должно."""
        release, self.release_subscription = self.release_subscription, None
        if release is None:
            return
        self.run_task(release, lambda _r: None,
                      lambda error: self.append_log(t("✖ временная учётка проверки не удалена: %s") % error))

    def on_sites_toggled(self, on):
        self.settings["check_sites"] = on
        if self.targets and not self.worker and not self.loading:
            self.load_subscription()

    def source_label(self):
        kind = self.source.currentData()
        if kind == "panel":
            return "%s / %s" % (self.panel.currentText(), self.squad.currentText().strip())
        return self.url.text().strip() if kind == "url" else os.path.basename(self.file.text().strip())

    def source_record(self):
        """Панель и сквад, под которыми прогон ляжет в историю; для подписки - код источника и её название."""
        if self.source.currentData() == "panel":
            return self.panel.currentText(), self.squad.currentText().strip()
        return self.source.currentData(), self.source_label()

    def on_subscription_loaded(self, result):
        targets, release, sites = result
        self.set_loading(False)
        if self.worker or self.closing:
            self.run_task(release, lambda _r: None,
                          lambda error: self.append_log(t("✖ временная учётка проверки не удалена: %s") % error))
            if self.closing:
                return None
            return self.append_log(t("узлы загрузились, когда уже шёл прогон - оставляю прежние"))
        self.release_in_background()
        if sites is not None:
            self.settings["sites"] = sites
        targets = [target for target in targets if not target.get("site_url")] + subscription.site_targets(sites)
        self.targets, self.release_subscription = targets, release
        locations = len({target["location"] for target in targets})
        self.targets_label.setText(t("узлов: %d · локаций: %d") % (len(targets), locations))
        self.append_log(t("узлов: %d, локаций: %d") % (len(targets), locations))
        self.fill_table(targets, [])
        self.run_title.setText(t("%s  ·  узлы загружены, прогон не запускался") % self.source_label())
        summary = subscription.routing_summary(getattr(release, "raw", None) or subscription.LAST_RAW)
        mark = "✅" if summary["ru_direct"] else "⚠"
        self.append_log(t("%s геомаршрут: %s") % (mark, summary["verdict"]))

    def on_subscription_failed(self, error):
        self.set_loading(False)
        self.targets_label.setText(t("ошибка загрузки"))
        self.append_log(t("✖ подписка: %s") % error)
        self.warn(t("Не удалось загрузить узлы:\n%s") % error)


    def fill_table(self, targets, modes):
        self.placeholder.setVisible(not targets)
        self.table.setSortingEnabled(False)
        self.mode_columns = {}
        headers = [t(column) for column in FIXED_COLUMNS] + [mode["label"] if isinstance(mode, dict) else mode.label
                                                             for mode in modes]
        self.table.setColumnCount(0)
        self.totals.setColumnCount(0)
        self.table.setColumnCount(len(headers))
        self.table.setHorizontalHeaderLabels(headers)
        for col, width in enumerate(FIXED_WIDTHS):
            self.table.setColumnWidth(col, width)
        self.mode_kinds = {}
        for index, mode in enumerate(modes):
            mode_id = mode["id"] if isinstance(mode, dict) else mode.id
            self.mode_kinds[mode_id] = mode.get("kind") if isinstance(mode, dict) else mode.kind
            self.mode_columns[mode_id] = len(FIXED_COLUMNS) + index
            self.table.setColumnWidth(len(FIXED_COLUMNS) + index, 150)
        self.table.setRowCount(len(targets))
        self.row_by_key = {}
        self.cell_states = {mode_id: {} for mode_id in self.mode_columns}
        self.cell_counts = {mode_id: {"alive": 0, "dead": 0, "unchecked": 0} for mode_id in self.mode_columns}
        self.finished_modes = set()
        for row, target in enumerate(sorted(targets, key=lambda item: (item["location"], item["key"]))):
            self.row_by_key[target["key"]] = row
            host = target["key"].rsplit(":", 1)[0]
            cached = self.geo_cached(host)
            for col, text in enumerate((target["location"], target["key"], cached.get("ip", ""),
                                        self.hoster_text(cached), target.get("sni") or "")):
                item = self.ip_item(text) if col == COL_IP else QTableWidgetItem(text)
                if col:
                    item.setForeground(QColor(theme.MUTED))
                if col == COL_KEY:
                    item.setData(Qt.UserRole, target["key"])
                self.table.setItem(row, col, item)
            for mode_id in self.mode_columns:
                self.set_cell(mode_id, target["key"], "-", theme.MUTED)
        self.table.setSortingEnabled(True)
        self.table.sortItems(0)
        self.clear_chips()
        self.rebuild_totals(headers)
        self.place_mode_columns()
        self.toggle_detail(self.detail_toggle.isChecked())
        self.start_geo_lookup(targets)

    def place_mode_columns(self):
        """После «Локации» - IP узла, за ним колонки сетей: на узком экране их видно без прокрутки вбок.
        Порядок меняется только на экране - номера колонок в коде прежние."""
        for header in (self.table.horizontalHeader(), self.totals.horizontalHeader()):
            header.moveSection(header.visualIndex(COL_IP), 1)
            for place, col in enumerate(sorted(self.mode_columns.values()), start=2):
                header.moveSection(header.visualIndex(col), place)

    @staticmethod
    def ip_item(text):
        """IP сортируется как число: 9.x раньше 10.x."""
        parts = text.split(".")
        key = None
        if len(parts) == 4 and all(part.isdigit() for part in parts):
            key = sum(int(part) << (8 * (3 - index)) for index, part in enumerate(parts))
        return SortItem(text, key)

    def reindex_rows(self):
        """Строка каждого узла заново после сортировки: номера строк при сортировке меняются."""
        index = {}
        for row in range(self.table.rowCount()):
            item = self.table.item(row, COL_KEY)
            key = item.data(Qt.UserRole) if item else None
            if key:
                index[key] = row
        self.row_by_key = index

    def mode_rows(self, mode_id):
        """Строки колонки: у ДЦ - только узлы; пустой набор - пустая колонка, а не вся таблица."""
        keys = self.mode_keys.get(mode_id)
        return list(self.row_by_key if keys is None else keys)

    def mode_total(self, mode_id):
        return len(self.mode_rows(mode_id))

    def rebuild_totals(self, headers):
        self.totals.setColumnCount(len(headers))
        for col in range(len(headers)):
            self.totals.setColumnWidth(col, self.table.columnWidth(col))
            item = QTableWidgetItem(t("Итого") if col == 0 else "")
            item.setForeground(QColor(theme.TEXT if col == 0 else theme.MUTED))
            font = QFont()
            font.setBold(True)
            item.setFont(font)
            if col >= len(FIXED_COLUMNS):
                item.setTextAlignment(Qt.AlignCenter)
            self.totals.setItem(0, col, item)
        self.totals.horizontalHeader().setStretchLastSection(True)
        self.update_totals()

    def update_totals(self, only=None):
        """Итог колонки по счётчикам set_cell - без обхода всей таблицы на каждую ячейку."""
        for mode_id, col in self.mode_columns.items():
            if only is not None and mode_id != only:
                continue
            total = self.mode_total(mode_id)
            counts = self.cell_counts.get(mode_id) or {}
            alive, dead, unchecked = counts.get("alive", 0), counts.get("dead", 0), counts.get("unchecked", 0)
            if alive + dead + unchecked == 0:
                text, color = "-", theme.MUTED
            else:
                text = t("%d из %d") % (alive, total)
                if unchecked:
                    text += t(" · не проверено %d") % unchecked
                color = (theme.GREEN if alive == total else theme.RED if alive == 0 and not unchecked
                         else theme.AMBER)
            item = QTableWidgetItem(text)
            item.setForeground(QColor(color))
            item.setTextAlignment(Qt.AlignCenter)
            font = QFont()
            font.setBold(True)
            item.setFont(font)
            self.totals.setItem(0, col, item)

    @staticmethod
    def hoster_text(info):
        if not info or not info.get("org"):
            return ""
        return "%s%s" % (info["org"], (" · " + info["country"]) if info.get("country") else "")

    def geo_cached(self, host):
        """Хостер из кэша; в демо - выдуманный, демо в сеть не ходит и кэш не пачкает."""
        if self.demo:
            org, country = DEMO_HOSTERS.get(host, ("", ""))
            return {"ip": host, "org": org, "country": country} if org else {}
        return geo.cached(host)

    def start_geo_lookup(self, targets):
        if self.demo:
            return
        hosts = [target["key"].rsplit(":", 1)[0] for target in targets]
        missing = [host for host in hosts if not geo.cached(host).get("org")]
        if not missing:
            return
        self.run_task(lambda: geo.lookup_many(missing), self.apply_geo, lambda _error: None)

    def apply_geo(self, info):
        self.table.setSortingEnabled(False)
        for key, row in self.row_by_key.items():
            host = key.rsplit(":", 1)[0]
            entry = info.get(host) or geo.cached(host)
            if not entry:
                continue
            for col, text in ((COL_IP, entry.get("ip", "")), (COL_HOSTER, self.hoster_text(entry))):
                item = self.ip_item(text) if col == COL_IP else QTableWidgetItem(text)
                item.setForeground(QColor(theme.MUTED))
                self.table.setItem(row, col, item)
        self.table.setSortingEnabled(True)

    def set_cell(self, mode_id, key, text, color, background=None, tooltip="", order=ORDER_EMPTY):
        row = self.row_by_key.get(key)
        col = self.mode_columns.get(mode_id)
        if row is None or col is None:
            return
        self.pause_sorting()
        item = SortItem(text, order)
        item.setForeground(QColor(color))
        item.setTextAlignment(Qt.AlignCenter)
        font = QFont()
        font.setBold(background is not None)
        item.setFont(font)
        if background:
            item.setBackground(QColor(background))
        if tooltip:
            item.setToolTip(tooltip)
        self.table.setItem(row, col, item)
        state = ("alive" if text.startswith("●") else "dead" if text.startswith("✕")
                 else "unchecked" if text.startswith("?") else "")
        states = self.cell_states.setdefault(mode_id, {})
        counts = self.cell_counts.setdefault(mode_id, {"alive": 0, "dead": 0, "unchecked": 0})
        old = states.get(key, "")
        if old != state:
            if old:
                counts[old] -= 1
            if state:
                counts[state] += 1
            states[key] = state

    def pause_sorting(self):
        """Пачка результатов пишется без сортировки: иначе таблица пересортировывается на каждую ячейку.
        Сортировка включается сама, когда поток результатов затих, - порядок строк меняется один раз."""
        if self.table.isSortingEnabled():
            self.table.setSortingEnabled(False)
        self.resort_timer.start()

    def show_result(self, mode_id, key, value, totals=True):
        if value.get("retrying"):
            self.set_cell(mode_id, key, t("↻ ещё раз"), theme.AMBER, order=ORDER_RETRY)
            return
        if value.get("exit_ip") and value.get("slow"):
            self.set_cell(mode_id, key, t("● медленно"), theme.AMBER, theme.AMBER_BG,
                          t("выход через %s; узел жив, но замер задержки не уложился в отведённое время")
                          % value["exit_ip"], order=ORDER_SLOW)
        elif value.get("exit_ip"):
            latency = value.get("latency")
            text = t("● %d мс") % latency if latency else t("● жив")
            self.set_cell(mode_id, key, text, theme.GREEN, theme.GREEN_BG, t("выход через %s") % value["exit_ip"],
                          order=latency if latency else ORDER_ALIVE)
        elif value.get("unchecked") == "stop":
            self.set_cell(mode_id, key, t("? остановлен"), theme.AMBER, None,
                          t("не проверен: прогон остановлен до перепроверки - узел может быть жив"),
                          order=ORDER_UNCHECKED)
        elif value.get("unchecked"):
            self.set_cell(mode_id, key, t("? нет сети"), theme.AMBER, None,
                          t("не проверен: во время перепроверки у телефона пропал интернет - узел может быть жив"),
                          order=ORDER_UNCHECKED)
        elif mode_id in self.whitelisted:
            self.set_cell(mode_id, key, t("✕ БС"), theme.MUTED, None,
                          t("SIM в режиме белых списков: узел не пробился, но сам он может быть жив"),
                          order=ORDER_WHITELIST)
        else:
            self.set_cell(mode_id, key, t("✕ мёртв"), theme.RED_TEXT, theme.RED_BG, order=ORDER_DEAD)
        self.final_cells.add((mode_id, key))
        if totals:
            self.update_totals(mode_id)
        if self.total_cells:
            self.progress.setValue(int(100 * len(self.final_cells) / self.total_cells))

    def table_rows(self):
        """Заголовки и строки таблицы как текст (только видимые колонки) + строка «Итого»."""
        header = self.table.horizontalHeader()
        columns = sorted((col for col in range(self.table.columnCount()) if not self.table.isColumnHidden(col)),
                         key=header.visualIndex)
        headers = [self.table.horizontalHeaderItem(col).text() for col in columns]
        rows = [[cell_text(self.table, row, col) for col in columns] for row in range(self.table.rowCount())]
        totals = [cell_text(self.totals, 0, col) for col in columns]
        return headers, rows, totals

    def copy_table(self, fmt):
        headers, rows, totals = self.table_rows()
        if not rows:
            return self.statusBar().showMessage(t("таблица пуста"), 3000)
        title = self.run_title.text()
        if fmt == "markdown":
            lines = [("**%s**" % title) if title else "", "",
                     "| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
            lines += ["| " + " | ".join(row) + " |" for row in rows]
            lines.append("| " + " | ".join("**%s**" % total if total else "" for total in totals) + " |")
            text = "\n".join(lines)
        elif fmt == "csv":
            import csv
            import io
            buffer = io.StringIO()
            writer = csv.writer(buffer, delimiter=";")
            writer.writerow(headers)
            writer.writerows(rows)
            writer.writerow(totals)
            text = buffer.getvalue()
        else:
            widths = [max(len(header), *(len(row[col]) for row in rows), len(totals[col]))
                      for col, header in enumerate(headers)]

            def fmt_row(cells):
                return "  ".join(cell.ljust(widths[col]) for col, cell in enumerate(cells)).rstrip()

            lines = ([title, ""] if title else []) + [fmt_row(headers), "-" * (sum(widths) + 2 * (len(widths) - 1))]
            lines += [fmt_row(row) for row in rows] + [fmt_row(totals)]
            text = "\n".join(lines)
        QApplication.clipboard().setText(text)
        self.statusBar().showMessage(t("таблица скопирована (строк: %d, %s)") % (len(rows), fmt), 4000)

    def clear_chips(self):
        while self.chips.count():
            item = self.chips.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self.mode_chips = {}

    def set_chip(self, mode_id, text, kind, tip=""):
        label = self.mode_chips.get(mode_id)
        if label is None:
            label = chip(text, kind)
            self.chips.addWidget(label)
            self.mode_chips[mode_id] = label
        label.setText(text)
        if tip:
            label.setToolTip(tip)
        restyle(label, kind)


    def start_check(self):
        if self.worker:
            return
        planned = self._plan_jobs()
        if not planned:
            return
        modes, jobs, phones = planned
        jobs, windows = multiphone.lease_port_windows(jobs)
        if jobs is None:
            return self.warn(t("Все окна локальных портов заняты другими прогонами - дождитесь их окончания"))
        try:
            self._spawn_workers(modes, jobs, windows, phones)
        except Exception:
            portlock.release_all(windows)
            self.run_windows = []
            self.worker = None
            self.set_running(False)
            raise

    def _plan_jobs(self):
        """Проверки перед прогоном и раскладка сетей по телефонам: (сети, потоки, телефоны) или None."""
        if self.loading:
            return self.warn(t("Узлы ещё загружаются - дождитесь окончания"))
        if self.phone_busy:
            return self.warn(t("Телефон занят прошлой командой - дождитесь её окончания"))
        if not self.targets:
            return self.warn(t("Сначала загрузите узлы"))
        modes = self.networks.selected()
        if not modes:
            return self.warn(t("Выберите хотя бы одну сеть"))
        phones = self.connected_phones()
        if any(m.kind != "dc" for m in modes) and not phones:
            return self.warn(t("Телефон не подключён - доступна только проверка из ДЦ"))
        jobs = multiphone.plan(modes, phones, self.targets)
        if not jobs:
            return self.warn(t("Телефон не подключён - доступна только проверка из ДЦ"))
        planned = {mode.id for job in jobs for mode in job.modes}
        dropped = [mode for mode in modes if mode.id not in planned]
        if dropped:
            answer = QMessageBox.question(
                self, "VPNCheck Stand",
                t("Эти сети не попадут в прогон - их телефон отключился:\n%s\n\nПроверить остальные?")
                % "\n".join(mode.label for mode in dropped))
            if answer != QMessageBox.Yes:
                return None
            modes = [mode for mode in modes if mode.id in planned]
        return modes, jobs, phones

    def _spawn_workers(self, modes, jobs, windows, phones):
        """Таблица под новый прогон и потоки проверки: по одному на телефон и на ДЦ."""
        self.run_windows = windows
        self.settings["restore_network"] = self.networks.restore.isChecked()
        self.run_source = self.source_record()
        self.shown_run_path = None
        self.mode_keys = mode_keys(modes, self.targets)
        self.fill_table(self.targets, modes)
        self.run_title.setText(t("▶ идёт проверка  ·  %s  ·  %s  ·  узлов: %d") % (
            self.source_label(), time.strftime("%H:%M"), len(self.targets)))
        self.final_cells = set()
        self.total_cells = sum(len(keys) for keys in self.mode_keys.values())
        self.progress.setValue(0)
        self.log.clear()
        workers = []
        self.run_parts = [None] * len(jobs)
        self.run_left = len(jobs)
        self.mode_results = {}
        self.mode_ips = {}
        self.whitelisted = set()
        for slot, job in enumerate(jobs):
            serial, tag = job.serial, job.tag
            adb = Adb(path=self.base_adb.path, serial=serial) if serial and self.base_adb else self.adb
            worker = multiphone.make_worker(job, self.targets, self.settings, self.connections, adb,
                                            raw=getattr(self.release_subscription, "raw", None))
            rows = {mode_id: {target["key"] for target in part} for mode_id, part in job.mode_targets.items()}
            worker.log.connect(self.append_log)
            worker.mode_started.connect(lambda mid, ip, rows=rows: self.on_mode_started(mid, ip, rows.get(mid)))
            worker.mode_failed.connect(lambda mid, why, rows=rows: self.on_mode_failed(mid, why, rows.get(mid)))
            worker.node_result.connect(self.show_result)
            worker.mode_finished.connect(self.on_mode_finished)
            worker.run_finished.connect(
                lambda run, slot=slot, tag=(tag if serial else ""): self.on_part_finished(slot, tag, run))
            worker.failed.connect(lambda error, tag=tag: self.warn(
                t("Прогон прерван%s: %s") % ((" (%s)" % t(tag)) if tag else "", error)))
            workers.append(worker)
        if len(phones) > 1:
            self.append_log(t("телефонов в прогоне: %d - идут одновременно") % sum(1 for job in jobs if job.serial))
        self.worker = RunGroup(workers)
        self.set_running(True)
        for worker in workers:
            worker.start()

    def on_part_finished(self, slot, tag, run):
        """Один поток (телефон или ДЦ) закончил. Когда закончили все - один общий отчёт."""
        run["phone_tag"] = tag
        self.run_parts[slot] = run
        self.run_left -= 1
        if self.run_left <= 0:
            portlock.release_all(self.run_windows)
            self.run_windows = []
            self.on_run_finished(multiphone.merge_runs(self.run_parts, self.targets))

    def stop_check(self):
        if self.worker:
            self.worker.stop()
            self.append_log(t("останавливаю после текущей пачки…"))
            self.stop_button.setEnabled(False)

    def set_running(self, running):
        self.run_button.setVisible(not running)
        self.run_button.setEnabled(not self.loading)
        self.stop_button.setVisible(running)
        self.stop_button.setEnabled(True)
        self.load_button.setEnabled(not running and not self.loading)
        for widget in (self.source, self.panel, self.squad, self.squad_refresh, self.url, self.file, self.browse,
                       self.all_ports, self.sites_check, self.geo_check):
            widget.setEnabled(not running)
        self.networks.set_enabled(not running)
        self.phone.set_controls_enabled(not running and not self.phone_busy and self.phone_state.connected)
        self.history.setEnabled(not running)
        if self.poller:
            self.poller.slow = running
        if not running and not self.demo:
            self.networks.rebuild(self.connected_phones(), self.dc_label())
        self.statusBar().showMessage(t("идёт проверка…") if running else t("готово"))

    def on_mode_started(self, mode_id, ip, rows=None):
        """rows - строки этого телефона в общей колонке; None - вся колонка."""
        whitelist = ip == WHITELIST_IP
        if whitelist:
            self.whitelisted.add(mode_id)
        for key in list(rows if rows is not None else self.mode_rows(mode_id)):
            self.set_cell(mode_id, key, "…", "#5b8def")
        self.mode_ips[mode_id] = self.mode_ips.get(mode_id) or ip
        if not self.mode_results.get(mode_id):
            if whitelist:
                self.set_chip(mode_id, t("%s · белые списки · идёт проверка") % self.mode_label(mode_id), "chipAmber")
            else:
                self.set_chip(mode_id, t("%s · идёт проверка") % self.mode_label(mode_id), "chipBlue",
                              tip="IP %s" % ip if ip else "")

    def on_mode_failed(self, mode_id, reason, rows=None):
        for key in list(rows if rows is not None else self.mode_rows(mode_id)):
            self.set_cell(mode_id, key, t("? нет сети"), theme.AMBER, None, reason)
        self.update_totals(mode_id)
        if rows is None:
            self.finished_modes.add(mode_id)
        self.set_chip(mode_id, "%s · %s%s" % (self.mode_label(mode_id), reason,
                                            t(" (часть колонки)") if rows is not None else ""), "chipAmber")

    def on_mode_finished(self, mode_id, results, note=""):
        if mode_id in self.whitelisted:
            return self.finish_whitelisted(mode_id, results, note)
        if not results:
            return
        merged = self.mode_results.setdefault(mode_id, {})
        merged.update(results)
        alive = sum(1 for value in merged.values() if value.get("exit_ip"))
        total = self.mode_total(mode_id)
        ip = self.mode_ips.get(mode_id, "")
        if len(merged) < total:
            self.set_chip(mode_id, t("%s · живых %d из %d проверенных · вторая часть идёт")
                          % (self.mode_label(mode_id), alive, len(merged)), "chipBlue")
            return
        unchecked = unchecked_count(merged)
        kind = "chipGreen" if alive == total else "chipRed" if alive == 0 and not unchecked else "chipAmber"
        text = t("%s · живых %d из %d") % (self.mode_label(mode_id), alive, total)
        if unchecked:
            text += " · " + unchecked_note(merged)
        if ip and self.mode_kinds.get(mode_id) == "dc":
            text += " · " + t("пробник %s") % ip
        self.set_chip(mode_id, text, kind, tip="IP %s" % ip if ip else "")
        self.finished_modes.add(mode_id)

    def finish_whitelisted(self, mode_id, results, note=""):
        """Колонка SIM в белых списках: серая, с вердиктом по балансу (денег нет / ограничения оператора)."""
        if not results:
            for key in self.mode_rows(mode_id):
                self.set_cell(mode_id, key, t("- БС"), theme.MUTED, None,
                              t("колонку не проверяли: SIM в режиме белых списков. %s") % note)
                self.final_cells.add((mode_id, key))
            self.update_totals(mode_id)
            text = t("%s · белые списки - колонка пропущена") % self.mode_label(mode_id)
        else:
            alive = sum(1 for value in results.values() if value.get("exit_ip"))
            text = t("%s · белые списки - пробились %d из %d (обходы)") % (self.mode_label(mode_id), alive,
                                                                     self.mode_total(mode_id))
        self.set_chip(mode_id, text, "chip", tip=note or t("SIM в режиме белых списков"))
        self.finished_modes.add(mode_id)

    def finish_columns(self, stopped):
        """После прогона не остаётся «…» и «идёт проверка»: непроверенное - прочерк, у колонки - итог."""
        for mode_id in list(self.mode_columns):
            for key in self.mode_rows(mode_id):
                row, col = self.row_by_key.get(key), self.mode_columns[mode_id]
                item = self.table.item(row, col) if row is not None else None
                if item is not None and (item.text() == "…" or item.text() == t("↻ ещё раз")):
                    self.set_cell(mode_id, key, "-", theme.MUTED, None,
                                  t("не проверен: прогон остановлен") if stopped else t("не проверен"))
            self.update_totals(mode_id)
            if mode_id in self.finished_modes:
                continue
            merged = self.mode_results.get(mode_id) or {}
            if not merged:
                label = self.mode_chips.get(mode_id)
                if label is not None and label.text().endswith(t("идёт проверка")):
                    self.set_chip(mode_id, t("%s · не проверялась") % self.mode_label(mode_id), "chip")
                continue
            alive = sum(1 for value in merged.values() if value.get("exit_ip"))
            text = t("%s · живых %d из %d проверенных") % (self.mode_label(mode_id), alive,
                                                          len(merged) - unchecked_count(merged))
            self.set_chip(mode_id, text + (t(" · остановлено") if stopped else ""), "chipAmber")

    def on_run_finished(self, run):
        """Прогон закончен: итоги, сохранение. Что бы ни случилось при сохранении - окно выходит из
        «идёт проверка», а данные прогона остаются в журнале ошибок."""
        path = None
        try:
            run["panel"], run["squad"] = self.run_source
            self.finish_columns(bool(run.get("stopped")))
            self.show_geo_chip(run.get("geo") or {})
            if not self.demo:
                path = storage.save_run(run)
                self.shown_run_path = path
                self.append_log(t("прогон сохранён: %s") % os.path.basename(path))
        except Exception as exc:  # noqa: BLE001 - диск полон, нет прав: окно не должно зависнуть
            errorlog.record("прогон", exc)
            try:
                errorlog.record("прогон", json.dumps(run, ensure_ascii=False))
            except (TypeError, ValueError):
                pass
            self.append_log(t("✖ прогон не сохранён: %s") % exc)
            if not self.closing:
                self.warn(t("Прогон не сохранился: %s\n\nРезультаты остались в таблице и в журнале ошибок "
                            "(Агенты → Центр управления агентами → «Ошибки»).") % exc)
        finally:
            self.worker = None
            self.set_running(False)
            self.progress.setValue(100)
            self.reload_history()
        if path and not self.closing:
            self.start_diagnosis(run, path)

    def show_geo_chip(self, routing):
        if not routing.get("available"):
            return
        ok, total = routing.get("ok", 0), routing.get("total", 0)
        short = (t("РФ напрямую %d/%d") % (ok, total)) if total else t("не проверено")
        self.set_chip("geo", t("Геомаршрут: %s") % short, "chipGreen" if routing.get("direct") else "chipAmber",
                      tip=routing.get("verdict", ""))

    def start_diagnosis(self, run, path):
        """Узлы мертвы везде, включая ДЦ, - выяснить с пробника почему (фоном, прогон уже сохранён)."""
        from .. import dcprobe
        dead = dcprobe.dead_everywhere(run)
        if not dead or not storage.has_probe(self.connections):
            return
        self.append_log(t("мертвы везде, включая ДЦ: %d - выясняю почему…") % len(dead))

        def done(diagnosis):
            run["diagnosis"] = diagnosis
            storage.update_run(path, run)
            if not self.worker and self.shown_run_path == path:
                self.show_diagnosis(diagnosis)
            counts = Counter(check["verdict"] for check in diagnosis.values())
            self.append_log(t("диагноз: %s") % ", ".join("%s - %d" % (t(verdict), count)
                                                          for verdict, count in sorted(counts.items())))

        self.run_task(lambda: dcprobe.diagnose_run(self.connections["probe"], run), done,
                      lambda error: self.append_log(t("✖ диагноз мёртвых узлов: %s") % error))

    def show_diagnosis(self, diagnosis):
        """Колонка «Почему мёртв» - только у узлов, мёртвых везде; подробности во всплывающей подсказке."""
        if not diagnosis:
            return
        colors = {"не достучаться из РФ": theme.RED, "рвут рукопожатие": theme.AMBER}
        sorting = self.table.isSortingEnabled()
        self.table.setSortingEnabled(False)
        col = self.table.columnCount()
        self.table.insertColumn(col)
        self.table.setHorizontalHeaderItem(col, QTableWidgetItem(t("Почему мёртв")))
        self.table.setColumnWidth(col, 190)
        rows = dict(self.row_by_key)
        for key, check in diagnosis.items():
            if key not in rows:
                continue
            item = QTableWidgetItem(t(check.get("verdict", "")))
            item.setForeground(QColor(colors.get(check.get("verdict"), theme.MUTED)))
            item.setToolTip(t("%s\nадрес %s · TCP %s · TLS %s") % (check.get("detail", ""), check.get("ip") or "?",
                                                                 check.get("tcp") or "-", check.get("tls") or "-"))
            self.table.setItem(rows[key], col, item)
        self.table.setSortingEnabled(sorting)
        headers = [self.table.horizontalHeaderItem(col).text() for col in range(self.table.columnCount())]
        self.rebuild_totals(headers)

    def mode_label(self, mode_id):
        col = self.mode_columns.get(mode_id)
        return self.table.horizontalHeaderItem(col).text() if col is not None else mode_id


    def reload_history(self):
        self.history.blockSignals(True)
        self.history.clear()
        self.history.addItem(t("История прогонов…"), None)
        for path, label in self.run_labels.entries():
            self.history.addItem(label, path)
        self.history.blockSignals(False)

    def show_newest_run(self):
        """Прогон из консоли (run_check.py) сам появляется в таблице, как только сохранён."""
        if self.worker:
            return
        if self.loading:
            return
        runs = run_paths(limit=1)
        if not runs or runs[0] == self.shown_run_path:
            return
        self.shown_run_path = runs[0]
        self.reload_history()
        self.history.setCurrentIndex(1)

    @staticmethod
    def run_source_text(run):
        """«панель / сквад»; у подписки вместо панели - код источника, он показывается словами."""
        if not run.get("panel"):
            return ""
        panel = SOURCE_NAMES.get(run["panel"])
        return "%s / %s" % (t(panel) if panel else run["panel"], run.get("squad", ""))

    def on_history_selected(self, index):
        path = self.history.itemData(index)
        if not path or self.worker:
            return
        run = read_run(path)
        if run is None:
            return self.append_log(t("✖ прогон не читается: %s") % os.path.basename(path))
        self.shown_run_path = path
        targets = [{"location": target["location"], "key": target["key"], "sni": target.get("sni")}
                   for target in run["targets"]]
        self.mode_keys = mode_keys(run["modes"], targets)
        self.mode_results, self.mode_ips = {}, {}
        self.fill_table(targets, run["modes"])
        source = self.run_source_text(run) or t("прогон")
        self.run_title.setText(t("📋 из истории  ·  %s  ·  %s  ·  узлов: %d") % (
            source, run.get("started", ""), len(run["targets"])))
        self.whitelisted = {mode["id"] for mode in run["modes"]
                            if mode.get("whitelist") or mode.get("ip") == WHITELIST_IP}
        for mode in run["modes"]:
            self.mode_ips[mode["id"]] = mode.get("ip", "")
            if mode.get("error"):
                self.on_mode_failed(mode["id"], mode["error"])
                continue
            for key, value in mode["results"].items():
                self.show_result(mode["id"], key, value, totals=False)
            self.on_mode_finished(mode["id"], mode["results"], mode.get("whitelist_note", ""))
        self.finish_columns(bool(run.get("stopped")))
        self.update_totals()
        self.show_diagnosis(run.get("diagnosis"))
        self.append_log(t("показан прогон %s%s") % (
            (self.run_source_text(run) + " ") if run.get("panel") else "", run.get("started")))
        self.targets_label.setText(t("узлов: %d · локаций: %d") % (
            len(run["targets"]), len({target["location"] for target in run["targets"]})))
        self.progress.setValue(0)


    def on_phone_state(self, state):
        if self.demo and not state.connected:
            return
        was_connected = self.phone_state.connected
        self.phone_state = state
        saved = self.settings.get("sim_numbers") or {}
        if saved and state.sims:
            only = len(self.connected_phones()) <= 1
            self.phone.sim_numbers = {sim.sub_id: saved_number(saved, sim, state.serial, only)
                                      for sim in state.sims}
        self.phone.update_state(state)
        if self.worker or self.phone_busy:
            self.phone.set_controls_enabled(False)
        if self.demo:
            self.networks.rebuild(state, self.dc_label())
        if state.connected and not was_connected:
            self.append_log(t("телефон на связи: %s, Android %s") % (state.model, state.android))
            if not self.demo and not self.phone_busy:
                self.check_ip(quiet=True)
        elif was_connected and not state.connected:
            self.append_log(t("телефон отключился") + (": " + state.error if state.error else ""))

    def fit_canvas(self):
        """Минимум холста = сколько реально просит раскладка (но не меньше 1180×700).
        Меньше - Qt ужимает кнопки друг на друга; ровно столько - окно уже просто прокручивается."""
        need = self.canvas.layout().minimumSize() if self.canvas.layout() else None
        width = max(1180, need.width() if need else 0)
        height = max(700, need.height() if need else 0)
        self.canvas.setMinimumSize(width, height)

    def dc_label(self):
        return multiphone.dc_label(self.connections) if storage.has_probe(self.connections) else ""

    def connected_phones(self):
        """Телефоны, готовые к прогону; окно портов - по серийнику, как в run_check (multiphone.assign_port_windows)."""
        phones = [phone for phone in self.phones if phone["state"].connected]
        return multiphone.assign_port_windows(phones, [phone["serial"] for phone in phones])

    def on_phone_states(self, snapshot):
        """Свежий опрос всех телефонов: левая карточка - выбранный, «Что проверять» - все."""
        if self.demo:
            return
        phones, taken = [], []
        for item in snapshot:
            if not item["serial"]:
                continue
            state = item["state"]
            tag = multiphone.phone_tag(state.model, item["serial"], taken)
            taken.append(tag)
            phones.append({"serial": item["serial"], "tag": tag, "state": state, "model": state.model})
        old = [phone["serial"] for phone in self.phones]
        self.phones = phones
        serials = [phone["serial"] for phone in phones]
        if serials != old and len(serials) > 1 and len(old) <= 1:
            self.append_log(t("на кабеле несколько телефонов: %s - переключатель в карточке «Телефон»")
                            % ", ".join(phone["tag"] for phone in phones))
        if self.selected_serial not in serials:
            self.selected_serial = serials[0] if serials else ""
        self.bind_selected_adb()
        self.phone.set_phones(phones, self.selected_serial)
        selected = next((phone["state"] for phone in phones if phone["serial"] == self.selected_serial), None)
        if selected is None:
            selected = snapshot[0]["state"] if snapshot else PhoneState()
        self.on_phone_state(selected)
        if not self.worker:
            self.networks.rebuild(self.connected_phones(), self.dc_label())

    def bind_selected_adb(self):
        """Кнопки карточки работают с выбранным телефоном: при двух на кабеле adb без серийника отказывает."""
        if not self.base_adb:
            return
        if self.selected_serial and (self.adb is None or self.adb.serial != self.selected_serial):
            self.adb = Adb(path=self.base_adb.path, serial=self.selected_serial)
            self.screen.set_serial(self.selected_serial)

    def select_phone(self, serial):
        if not serial or serial == self.selected_serial:
            return
        self.selected_serial = serial
        self.settings["phone_serial"] = serial
        self.bind_selected_adb()
        phone = next((item for item in self.phones if item["serial"] == serial), None)
        if phone:
            self.append_log(t("в карточке телефон %s (%s)") % (phone["tag"], serial))
            self.phone.set_ip("")
            self.on_phone_state(phone["state"])
            if phone["state"].connected and not self.worker and not self.phone_busy:
                self.check_ip(quiet=True)

    def phone_locked(self, quiet=False):
        """Телефон занят прогоном другого процесса (консольный run_check): кнопки окна его не трогают."""
        serial = (self.adb.serial if self.adb else "") or self.selected_serial
        pid = (runlock.holder(serial) if serial else 0) or runlock.holder("")
        if not pid:
            return False
        text = t("телефон занят другим прогоном (PID %d) - дождитесь его окончания") % pid
        if quiet:
            self.append_log(text)
        else:
            self.warn(text)
        return True

    def phone_ready(self, quiet=False):
        """Можно ли сейчас командовать телефоном: нет прогона, нет другого действия, телефон не занят извне."""
        if not self.adb or self.worker:
            return False
        if self.phone_busy:
            if not quiet:
                self.statusBar().showMessage(t("телефон занят прошлой командой - дождитесь её окончания"), 4000)
            return False
        return not self.phone_locked(quiet)

    def set_phone_busy(self, busy):
        self.phone_busy = busy
        self.phone.set_controls_enabled(not busy and not self.worker and self.phone_state.connected)

    def phone_task(self, fn, on_done, on_error, on_progress=None, ports=False, quiet=False):
        """Команда телефону фоном; пока идёт - кнопки карточки выключены, опрос их не включит.

        Телефон занимается тем же локом, что и прогон (консольный run_check его не перебьёт),
        а с ports=True ещё и своё окно локальных портов: fn получает его сдвиг первым аргументом.
        """
        serial = (self.adb.serial if self.adb else "") or self.selected_serial
        if not runlock.acquire(serial):
            pid = runlock.holder(serial)
            text = (t("телефон занят другим прогоном (PID %d) - дождитесь его окончания") % pid if pid
                    else t("телефон занят прошлой командой - дождитесь её окончания"))
            return self.append_log(text) if quiet else self.warn(text)
        window = portlock.acquire() if ports else None
        if ports and window is None:
            runlock.release(serial)
            text = t("Все окна локальных портов заняты другими прогонами - дождитесь их окончания")
            return self.append_log(text) if quiet else self.warn(text)
        self.set_phone_busy(True)

        def finish():
            portlock.release(window)
            runlock.release(serial)
            self.set_phone_busy(False)

        def done(result):
            finish()
            on_done(result)

        def failed(error):
            finish()
            on_error(error)
        if ports:
            shift = portlock.shift(window)
            call = (lambda say: fn(shift, say)) if on_progress is not None else (lambda: fn(shift))
        else:
            call = fn
        return self.run_task(call, done, failed, on_progress)

    def phone_command(self, name, command):
        if not self.phone_ready():
            return
        control = PhoneControl(self.adb)
        self.phone_task(lambda: command(control),
                        lambda _r: self.append_log(t("телефон: %s - ок") % name),
                        lambda error: self.warn("%s: %s" % (name, error)))

    def switch_data_sim(self, sub_id):
        if not self.phone_ready():
            return
        control = PhoneControl(self.adb)

        def work():
            if control.set_data_sim(sub_id):
                return "ok"
            if control.current_data_sub() == sub_id:
                return "late"
            control.open_sim_manager()
            return "manual"

        def done(outcome):
            if outcome == "ok":
                self.append_log(t("SIM для данных переключена"))
            elif outcome == "late":
                self.append_log(t("SIM для данных переключена (подтвердилось с опозданием)"))
            else:
                self.append_log(t("SIM для данных не переключилась штатной настройкой - открываю диспетчер SIM"))
                self.warn(t("Прошивка не дала переключить SIM командой.\n"
                            "Открыт «Диспетчер SIM» на телефоне - выберите SIM для мобильных данных рукой."))
        self.phone_task(work, done, self.warn)

    def check_ip(self, quiet=False):
        if not self.phone_ready(quiet):
            return
        adb = self.adb
        self.phone.set_ip("", t("проверяю…"))
        self.phone.ip.setText(t("IP: проверяю…"))
        self.phone.ip.setStyleSheet("font-weight: 600; color: %s;" % theme.MUTED)

        def work(shift):
            xray = PhoneXray(adb, self.append_log, shift=shift)
            xray.ensure_installed()
            return xray.direct_ip()

        def done(result):
            ip, whitelist = result
            if ip:
                self.phone.set_ip(ip)
                self.append_log(t("IP телефона: %s") % ip)
            elif whitelist:
                self.phone.ip.setText(t("IP: белые списки - нужна капча"))
                self.phone.ip.setStyleSheet("font-weight: 600; color: %s;" % theme.AMBER)
                self.append_log(t("сеть в режиме белых списков: Телефон → Открыть капчу оператора"))
            else:
                self.phone.set_ip("")
                self.append_log(t("IP телефона: нет интернета"))
        self.phone_task(work, done, lambda error: (self.phone.set_ip(""), self.append_log(t("✖ IP: %s") % error)),
                        ports=True, quiet=quiet)

    def check_sim_money(self):
        """Баланс и остаток пакетов по каждой SIM: USSD плюс ответные SMS оператора."""
        if not self.phone_ready():
            return
        self.phone.show_sim_money(t("спрашиваю операторов…"))
        control = PhoneControl(self.adb)

        def work(say):
            return control.sim_report(progress=say, known_numbers=self.settings.get("sim_numbers") or {},
                                      only_phone=len(self.connected_phones()) <= 1)

        def done(report):
            if not report:
                self.phone.show_sim_money(t("SIM-карты не видны"))
                return
            lines = []
            numbers = dict(self.settings.get("sim_numbers") or {})
            by_sub = {}
            for item in report:
                if item.get("number"):
                    numbers[item["key"]] = item["number"]
                    by_sub[item["sub_id"]] = item["number"]
                answers = list(item["ussd"]) + [sms.replace("\n", " ") for sms in item["sms"]]
                title = item["name"] + (" %s" % item["number"] if item.get("number") else "")
                lines.append("<b>%s</b>: %s" % (html.escape(title), html.escape("; ".join(answers) if answers
                                                                                else t("оператор не ответил"))))
                for text in answers:
                    self.append_log("%s - %s" % (item["name"], text[:300]))
            self.settings["sim_numbers"] = numbers
            self.phone.set_sim_numbers(by_sub)
            self.phone.show_sim_money("<br>".join(lines), rich=True)

        def failed(error):
            self.phone.show_sim_money(t("не вышло: %s") % error)
            self.append_log(t("✖ баланс SIM: %s") % error)
        self.phone_task(work, done, failed, on_progress=self.phone.show_sim_money)

    def toggle_detail(self, on):
        self.settings["detail_columns"] = on
        for col in BRIEF_HIDDEN:
            self.table.setColumnHidden(col, not on)
            self.totals.setColumnHidden(col, not on)
        self.detail_toggle.setText(t("Подробные колонки") + (" ●" if on else ""))

    def toggle_screen(self, on):
        self.screen_toggle.blockSignals(True)
        self.screen_toggle.setChecked(on)
        self.screen_toggle.blockSignals(False)
        if on:
            self.screen_dock.show()
            self.screen.start()
        else:
            self.screen.stop()
            self.screen_dock.hide()

    def on_screen_dock_visibility(self, visible):
        if not visible and self.screen_action.isChecked() and not self.isMinimized():
            self.screen_action.setChecked(False)

    def open_captcha(self):
        if not self.phone_ready():
            return
        control = PhoneControl(self.adb)
        self.append_log(t("выключаю Wi-Fi и открываю страницу в браузере телефона - пройдите капчу на экране"))
        self.phone_task(control.open_captcha_page,
                        lambda _r: QTimer.singleShot(30000, lambda: self.check_ip(quiet=True)), self.warn)

    def new_ip(self):
        if not self.phone_ready():
            return
        control = PhoneControl(self.adb)
        self.append_log(t("режим полёта на 4 секунды - меняю IP"))
        self.phone_task(control.airplane_cycle,
                        lambda _result: QTimer.singleShot(6000, lambda: self.check_ip(quiet=True)), self.warn)

    def run_diagnostics(self):
        if not self.adb:
            return self.warn(self.adb_error)
        control = PhoneControl(self.adb)
        self.append_log(t("собираю диагностику телефона…"))
        self.run_task(control.diagnostics,
                      lambda text: self.show_dialog(TextDialog(t("Диагностика телефона"), text, self)),
                      self.warn)

    def install_xray(self):
        if not self.adb:
            return self.warn(self.adb_error)
        if not self.phone_ready():
            return
        adb = self.adb
        self.phone_task(lambda shift: PhoneXray(adb, self.append_log, shift=shift).ensure_installed(),
                        lambda version: self.append_log("xray: %s" % version), self.warn, ports=True)

    def kill_xray(self):
        if not self.phone_ready():
            return
        adb = self.adb
        self.phone_task(lambda shift: PhoneXray(adb, self.append_log, shift=shift).stop_all(),
                        lambda _r: self.append_log(t("xray на телефоне остановлен")), self.warn, ports=True)


    def eventFilter(self, obj, event):
        if obj is self.table.viewport() and event.type() == event.Type.Resize:
            self.placeholder.setGeometry(0, 0, obj.width(), obj.height())
        return super().eventFilter(obj, event)

    def load_demo(self):
        """Показать окно с выдуманными данными - посмотреть вид без телефона и панели."""
        import random

        from ..checker import Mode
        from ..phone import Sim
        self.demo = True
        self.history_timer.stop()
        if self.poller:
            self.poller.stop()
        state = PhoneState(connected=True, serial="R58X1234ABC", state="device", model="SM-A075F",
                           android="15", battery=84, charging=True, data_sub_id=1, wifi_on=False,
                           mobile_data_on=True, airplane=False, transport="cellular")
        state.sims = [Sim(1, 0, "MegaFon", "MegaFon", "LTE", 3, True), Sim(2, 1, "MTS", "MTS RUS", "LTE", 2, False)]
        self.on_phone_state(state)
        self.phone.set_ip("192.0.2.15")
        locations = [("🇩🇪 Германия", ["203.0.113.21", "203.0.113.22"]), ("🇳🇱 Нидерланды", ["198.51.100.31"]),
                     ("🇵🇱 Польша", ["198.51.100.45"]), ("🇨🇭 Швейцария", ["192.0.2.61", "192.0.2.62"]),
                     ("🇫🇮 Финляндия", ["203.0.113.71"]), ("🇦🇹 Австрия", ["198.51.100.81", "198.51.100.82"])]
        blocked = {ip for loc, ips in locations if "Польша" in loc or "Швейцария" in loc for ip in ips}
        self.targets = [{"location": t(loc), "key": "%s:443" % ip, "address": ip, "port": 443,
                         "sni": "apple.com", "outbound": {}} for loc, ips in locations for ip in ips]
        self.targets_label.setText(t("узлов: %d · локаций: %d") % (len(self.targets), len(locations)))
        modes = [Mode("dc", "dc", t("ДЦ") + " · " + t("Москва")), Mode("sim1", "sim", "MegaFon", 1),
                 Mode("sim2", "sim", "MTS", 2), Mode("wifi", "wifi", "Wi-Fi · HomeNet")]
        self.fill_table(self.targets, modes)
        self.total_cells = len(modes) * len(self.targets)
        random.seed(7)
        for mode in modes:
            demo_ips = ["203.0.113.10", "198.51.100.23", "198.51.100.77", "192.0.2.44"]
            self.on_mode_started(mode.id, random.choice(demo_ips))
            results = {}
            for target in self.targets:
                dead = target["address"] in blocked and mode.id != "dc"
                dead = random.random() < 0.08 or dead or target["address"] == DEMO_DEAD
                results[target["key"]] = {"exit_ip": "" if dead else target["address"],
                                          "latency": None if dead else random.randint(90, 400)}
                self.show_result(mode.id, target["key"], results[target["key"]])
            self.on_mode_finished(mode.id, results)
        from ..dcprobe import verdict
        check = {"ip": DEMO_DEAD, "tcp": "timeout", "tls": ""}
        check["verdict"], check["detail"] = verdict(check)
        self.show_diagnosis({"%s:443" % DEMO_DEAD: check})
        self.append_log(t("демо-режим: данные выдуманные"))

    def run_task(self, fn, on_done, on_error, on_progress=None):
        return run_task(self, fn, on_done, on_error, on_progress)

    def append_log(self, text):
        if not re.match(r"\d\d:\d\d:\d\d ", text):
            text = time.strftime("%H:%M:%S  ") + text
        self.log.appendPlainText(text)

    def toggle_log(self, visible):
        self.log.setVisible(visible)
        self.settings["log_visible"] = visible

    def warn(self, text):
        QMessageBox.warning(self, "VPNCheck Stand", text)

    def open_settings(self):
        dialog = SettingsDialog(self.settings, self)
        if dialog.exec() == QDialog.Accepted:
            old_language = self.settings.get("language", "auto")
            dialog.apply(self.settings)
            storage.save_settings(self.settings)
            new_language = self.settings.get("language", "auto")
            if new_language != old_language:
                self.settings["language"] = old_language
                self.set_language(new_language)
            if self.poller:
                self.poller.interval = int(self.settings["poll_seconds"])
        dialog.deleteLater()

    def open_connections(self):
        from .connections import ConnectionsDialog
        if self.show_dialog(ConnectionsDialog(self)) != QDialog.Accepted:
            return
        self.connections = storage.load_connections()
        current = self.panel.currentText()
        self.fill_panels()
        if current in self.connections["panels"]:
            self.panel.setCurrentText(current)
        self.networks.rebuild(self.connected_phones(), self.dc_label())
        if self.center is not None:
            self.center.set_connections(self.connections)

    def open_center(self):
        from .center import CenterWindow
        if self.center is None:
            self.center = CenterWindow(self.settings, self.connections, self)
        self.center.show()
        self.center.raise_()

    def show_new_phone_help(self):
        from .help import HelpDialog, new_phone_html
        self.show_dialog(HelpDialog(t("Как подключить новый телефон"), new_phone_html(), self))

    @staticmethod
    def show_dialog(dialog):
        dialog.setAttribute(Qt.WA_DeleteOnClose)
        return dialog.exec()

    def about(self):
        text = html.escape(t("VPNCheck Stand\n\nТелефоны на кабеле как стенд проверки VPN-узлов: "
                                  "xray запускается на телефоне по ADB, трафик уходит через его сеть "
                                  "(SIM или Wi-Fi), результат - колонка на каждую сеть. Несколько "
                                  "телефонов проверяются одновременно.\n\n"
                                  "Проверка из ДЦ - со своего сервера по SSH (Файл → Подключения).\n\n"
                                  "Как подключить новый телефон - в меню «Справка».")).replace("\n", "<br>")
        contact = t("По вопросам обхода белых списков и настройки VPN - пишите в Telegram:")
        box = QMessageBox(QMessageBox.Information, t("О программе"), "", QMessageBox.Ok, self)
        box.setTextFormat(Qt.RichText)
        box.setTextInteractionFlags(Qt.TextBrowserInteraction)
        link = '<a href="%s" style="color:#60a5fa">%s</a>'
        box.setText("%s<br><br>%s %s<br><br>%s" % (text, html.escape(contact), link % (CONTACT_URL, "@joodjoy"),
                                                   link % (REPO_URL, REPO_URL.replace("https://", ""))))
        label = box.findChild(QLabel, "qt_msgbox_label")
        if label is not None:
            label.setOpenExternalLinks(True)
        box.exec()

    def threads_running(self):
        tasks = list(self.tasks) + (list(self.center.tasks) if self.center is not None else [])
        return bool((self.worker and self.worker.isRunning()) or any(task.isRunning() for task in tasks)
                    or (self.poller and self.poller.isRunning()))

    def closeEvent(self, event):
        """Выход ждёт фоновые потоки: окно прячется, процесс закрывается, когда они закончат."""
        if not self.closing:
            if self.worker and self.worker.isRunning():
                if QMessageBox.question(self, t("Идёт проверка"), t("Остановить проверку и выйти?")) != QMessageBox.Yes:
                    self.restart_args = None
                    event.ignore()
                    return
                self.worker.stop()
            self.closing = True
            self.close_deadline = time.time() + 120
            self.settings["window_maximized"] = self.isMaximized()
            box = self.normalGeometry() if self.isMaximized() else self.frameGeometry()
            self.settings["window"] = [box.x(), box.y(), self.width(), self.height()]
            storage.save_settings(self.settings)
            self.history_timer.stop()
            if self.poller:
                self.poller.stop()
            self.screen.stop()
            if self.center is not None:
                self.center.close()
            self.release_in_background()
        stuck = self.threads_running()
        if stuck and time.time() < self.close_deadline:
            self.hide()
            event.ignore()
            QTimer.singleShot(250, self.close)
            return
        portlock.release_all(self.run_windows)
        if self.restart_args:
            QProcess.startDetached(sys.executable, self.restart_args, os.path.dirname(self.restart_args[0]))
            self.restart_args = None
        event.accept()
        if stuck:
            os._exit(0)
        QTimer.singleShot(0, QApplication.quit)


class RunGroup:
    """Несколько потоков проверки (по телефону и ДЦ) как один «прогон»: остановить, дождаться, идёт ли."""

    def __init__(self, workers):
        self.workers = workers

    def stop(self):
        for worker in self.workers:
            worker.stop()

    def isRunning(self):
        return any(worker.isRunning() for worker in self.workers)

    def wait(self, msecs=15000):
        for worker in self.workers:
            worker.wait(msecs)
