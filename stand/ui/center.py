"""Центр управления агентами: карта, список телефонов, матрица узел × регион, узлы и обновления."""
import html
import json
import math
import os
import re
import time
import urllib.parse
import urllib.request
import zipfile

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor, QFont, QKeySequence
from PySide6.QtWebEngineCore import QWebEngineSettings
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QInputDialog,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from .. import agentapi, errorlog, i18n, places, storage, subscription
from ..i18n import t
from . import mapscheme, theme
from .agent_dialog import (
    ABANDONED_DAYS,
    ONLINE_HOURS,
    STALE_HOURS,
    AgentDialog,
    dead_reason,
    unchecked_reason,
    version_tuple,
)
from .widgets import (
    LAST,
    Card,
    EmptyHint,
    FlowLayout,
    SortItem,
    cell_text,
    chip,
    fill_squad_combo,
    muted,
    net_error,
    network_name,
    plain_tip,
)
from .workers import run_task

ASSETS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")
AGENT_USER_MB, AGENT_USER_DAYS = 500, 30
MAX_AGENT_NODES = 300
MATRIX_SLOW_HOURS, MATRIX_SLOW_EVERY = 24, 300
TRENDS_LIMIT = 5000
ALERTS_LIMIT = 50
TAG_RE = re.compile(r"<[^>]*>")
XRAY_LIB = "lib/arm64-v8a/libxray.so"
LOCATION_ROUNDS = [(200, t("≈ 500 м - район")), (100, t("≈ 1 км")), (50, t("≈ 2 км")), (20, t("≈ 5 км - город")),
                   (10, t("≈ 10 км")), (5, t("≈ 20 км - только область"))]
NO_DATA_YET = t("Пока нет данных. Новые агенты попадают в матрицу и стабильность через сутки после подключения - "
                "так выдуманные агенты не исказят картину; их отчёты уже видны в карточке агента.")


def _remote_error(entry):
    """Ошибка агента или самого сервера (agent_id пустой) - в том же виде, что и ошибки стенда."""
    agent_id = entry.get("agent_id") or ""
    source = t("агент %s · %s") % (agent_id[:8], entry.get("model") or "") if agent_id else t("сервер")
    return {"ts": entry["ts"], "source": source,
            "version": entry.get("app_version") or "", "kind": entry.get("kind") or "", "text": entry.get("text") or ""}


def _is_updated(agent, target):
    """Стоит ли на агенте выложенная версия или новее; сравнение по числам - строками «0.10» < «0.9»."""
    version = agent.get("app_version") or ""
    return bool(version) and version_tuple(version) >= version_tuple(target)


AGENT_KINDS = {
    "crash": "падение", "check": "проверка", "install": "установка обновления", "locate": "геолокация",
    "ping": "пинг", "link-start": "канал: запуск", "link-command": "канал: команда",
    "link-foreground": "канал: работа в фоне", "cmd-result": "ответ на команду", "cmd-update": "команда обновиться",
    "core-start": "ядро проверки не запустилось", "report": "отчёт не принят сервером",
    "telegram": "Telegram: не отправлено", "backup": "резервная копия", "link": "канал: связь",
    "update": "обновление", "push-token": "push-токен", "report-deferred": "отчёт отложен", "tls": "TLS-порт",
    "core-direct": "ядро не вышло в интернет", "core-exit": "ядро упало на узле",
}
KIND_NAMES = {"падение": t("падение"), "проверка": t("проверка"), "установка обновления": t("установка обновления"),
              "геолокация": t("геолокация"), "пинг": t("пинг"), "канал: запуск": t("канал: запуск"),
              "канал: команда": t("канал: команда"), "канал: работа в фоне": t("канал: работа в фоне"),
              "ответ на команду": t("ответ на команду"), "команда обновиться": t("команда обновиться"),
              "ядро проверки не запустилось": t("ядро проверки не запустилось"),
              "отчёт не принят сервером": t("отчёт не принят сервером"),
              "падение потока": t("падение потока"), "прогон": t("прогон"), "задача": t("задача"),
              "Telegram: не отправлено": t("Telegram: не отправлено"), "резервная копия": t("резервная копия"),
              "канал: связь": t("канал: связь"), "обновление": t("обновление"), "push-токен": t("push-токен"),
              "отчёт отложен": t("отчёт отложен"), "ядро не вышло в интернет": t("ядро не вышло в интернет"),
              "ядро упало на узле": t("ядро упало на узле"), "TLS-порт": t("TLS-порт")}
MODE_PREFIXES = ("mode:", "режим ", "mode ")
ALERT_COLORS = {"down": theme.RED, "up": theme.GREEN, "flap": theme.AMBER, "more": theme.MUTED,
                "db_room": theme.RED, "expired": theme.RED, "fleet_zero": theme.RED, "expiry": theme.AMBER,
                "tls_down": theme.RED}


def error_kind(kind):
    """Тип ошибки словами. Пишется сырым кодом (агент - «check», стенд - «mode:<сеть>»), переводится здесь."""
    kind = (kind or "").strip()
    for prefix in MODE_PREFIXES:
        if kind.startswith(prefix):
            return t("режим %s") % kind[len(prefix):].strip()
    if kind.startswith("cmd-") and kind not in AGENT_KINDS:
        return t("команда %s") % kind[len("cmd-"):]
    name = AGENT_KINDS.get(kind, kind)
    return KIND_NAMES.get(name, name)


def is_crash(kind):
    """Падение программы или её потока - красным в списке ошибок."""
    return (kind or "").strip() == "crash" or (kind or "").strip().startswith("падение")


def coordinate(value, limit):
    """Координата с сервера как число в допустимых пределах, иначе None: в карту идут только числа."""
    if isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) and -limit <= number <= limit else None


def agent_point(agent):
    lat, lon = coordinate(agent.get("lat"), 90), coordinate(agent.get("lon"), 180)
    return None if lat is None or lon is None else (lat, lon)


def untrusted(agent):
    """Последний отчёт агента ненадёжный (белые списки, VPN, частичный) - цифры живых из прошлого надёжного."""
    return agent.get("last_trusted") is False or bool(agent.get("last_partial"))


def agent_status(agent, now=None):
    """(текст, цвет, ранг) статуса: онлайн сейчас / на связи (< 3 ч) / был недавно (< 12 ч) / молчит /
    не выходит (дольше ABANDONED_DAYS). Пороги те же, что у серых строк и значков карты; ранг - для сортировки."""
    silence = (now or time.time()) - (agent.get("last_seen") or 0)
    if agent.get("online"):
        return t("● онлайн сейчас"), theme.GREEN, 0
    if silence < ONLINE_HOURS * 3600:
        return t("● на связи"), theme.GREEN, 1
    if silence < STALE_HOURS * 3600:
        return t("● был недавно"), theme.TEXT, 2
    if silence < ABANDONED_DAYS * 86400:
        return t("● молчит"), theme.MUTED, 3
    return t("● не выходит"), theme.RED_TEXT, 4


def version_key(version):
    """Версия числом для сортировки: 0.10.2 → 10002, «?» - в конец."""
    parts = list(version_tuple(version)[:3]) + [0, 0, 0]
    return parts[0] * 1e8 + parts[1] * 1e4 + parts[2] if version else None


def pick_spread(targets, limit):
    """Не больше limit узлов, по кругу из каждой локации - чтобы ни одна страна не выпала целиком."""
    by_location = {}
    for target in targets:
        by_location.setdefault(target.get("location") or "", []).append(target)
    queues = [list(items) for _name, items in sorted(by_location.items())]
    picked = []
    while len(picked) < limit and any(queues):
        for queue in queues:
            if queue and len(picked) < limit:
                picked.append(queue.pop(0))
    return picked


def ago(ts):
    if not ts:
        return "-"
    delta = time.time() - ts
    if delta < 90:
        return t("только что")
    if delta < 3600:
        return t("%d мин назад") % (delta // 60)
    if delta < 86400:
        return t("%d ч назад") % (delta // 3600)
    return t("%d дн назад") % (delta // 86400)


class CenterWindow(QMainWindow):
    def __init__(self, settings, connections, parent=None):
        super().__init__(parent)
        self.setWindowTitle(t("VPNCheck Stand - центр управления агентами"))
        self.resize(1400, 860)
        self.settings = settings
        self.connections = connections
        self.tasks = []
        self.api = None
        self.agents = []
        self.all_agents = []
        self._target_version = ""
        self._published_app = {}
        self._manifest = None
        self._state_seen = False
        self._node_count = 0
        self._matrix_data = None
        self._matrix_fetched = (None, 0.0)
        self._node_labels = {}
        self._site_labels = {}
        self._pending = set()
        self._generation = 0
        self._edited = set()
        self._filling = False
        self.timer = QTimer(self)
        self.timer.setInterval(20000)
        self.timer.timeout.connect(self.refresh)
        self._build()
        self.connect_server()

    def showEvent(self, event):
        super().showEvent(event)
        if not self.timer.isActive():
            self.timer.start()
            self.refresh()

    def hideEvent(self, event):
        super().hideEvent(event)
        self.timer.stop()


    def _build(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(14, 12, 14, 10)
        root.setSpacing(10)

        bar = QHBoxLayout()
        bar.setSpacing(8)
        bar.addWidget(muted(t("Сервер")))
        agent_cfg = agentapi.load_agent_config()
        self.server = QLineEdit(agent_cfg.get("server", ""))
        self.server.setPlaceholderText(t("http://адрес-сервера:8787"))
        self.server.setMinimumWidth(260)
        bar.addWidget(self.server)
        bar.addWidget(muted(t("токен")))
        self.token = QLineEdit(agent_cfg.get("token", ""))
        self.token.setEchoMode(QLineEdit.Password)
        self.token.setFixedWidth(160)
        bar.addWidget(self.token)
        self.connect_button = QPushButton(t("Подключить"))
        self.connect_button.clicked.connect(self.connect_server)
        bar.addWidget(self.connect_button)
        self.status = muted("")
        self.status.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        bar.addWidget(self.status, 1)
        self.refresh_button = QPushButton(t("⟳ Перечитать"))
        self.refresh_button.setToolTip(t("заново запросить агентов, матрицу и ошибки с сервера"))
        self.refresh_button.clicked.connect(self.refresh)
        bar.addWidget(self.refresh_button)
        root.addLayout(bar)

        bar = QHBoxLayout()
        bar.setSpacing(8)
        self.chips = FlowLayout()
        bar.addLayout(self.chips, 1)
        self.show_abandoned = QCheckBox(t("давно молчащие"))
        self.show_abandoned.setToolTip(t("показывать агентов, молчащих дольше %d дней: удалили приложение, "
                                         "сменили телефон. В счётчики они не входят") % ABANDONED_DAYS)
        self.show_abandoned.toggled.connect(lambda _on: self.on_agents(self.all_agents))
        bar.addWidget(self.show_abandoned, alignment=Qt.AlignTop)
        self.provider_button = QPushButton(t("Карта"))
        self.provider_button.setToolTip(t("какую карту показывать"))
        menu = QMenu(self.provider_button)
        menu.addAction(t("Яндекс Карты"), lambda: self.set_map_provider("yandex"))
        menu.addAction(t("OpenStreetMap (без ключа)"), lambda: self.set_map_provider("leaflet"))
        menu.addSeparator()
        menu.addAction(t("Ключ Яндекс Карт…"), self.ask_yandex_key)
        menu.addAction(t("Перезагрузить карту"), self.load_map)
        self.provider_button.setMenu(menu)
        bar.addWidget(self.provider_button, alignment=Qt.AlignTop)
        pair = QPushButton(t("📱 Подключить агента"))
        pair.setToolTip(t("QR-коды для волонтёра: скачать приложение и подключить его к этому серверу"))
        pair.clicked.connect(self.show_pairing)
        bar.addWidget(pair, alignment=Qt.AlignTop)
        self.run_now_button = QPushButton(t("▶ Проверить всех сейчас"))
        self.run_now_button.setObjectName("primary")
        self.run_now_button.setToolTip(t("онлайн-агенты проверят сразу, остальные - при следующем выходе "
                                         "на связь (до 15 минут)"))
        self.run_now_button.clicked.connect(self.run_now_all)
        bar.addWidget(self.run_now_button, alignment=Qt.AlignTop)
        more = QPushButton(t("Ещё"))
        more.setToolTip(t("ещё: обновление агентов, отчёт по версиям"))
        more_menu = QMenu(more)
        more_menu.addAction(t("⬆ Обновить агентов"), self.update_now_all).setToolTip(
            t("агенты заберут манифест по ближайшему пингу (до 15 мин) и предложат установку"))
        more_menu.addAction(t("Отчёт по версиям"), self.show_version_report).setToolTip(
            t("кто уже обновился до выложенной версии, а кто ещё нет"))
        more_menu.setToolTipsVisible(True)
        more.setMenu(more_menu)
        bar.addWidget(more, alignment=Qt.AlignTop)
        root.addLayout(bar)

        self.tabs = QTabWidget()
        root.addWidget(self.tabs, 1)
        self.tabs.addTab(self._build_map_tab(), t("Карта и агенты"))
        self.matrix_tab = self._build_matrix_tab()
        self.tabs.addTab(self.matrix_tab, t("Матрица узел × регион"))
        self.tabs.addTab(self._build_manage_tab(), t("Узлы и обновления"))
        self.tabs.addTab(self._build_trends_tab(), t("Стабильность"))
        self.tabs.addTab(self._build_errors_tab(), t("Ошибки"))
        self.tabs.currentChanged.connect(lambda _index: self.refresh_matrix(periodic=True))

    def _build_map_tab(self):
        splitter = QSplitter(Qt.Horizontal)
        mapscheme.install()
        self.map = QWebEngineView()
        self.map.setMinimumWidth(500)
        self.map.settings().setAttribute(QWebEngineSettings.WebAttribute.LocalContentCanAccessFileUrls, False)
        self.map.loadFinished.connect(self.on_map_loaded)
        self.map.renderProcessTerminated.connect(lambda *_a: QTimer.singleShot(1000, self.load_map))
        self.load_map()
        splitter.addWidget(self.map)
        self.agents_table = QTableWidget(0, 9)
        self.agents_table.setHorizontalHeaderLabels([t("Статус"), t("Агент"), t("Город"), t("Регион"), t("Оператор"),
                                                     t("Сеть"), t("Живых"), t("Был"), t("Версия")])
        self.agents_table.horizontalHeaderItem(0).setToolTip(
            t("онлайн сейчас - держит канал команд; на связи - отчёт меньше 3 ч назад; был недавно - меньше 12 ч; "
              "молчит - дольше 12 ч; не выходит - дольше %d дн") % ABANDONED_DAYS)
        self.agents_table.verticalHeader().setVisible(False)
        self.agents_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.agents_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.agents_table.horizontalHeader().setStretchLastSection(True)
        self.agents_table.setShowGrid(False)
        self.agents_table.itemClicked.connect(lambda _item: self.focus_selected_agent())
        self.agents_table.itemDoubleClicked.connect(lambda _item: self.open_agent())
        self.agents_table.setToolTip(t("клик - показать на карте, двойной клик - карточка телефона"))
        self.agents_hint = EmptyHint(self.agents_table, t("Агентов пока нет - «📱 Подключить агента» покажет "
                                                          "QR-коды для волонтёра"))
        splitter.addWidget(self.agents_table)
        splitter.setSizes([820, 560])
        return splitter

    def _build_matrix_tab(self):
        box = QWidget()
        layout = QVBoxLayout(box)
        layout.setContentsMargins(0, 8, 0, 0)
        row = QHBoxLayout()
        row.addWidget(muted(t("За последние")))
        self.hours = QSpinBox()
        self.hours.setRange(1, 720)
        self.hours.setValue(24)
        self.hours.setSuffix(t(" ч"))
        self.hours.valueChanged.connect(lambda _v: self.refresh_matrix())
        row.addWidget(self.hours)
        row.addWidget(muted(t("в клетке - сколько раз узел ответил из этого региона и оператора")))
        row.addStretch()
        layout.addLayout(row)
        self.matrix_cut = muted("")
        self.matrix_cut.setStyleSheet("color: %s;" % theme.AMBER)
        self.matrix_cut.hide()
        layout.addWidget(self.matrix_cut)
        self.matrix = QTableWidget(0, 1)
        self.matrix.setHorizontalHeaderLabels([t("Локация (узел)")])
        self.matrix.verticalHeader().setVisible(False)
        self.matrix.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.matrix.setShowGrid(False)
        self.matrix_hint = EmptyHint(self.matrix, NO_DATA_YET)
        layout.addWidget(self.matrix, 3)
        layout.addWidget(muted(t("Сайты напрямую, без VPN: сколько раз открылся из этого региона и оператора")))
        self.sites_matrix = QTableWidget(0, 1)
        self.sites_matrix.setHorizontalHeaderLabels([t("Сайт")])
        self.sites_matrix.verticalHeader().setVisible(False)
        self.sites_matrix.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.sites_matrix.setShowGrid(False)
        self.sites_hint = EmptyHint(self.sites_matrix,
                                    t("Пока нет данных - сайты задаются во вкладке «Узлы и обновления»"))
        layout.addWidget(self.sites_matrix, 2)
        return box

    def _build_trends_tab(self):
        box = QWidget()
        layout = QVBoxLayout(box)
        layout.setContentsMargins(0, 8, 0, 0)
        layout.addWidget(muted(t("Что стабильно мертво, а что работает с перебоями. «Живучесть» - доля удачных "
                                 "проверок за последнюю неделю; узлы с перебоями (не 0% и не 100%) выделены жёлтым.")))
        self.trends_table = QTableWidget(0, 6)
        self.trends_table.setHorizontalHeaderLabels([t("Узел / сайт"), t("Регион · оператор"), t("Сейчас"),
                                                     t("Живучесть за неделю"), t("Проверок за неделю"),
                                                     t("Состояние сменилось")])
        self.trends_table.verticalHeader().setVisible(False)
        self.trends_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.trends_table.setShowGrid(False)
        self.trends_table.setSortingEnabled(True)
        self.trends_table.resizeColumnsToContents()
        self.trends_hint = EmptyHint(self.trends_table, NO_DATA_YET)
        top = QWidget()
        top_layout = QVBoxLayout(top)
        top_layout.setContentsMargins(0, 0, 0, 0)
        top_layout.addWidget(self.trends_table, 1)
        self.trends_shown = muted("")
        self.trends_shown.hide()
        top_layout.addWidget(self.trends_shown)
        bottom = QWidget()
        bottom_layout = QVBoxLayout(bottom)
        bottom_layout.setContentsMargins(0, 4, 0, 0)
        bottom_layout.addWidget(muted(t("Последние тревоги (те же, что приходят в Telegram)")))
        self.alerts_table = QTableWidget(0, 2)
        self.alerts_table.setHorizontalHeaderLabels([t("Когда"), t("Тревога")])
        self.alerts_table.verticalHeader().setVisible(False)
        self.alerts_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.alerts_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.alerts_table.horizontalHeader().setStretchLastSection(True)
        self.alerts_table.setShowGrid(False)
        self.alerts_table.itemDoubleClicked.connect(
            lambda item: QMessageBox.information(self, t("Тревога"),
                                                 self.alerts_table.item(item.row(), 1).toolTip() or item.text()))
        self.alerts_hint = EmptyHint(self.alerts_table, t("Тревог пока не было"))
        bottom_layout.addWidget(self.alerts_table, 1)
        self.trends_split = QSplitter(Qt.Vertical)
        self.trends_split.setChildrenCollapsible(False)
        self.trends_split.addWidget(top)
        self.trends_split.addWidget(bottom)
        self.trends_split.setSizes([1000, 3000])
        self.trends_empty = True
        layout.addWidget(self.trends_split, 1)
        return box

    def balance_trends(self):
        """Пустая стабильность отдаёт место тревогам; с данными - пополам. Только при смене пусто/не пусто."""
        empty = self.trends_table.rowCount() == 0
        if empty == self.trends_empty:
            return
        self.trends_empty = empty
        total = sum(self.trends_split.sizes()) or 1000
        share = 0.25 if empty else 0.5
        self.trends_split.setSizes([int(total * share), total - int(total * share)])

    def refresh_alerts(self):
        if not self.api:
            return
        api = self.api
        self.run_once("alerts", lambda: fetch_alerts(api), self.fill_alerts, lambda _e: None)

    def fill_alerts(self, alerts):
        table = self.alerts_table
        table.setRowCount(len(alerts))
        for row, alert in enumerate(alerts):
            text = alert["text"]
            lines = text.splitlines()
            first = lines[0][:200] if lines else ""
            if len(lines) > 1:
                first += "  …"
            when = QTableWidgetItem(time.strftime("%d.%m %H:%M", time.localtime(alert["ts"])) if alert["ts"] else "-")
            item = QTableWidgetItem(first)
            item.setToolTip(plain_tip(text))
            item.setForeground(QColor(alert_color(alert["kind"], text)))
            table.setItem(row, 0, when)
            table.setItem(row, 1, item)
        table.resizeColumnToContents(0)
        self.alerts_hint.sync()

    def refresh_trends(self):
        if not self.api:
            return
        api = self.api
        self.run_once("trends", lambda: fetch_trends_with_new(api), lambda answer: self.fill_trends(*answer),
                      lambda _e: None)

    def fill_trends(self, nodes, total=None, new_agents=0):
        self.trends_hint.setText(no_data_text(new_agents))
        if total is not None and total > len(nodes):
            self.trends_shown.setText(t("показано %d из %d - самые свежие") % (len(nodes), total))
        elif total is None and len(nodes) >= TRENDS_LIMIT:
            self.trends_shown.setText(t("показаны первые %d - остальные сервер не прислал") % len(nodes))
        else:
            self.trends_shown.setText("")
        self.trends_shown.setVisible(bool(self.trends_shown.text()))
        table = self.trends_table
        table.setSortingEnabled(False)
        table.setRowCount(len(nodes))
        for row, node in enumerate(nodes):
            name = node["node"]
            if name.startswith("site:"):
                name = "🌐 " + name[len("site:"):].replace("https://", "").replace("http://", "").rstrip("/")
            rate = node["rate"]
            now_text = t("● отвечает") if node["ok"] else t("✕ не отвечает")
            if node["checks"] < 3:
                verdict, color = t("мало данных"), theme.MUTED
            elif rate >= 0.95:
                verdict, color = t("стабильно жив"), theme.GREEN
            elif rate <= 0.05:
                verdict, color = t("стабильно мёртв"), theme.RED
            else:
                verdict, color = t("с перебоями %d%%") % round(rate * 100), theme.AMBER
            values = [name, node["scope"], now_text, verdict, str(node["checks"]),
                      time.strftime("%d.%m %H:%M", time.localtime(node["changed"])) if node["changed"] else "-"]
            keys = [None, None, 0 if node["ok"] else 1, rate if node["checks"] >= 3 else -1, node["checks"],
                    node["changed"] or None]
            checks_all, ok_all = node.get("checks_all"), node.get("ok_checks_all")
            for col, text in enumerate(values):
                item = SortItem(text, keys[col])
                if col in (3, 4) and isinstance(checks_all, int) and isinstance(ok_all, int) and checks_all:
                    item.setToolTip(plain_tip(t("за всё время: %d из %d проверок удачны (%d%%)")
                                              % (ok_all, checks_all, round(ok_all * 100 / checks_all))))
                if col == 3:
                    item.setForeground(QColor(color))
                    font = QFont()
                    font.setBold(True)
                    item.setFont(font)
                if col == 2:
                    item.setForeground(QColor(theme.GREEN if node["ok"] else theme.RED))
                table.setItem(row, col, item)
        table.resizeColumnsToContents()
        table.setSortingEnabled(True)
        self.trends_hint.sync()
        self.balance_trends()
        self.tabs.setTabText(3, t("Стабильность (%d)") % len(nodes) if nodes else t("Стабильность"))

    def _build_errors_tab(self):
        box = QWidget()
        layout = QVBoxLayout(box)
        layout.setContentsMargins(0, 8, 0, 0)
        row = QHBoxLayout()
        row.addWidget(muted(t("Ошибки агентов (с сервера) и самого стенда (файл errors.log). "
                              "Двойной клик - полный текст, Ctrl+C - копировать.")))
        row.addStretch()
        copy = QPushButton(t("Копировать всё"))
        copy.clicked.connect(lambda: self.copy_errors(all_rows=True))
        row.addWidget(copy)
        clear = QPushButton(t("Очистить журнал (стенд и агенты)"))
        clear.clicked.connect(self.clear_errors)
        row.addWidget(clear)
        layout.addLayout(row)
        self.errors_table = QTableWidget(0, 5)
        self.errors_table.setHorizontalHeaderLabels([t("Когда"), t("Откуда"), t("Версия"), t("Тип"), t("Текст")])
        self.errors_table.verticalHeader().setVisible(False)
        self.errors_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.errors_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.errors_table.horizontalHeader().setStretchLastSection(True)
        self.errors_table.setShowGrid(False)
        self.errors_table.itemDoubleClicked.connect(
            lambda item: QMessageBox.information(self, t("Ошибка"),
                                                 self.errors_table.item(item.row(), 4).toolTip() or item.text()))
        self.errors_table.resizeColumnsToContents()
        self.errors_table.keyPressEvent = self._errors_key
        self.errors_hint = EmptyHint(self.errors_table, t("Ошибок нет"))
        layout.addWidget(self.errors_table, 1)
        return box

    def _errors_key(self, event):
        if event.matches(QKeySequence.Copy):
            self.copy_errors()
        else:
            QTableWidget.keyPressEvent(self.errors_table, event)

    def copy_errors(self, all_rows=False):
        table = self.errors_table
        rows = range(table.rowCount()) if all_rows else sorted({item.row() for item in table.selectedItems()})
        if not rows:
            rows = range(table.rowCount())
        lines = []
        for row in rows:
            cell = table.item(row, 4)
            full = (cell.toolTip() or cell.text()) if cell else ""
            lines.append("[%s] %s · %s\n%s" % (cell_text(table, row, 0), cell_text(table, row, 1),
                                                cell_text(table, row, 3), full))
        QApplication.clipboard().setText("\n\n".join(lines))
        self.status.setText(t("✔ скопировано строк: %d") % len(rows))

    def clear_errors(self):
        errorlog.clear()
        if self.api:
            self.run(self.api.clear_errors, lambda _r: self.refresh_errors(), self.show_error)
        else:
            self.refresh_errors()
        self.refresh_trends()

    def refresh_errors(self):
        local = [{"ts": entry["ts"], "source": t("стенд"), "version": "", "kind": entry["kind"], "text": entry["text"]}
                 for entry in errorlog.read()]
        if self.api:
            self.run_once("errors", self.api.errors,
                          lambda remote: self.fill_errors(local + [_remote_error(entry) for entry in remote]),
                          lambda _error: self.fill_errors(local))
        else:
            self.fill_errors(local)

    def fill_errors(self, items):
        items.sort(key=lambda entry: entry["ts"], reverse=True)
        table = self.errors_table
        table.setRowCount(len(items))
        for row, entry in enumerate(items):
            lines = (entry["text"] or "").strip().splitlines()
            first_line = lines[0][:160] if lines else ""
            values = [time.strftime("%d.%m %H:%M", time.localtime(entry["ts"])), entry["source"], entry["version"],
                      error_kind(entry["kind"]), first_line]
            for col, text in enumerate(values):
                item = QTableWidgetItem(text)
                if col == 4:
                    item.setToolTip(plain_tip(entry["text"]))
                    item.setForeground(QColor(theme.RED if is_crash(entry["kind"]) else theme.TEXT))
                table.setItem(row, col, item)
        table.resizeColumnsToContents()
        self.errors_hint.sync()
        self.tabs.setTabText(4, t("Ошибки (%d)") % len(items) if items else t("Ошибки"))

    def _build_manage_tab(self):
        box = QWidget()
        layout = QHBoxLayout(box)
        layout.setContentsMargins(0, 8, 0, 0)
        layout.setSpacing(12)
        layout.addWidget(self._build_nodes_card(), 1)
        layout.addWidget(self._build_updates_card(), 1)
        return box

    def _build_nodes_card(self):
        """Левая карточка: какие узлы выложить агентам, интервал и сообщение, сайты, параметры проверки."""
        nodes = Card(t("Узлы для агентов"))
        nodes.body.addWidget(muted(t("Какие узлы проверяют телефоны волонтёров. Берутся из панели, как на стенде.")))
        row = QHBoxLayout()
        self.panel = QComboBox()
        self.panel.setSizeAdjustPolicy(QComboBox.AdjustToContents)
        self.fill_panels()
        self.squad = QComboBox()
        self.squad.setEditable(True)
        self.squad.setInsertPolicy(QComboBox.NoInsert)
        self.squad.setMinimumWidth(200)
        self.squad.lineEdit().setPlaceholderText(t("сквад"))
        self.squad.setToolTip(t("сквад - группа узлов в Remnawave, которую получают клиенты"))
        self.squad.setEditText(self.settings.get("squad", ""))
        fill_squad_combo(self.squad, self.settings, self.panel.currentText())
        self.panel.currentTextChanged.connect(lambda name: fill_squad_combo(self.squad, self.settings, name))
        self.push_nodes_button = QPushButton(t("Выложить узлы этого сквада"))
        self.push_nodes_button.clicked.connect(self.push_nodes)
        row.addWidget(self.panel)
        row.addWidget(self.squad)
        row.addWidget(self.push_nodes_button)
        nodes.body.addLayout(row)
        self.nodes_info = muted(t("на сервере: -"))
        nodes.body.addWidget(self.nodes_info)
        row2 = QHBoxLayout()
        row2.addWidget(muted(t("Интервал проверки, мин")))
        self.interval = QSpinBox()
        self.interval.setRange(15, 1440)
        self.interval.setValue(180)
        self.interval.valueChanged.connect(lambda _v: self._mark_edited("interval"))
        row2.addWidget(self.interval)
        row2.addWidget(muted(t("Сообщение агентам")))
        self.message = QLineEdit()
        self.message.setPlaceholderText(t("видно в приложении"))
        self.message.setToolTip(t("текст покажется на главном экране приложения у всех агентов"))
        self.message.textEdited.connect(lambda _text: self._mark_edited("message"))
        row2.addWidget(self.message, 1)
        nodes.body.addLayout(row2)
        save = QPushButton(t("Сохранить интервал и сообщение"))
        save.clicked.connect(self.push_settings)
        nodes.body.addWidget(save, alignment=Qt.AlignLeft)
        self._build_sites(nodes)
        self._build_check_params(nodes)
        nodes.body.addStretch()
        return nodes

    def _build_sites(self, card):
        """Сайты, которые агенты открывают без VPN."""
        card.body.addWidget(
            muted(t("Сайты для проверки без VPN - по одному адресу в строке, через пробел можно подпись:")))
        self.sites_edit = QTextEdit()
        self.sites_edit.setPlaceholderText(t("https://example.com  Мой сайт\nhttps://shop.example.com  Магазин"))
        self.sites_edit.setMaximumHeight(120)
        self.sites_edit.textChanged.connect(lambda: self._mark_edited("sites"))
        card.body.addWidget(self.sites_edit)
        save_sites = QPushButton(t("Сохранить сайты"))
        save_sites.clicked.connect(self.push_sites)
        card.body.addWidget(save_sites, alignment=Qt.AlignLeft)

    def _build_check_params(self, card):
        """Параметры проверки на телефонах: сервис IP, адрес замера задержки, точность геолокации."""
        card.body.addWidget(muted(t("Параметры проверки на телефонах агентов:")))
        params = QFormLayout()
        self.test_url = QLineEdit()
        self.test_url.setPlaceholderText("https://api.ipify.org")
        self.test_url.setToolTip(t("через VPN-узел телефон открывает этот адрес и узнаёт выходной IP. "
                                   "Сервис должен отвечать голым IP-адресом. Ответил - узел живой"))
        self.latency_url = QLineEdit()
        self.latency_url.setPlaceholderText("https://www.google.com/generate_204")
        self.latency_url.setToolTip(t("по времени ответа этого адреса через узел считается задержка. "
                                      "Нужен быстрый адрес с пустым ответом"))
        self.location_round = QComboBox()
        for value, label in LOCATION_ROUNDS:
            self.location_round.addItem(label, value)
        self.location_round.setToolTip(t("с какой точностью агенты сообщают, где находятся. Грубее - "
                                         "приватнее для волонтёров, точнее - детальнее карта"))
        self.test_url.textEdited.connect(lambda _text: self._mark_edited("test_url"))
        self.latency_url.textEdited.connect(lambda _text: self._mark_edited("latency_url"))
        self.location_round.activated.connect(lambda _index: self._mark_edited("location_round"))
        params.addRow(t("Сервис определения IP"), self.test_url)
        params.addRow(t("Адрес замера задержки"), self.latency_url)
        params.addRow(t("Точность геолокации"), self.location_round)
        card.body.addLayout(params)
        save_params = QPushButton(t("Сохранить параметры проверки"))
        save_params.setToolTip(t("перед сохранением стенд сам проверит, что адреса отвечают как надо"))
        save_params.clicked.connect(self.push_params)
        card.body.addWidget(save_params, alignment=Qt.AlignLeft)

    def _build_updates_card(self):
        """Правая карточка: выложенный манифест, кнопка выкладки APK, журнал выкладки."""
        updates = Card(t("Обновления"))
        updates.body.addWidget(
            muted(t("Файлы подписываются ключом с этого компьютера; агент без подписи ничего не ставит.")))
        self.manifest_view = muted(t("манифест не выложен"))
        self.manifest_view.setWordWrap(True)
        updates.body.addWidget(self.manifest_view)
        row3 = QHBoxLayout()
        apk = QPushButton(t("Выложить APK приложения…"))
        apk.clicked.connect(self.publish_apk)
        row3.addWidget(apk)
        row3.addStretch()
        updates.body.addLayout(row3)
        self.update_log = QTextEdit()
        self.update_log.setReadOnly(True)
        self.update_log.setPlaceholderText(t("здесь появится ход выкладки APK"))
        updates.body.addWidget(self.update_log, 1)
        return updates


    def connect_server(self):
        if not self.server.text().strip():
            text = t("укажите адрес своего сервера агентов, например http://203.0.113.10:8787")
            self.status.setText(text)
            self.status.setToolTip(text)
            return
        agentapi.save_agent_config(self.server.text().strip(), self.token.text().strip())
        self.api = agentapi.server_for(self.server.text().strip(), self.token.text().strip())
        self._generation += 1
        self._state_seen = False
        self.status.setText(t("подключаюсь…"))
        self.run(self.api.health,
                 lambda health: (self.set_status(t("сервер на связи · агентов: %d") % health.get("agents", 0)),
                                 self.refresh()),
                 self.health_failed)

    def health_failed(self, error):
        """Нет связи. Если стенд ходит по TLS, а обычный http отвечает - значит пропал TLS-порт: громко, агенты с
        отпечатком замолчали."""
        self.show_error(error, t("нет связи: %s"))
        api = self.api
        if not api or not api.tls:
            return
        plain = agentapi.AgentServer(self.server.text().strip(), self.token.text().strip())
        generation = self._generation

        def lost(health):
            if generation != self._generation or not isinstance(health, dict):
                return
            text = t("⚠ TLS-порт %d сервера не отвечает, а http отвечает - агенты 0.12.9+ с отпечатком молчат, "
                     "пока TLS не вернут: python server/deploy.py") % api.tls["port"]
            self.set_status(text, plain_tip("%s\n%s" % (text, net_error(error)[1])))
            self.status.setStyleSheet("color: %s;" % theme.RED)
        self.run(plain.health, lost, lambda _error: None)

    def set_status(self, text, tip=None):
        self.status.setStyleSheet("")
        self.status.setText(text)
        self.status.setToolTip(text if tip is None else tip)

    def show_error(self, error, template="✖ %s"):
        """Коротко и понятно в строке состояния, сырой текст ошибки - в подсказке."""
        short, raw = net_error(error)
        self.set_status(template % short, plain_tip(raw))

    def need_api(self):
        """Кнопки центра без подключения к серверу не молчат, а говорят, что сделать."""
        if self.api:
            return True
        QMessageBox.information(self, t("Сервер агентов"),
                                t("Сначала подключитесь к серверу агентов: адрес и токен вверху окна, "
                                  "кнопка «Подключить»."))
        return False

    def refresh(self):
        if not self.api:
            return
        self.run_once("agents", self.api.agents, self.on_agents, lambda e: self.show_error(e, t("ошибка: %s")))
        self.run_once("state", self.api.state, self.on_state, lambda e: None)
        self.refresh_matrix(periodic=True)
        self.refresh_errors()
        self.refresh_trends()
        self.refresh_alerts()

    def refresh_matrix(self, periodic=False):
        """Матрица - самый тяжёлый запрос: по таймеру только на своей вкладке, а за период больше суток -
        не чаще раза в MATRIX_SLOW_EVERY с (за сутки она почти не меняется)."""
        if not self.api:
            return
        hours = self.hours.value()
        key = (self._generation, hours)
        if periodic:
            if self.tabs.currentWidget() is not self.matrix_tab:
                return
            fetched_key, fetched_at = self._matrix_fetched
            every = MATRIX_SLOW_EVERY if hours > MATRIX_SLOW_HOURS else self.timer.interval() / 1000 - 1
            if fetched_key == key and time.time() - fetched_at < every:
                return

        def done(data):
            self._matrix_fetched = (key, time.time())
            self.on_matrix(data)
            if self.hours.value() != hours:
                self.refresh_matrix()
        self.run_once("matrix", lambda: self.api.matrix(hours), done, lambda e: None)

    def on_agents(self, agents):
        self.all_agents = agents
        now = time.time()
        for agent in agents:
            silence = now - (agent.get("last_seen") or 0)
            agent["stale"] = silence > STALE_HOURS * 3600
            agent["abandoned"] = silence > ABANDONED_DAYS * 86400
        self.agents = (agents if self.show_abandoned.isChecked()
                       else [agent for agent in agents if not agent["abandoned"]])
        self.fill_agents()
        self.push_agents_to_map()
        self.fill_chips()

    def fill_chips(self):
        while self.chips.count():
            item = self.chips.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        active = [a for a in self.agents if not a["stale"]]
        regions = {places.region(a.get("region")) or a.get("city") for a in active if a.get("region") or a.get("city")}
        operators = {a.get("operator") for a in active if a.get("operator")}
        chips = [(t("за %d ч отчитались: %d") % (STALE_HOURS, len(active)), "chipGreen" if active else "chip"),
                 (t("регионов: %d") % len(regions), "chipBlue"),
                 (t("операторов: %d") % len(operators), "chipBlue"),
                 (t("всего когда-либо: %d") % len(self.all_agents), "chip")]
        abandoned = sum(1 for a in self.all_agents if a.get("abandoned"))
        if abandoned:
            label = t("давно молчат: %d") if self.show_abandoned.isChecked() else t("давно молчат: %d (скрыты)")
            chips.append((label % abandoned, "chip"))
        target = self._target_version
        counted = [a for a in self.all_agents if not a.get("abandoned")]
        if target and counted:
            updated = sum(1 for agent in counted if _is_updated(agent, target))
            chips.append((t("обновлено %d из %d до %s") % (updated, len(counted), target),
                          "chipGreen" if updated == len(counted) else "chipAmber"))
        secure = sum(1 for agent in active if agent.get("https"))
        if secure:
            chips.append((t("по https: %d из %d") % (secure, len(active)),
                          "chipGreen" if secure == len(active) else "chipBlue"))
        zero = fleet_zero(self.agents)
        if zero:
            chips.insert(0, (t("⚠ в нуле все агенты (%d) - перевыложите узлы") % zero, "chipRed"))
        for text, kind in chips:
            label = chip(text, kind)
            if kind == "chipRed":
                label.setToolTip(t("все свежие агенты разом прислали 0 живых узлов - обычно это истёкшая "
                                   "учётка узлов агентов или узлы сменились в панели"))
            self.chips.addWidget(label)

    def fill_agents(self):
        table = self.agents_table
        table.setSortingEnabled(False)
        table.setRowCount(len(self.agents))
        target = self._target_version
        for row, agent in enumerate(self.agents):
            alive, total = agent.get("alive") or 0, agent.get("total") or 0
            status, status_color, rank = agent_status(agent)
            values = [status, agent["agent_id"][:8], places.city(agent.get("city")), places.region(agent.get("region")),
                      agent.get("operator") or "", network_name(agent.get("network")),
                      t("%d из %d") % (alive, total) if total else "-", ago(agent.get("last_seen")),
                      "%s · xray %s%s" % (agent.get("app_version") or "?", agent.get("core_version") or "?",
                                          " · https" if agent.get("https") else "")]
            seen = agent.get("last_seen") or 0
            keys = {0: rank * LAST - seen if seen else rank * LAST, 6: alive / total if total else None,
                    7: -seen if seen else None, 8: version_key(agent.get("app_version") or "")}
            for col, text in enumerate(values):
                item = SortItem(text, keys.get(col))
                if col == 0:
                    item.setData(Qt.UserRole, agent["agent_id"])
                    item.setForeground(QColor(status_color))
                    font = QFont()
                    font.setBold(True)
                    item.setFont(font)
                if col == 6 and total and untrusted(agent):
                    item.setForeground(QColor(theme.MUTED))
                    item.setToolTip(t("последний отчёт ненадёжный (белые списки, VPN или неполный) - "
                                      "цифры из прошлого надёжного"))
                elif col == 6 and total:
                    item.setForeground(QColor(theme.GREEN if alive == total
                                              else theme.RED if alive == 0 else theme.AMBER))
                elif col == 8:
                    if target and agent.get("app_version"):
                        updated = _is_updated(agent, target)
                        item.setForeground(QColor(theme.GREEN if updated else theme.AMBER))
                        item.setToolTip((t("выложена %s - обновлён") if updated
                                         else t("выложена %s - ещё не обновился")) % target)
                elif agent["stale"] and col != 0:
                    item.setForeground(QColor(theme.MUTED))
                if col == 0:
                    item.setToolTip(plain_tip("%s\n%s %s\n%s" % (agent["agent_id"], agent.get("model") or "",
                                                               agent.get("android") or "", agent.get("org") or "")))
                table.setItem(row, col, item)
        table.resizeColumnsToContents()
        table.setSortingEnabled(True)
        self.agents_hint.sync()

    def push_agents_to_map(self):
        markers = []
        for index, agent in enumerate(self.agents):
            point = agent_point(agent)
            if point is None:
                continue
            alive, total = agent.get("alive") or 0, agent.get("total") or 0
            label = "%s · %s" % (places.city(agent.get("city")) or places.region(agent.get("region")) or "?",
                                 agent.get("operator") or network_name(agent.get("network")))
            tip = t("%s\n%s\nживых %d из %d\n%s\nбыл %s") % (label, agent.get("model") or "", alive, total,
                                                       agent.get("org") or "", ago(agent.get("last_seen")))
            markers.append({"lat": point[0], "lon": point[1], "alive": int(alive), "total": int(total),
                            "stale": bool(agent["stale"]), "label": label, "tip": tip,
                            "seed": index * 1.7, "operator": str(agent.get("operator") or "")})
        self.map.page().runJavaScript("window.setAgents(%s)" % json.dumps(markers, ensure_ascii=False))

    def map_provider(self):
        cfg = agentapi.load_agent_config()
        return "yandex" if cfg.get("map_provider") == "yandex" and cfg.get("yandex_key") else "leaflet"

    def load_map(self):
        cfg = agentapi.load_agent_config()
        if self.map_provider() == "yandex":
            query = urllib.parse.urlencode({"key": cfg["yandex_key"], "lang": i18n.language()})
            url = mapscheme.url("map_yandex.html", query)
        else:
            url = mapscheme.url("map.html", "lang=" + i18n.language())
        self.map.load(url)
        self.provider_button.setText(t("Карта: Яндекс") if self.map_provider() == "yandex"
                                     else t("Карта: OpenStreetMap"))

    def set_map_provider(self, provider):
        cfg = agentapi.load_agent_config()
        if provider == "yandex" and not cfg.get("yandex_key"):
            return self.ask_yandex_key()
        cfg["map_provider"] = provider
        save_agent_file(cfg)
        self.load_map()
        return None

    def ask_yandex_key(self):
        """Ключ Яндекс Карт: в agent.json для карты центра и на сервер - для страницы /admin."""
        cfg = agentapi.load_agent_config()
        key, ok = QInputDialog.getText(
            self, t("Ключ Яндекс Карт"),
            t("Ключ JavaScript API и HTTP Геокодера из кабинета разработчика Яндекса (developer.tech.yandex.ru).\n"
              "Пусто - карта без ключа (открытая)."), QLineEdit.Normal, cfg.get("yandex_key", ""))
        if not ok:
            return None
        key = key.strip()
        cfg["yandex_key"] = key
        cfg["map_provider"] = "yandex" if key else "leaflet"
        save_agent_file(cfg)
        self.load_map()
        if self.api:
            self.run(lambda: self.api.set_state(yandex_key=key),
                     lambda _r: self.set_status(t("ключ Яндекс Карт сохранён и отправлен на сервер")),
                     lambda e: self.set_status(t("ключ сохранён здесь, но не отправлен на сервер: %s") % e))
        else:
            self.set_status(t("ключ Яндекс Карт сохранён; на сервер уйдёт после подключения - задайте его ещё раз"))
        return None

    def on_map_loaded(self, ok):
        if not ok:
            return
        world = geojson_text(os.path.join(ASSETS, "world110m.geojson"))
        if world:
            self.map.page().runJavaScript("window.setWorld(%s)" % world)
        regions = geojson_text(os.path.join(ASSETS, "ru_regions.geojson"))
        if regions:
            self.map.page().runJavaScript("window.setRegions(%s)" % regions)
        if self.agents:
            self.push_agents_to_map()

    def _selected_agent(self):
        """Агент по выбранной строке - через сохранённый id, а не номер строки (таблица сортируется)."""
        rows = self.agents_table.selectionModel().selectedRows()
        if not rows:
            return None
        item = self.agents_table.item(rows[0].row(), 0)
        agent_id = item.data(Qt.UserRole) if item else None
        return next((a for a in self.agents if a.get("agent_id") == agent_id), None)

    def focus_selected_agent(self):
        agent = self._selected_agent()
        point = agent_point(agent) if agent else None
        if point is not None:
            self.map.page().runJavaScript("window.focusOn(%s, %s, 5)" % (json.dumps(point[1]), json.dumps(point[0])))

    def open_agent(self):
        agent = self._selected_agent()
        if not agent or not self.api:
            return
        self.run(lambda: self.api.reports(limit=40, agent_id=agent["agent_id"]),
                 lambda reports: show_dialog(AgentDialog(agent, reports, self, api=self.api)),
                 self.show_error)

    def on_state(self, state):
        nodes = state.get("nodes") or []
        labels = ({node.get("key"): node.get("location") for node in nodes if node.get("key")},
                  {site.get("url"): site.get("name") for site in (state.get("sites") or []) if site.get("url")})
        changed = labels != (self._node_labels, self._site_labels)
        self._node_labels, self._site_labels = labels
        if changed and self._matrix_data:
            self.on_matrix(self._matrix_data)
        app = (state.get("manifest") or {}).get("app") or {}
        self._published_app = app
        self._manifest = state.get("manifest")
        self._state_seen = True
        self._node_count = len(nodes)
        self._target_version = app.get("version_name") or ""
        if self.agents:
            self.fill_agents()
            self.fill_chips()
        self.show_nodes_info(state, nodes)
        self.show_manifest(state.get("manifest"))
        self.fill_state_fields(state)

    def show_nodes_info(self, state, nodes):
        """Строка «на сервере узлов…» и срок учётки агентов: чем ближе конец, тем заметнее."""
        info = t("на сервере узлов: %d · интервал %d мин") % (len(nodes), state.get("interval_min", 0))
        expire, color = float(state.get("nodes_expire") or 0), theme.MUTED
        if nodes and not expire:
            info += " · " + t("срок учётки агентов неизвестен - выложите узлы заново")
            color = theme.AMBER
        elif expire:
            left = expire - time.time()
            when = time.strftime("%d.%m %H:%M", time.localtime(expire))
            if left <= 0:
                info += " · " + t("✖ УЧЁТКА АГЕНТОВ ИСТЕКЛА %s - выложите узлы заново, "
                                  "агенты не могут подключиться") % when
                color = theme.RED
            elif left < 86400:
                info += " · " + t("⚠ учётка агентов истекает %s (меньше суток) - выложите узлы заново") % when
                color = theme.RED
            else:
                info += " · " + t("учётка агентов до %s (осталось %d дн)") % (when, int(left // 86400))
                color = theme.AMBER if left < 2 * 86400 else theme.MUTED
        self.nodes_info.setText(info)
        self.nodes_info.setStyleSheet("color: %s" % color)

    def fill_state_fields(self, state):
        """Поля настроек с сервера - только те, что человек сейчас не правит."""
        self._filling = True
        try:
            if self._untouched("interval", self.interval):
                self.interval.setValue(int(state.get("interval_min") or 180))
            if self._untouched("test_url", self.test_url):
                self.test_url.setText(state.get("test_url") or "")
            if self._untouched("latency_url", self.latency_url):
                self.latency_url.setText(state.get("latency_url") or "")
            if self._untouched("location_round", self.location_round):
                current = int(state.get("location_round") or 200)
                nearest = min(range(len(LOCATION_ROUNDS)),
                              key=lambda index: abs(LOCATION_ROUNDS[index][0] - current))
                self.location_round.setCurrentIndex(nearest)
            if self._untouched("message", self.message):
                self.message.setText(state.get("message") or "")
            if self._untouched("sites", self.sites_edit):
                self.sites_edit.setPlainText("\n".join("%s  %s" % (site.get("url", ""), site.get("name", ""))
                                                       for site in state.get("sites") or []))
        finally:
            self._filling = False

    def show_manifest(self, manifest):
        """Что выложено - одной строкой (версия и дата), весь манифест - в подсказке."""
        if not isinstance(manifest, dict) or not manifest:
            self.manifest_view.setText(t("манифест не выложен"))
            self.manifest_view.setToolTip("")
            return
        app = manifest.get("app") if isinstance(manifest.get("app"), dict) else {}
        issued = manifest.get("issued")
        version = app.get("version_name") or "?"
        if isinstance(issued, (int, float)) and issued > 0:
            when = time.strftime("%d.%m.%Y %H:%M", time.localtime(issued))
            self.manifest_view.setText(t("Выложено: приложение %s · %s") % (version, when))
        else:
            self.manifest_view.setText(t("Выложено: приложение %s") % version)
        self.manifest_view.setToolTip(plain_tip(json.dumps(manifest, ensure_ascii=False, indent=1)))

    def _mark_edited(self, name):
        if not self._filling:
            self._edited.add(name)

    def _untouched(self, name, widget):
        """Поле можно перезаписать с сервера: человек его не правит и несохранённых правок в нём нет."""
        return name not in self._edited and not widget.hasFocus()

    def _saved(self, *names):
        self._edited.difference_update(names)
        self._generation += 1
        self.refresh()

    def on_matrix(self, data):
        self._matrix_data = data
        columns = list(data.get("columns", {}).keys())
        unchecked = data.get("unchecked") if isinstance(data.get("unchecked"), dict) else {}
        reasons = data.get("reasons") if isinstance(data.get("reasons"), dict) else {}
        self.show_matrix_cut(data)
        self.matrix_hint.setText(no_data_text(data.get("new_agents")))
        self.fill_matrix(self.matrix, t("Локация (узел)"), columns, data.get("matrix", {}), self._node_labels,
                         unchecked, reasons)
        self.fill_matrix(self.sites_matrix, t("Сайт"), columns, data.get("sites", {}), self._site_labels)

    def show_matrix_cut(self, data, now=None):
        """Сервер собрал матрицу не за весь период (отчётов слишком много) - сказать, за сколько на самом деле."""
        since = data.get("since")
        if not data.get("truncated") or not isinstance(since, (int, float)) or isinstance(since, bool):
            self.matrix_cut.setText("")
            self.matrix_cut.hide()
            return
        span = max(0.0, (now or time.time()) - since)
        text = t("%d дн.") % round(span / 86400) if span >= 2 * 86400 else t("%d ч") % max(1, round(span / 3600))
        self.matrix_cut.setText(t("⚠ отчётов слишком много - матрица только за %s, а не за весь период") % text)
        self.matrix_cut.show()

    def fill_matrix(self, table, first, columns, matrix, labels, unchecked=None, reasons=None):
        """unchecked - {узел: {колонка: код причины}} от сервера: агент узел не проверил (серым, причина
        в подсказке). reasons - {узел: {колонка: dns-sinkhole | dns-fail}}: почему узел был мёртв."""
        unchecked = {key: value for key, value in (unchecked or {}).items() if isinstance(value, dict)}
        reasons = {key: value for key, value in (reasons or {}).items() if isinstance(value, dict)}
        matrix = {**{key: {} for key in unchecked}, **matrix}
        table.setSortingEnabled(False)
        table.setColumnCount(1 + len(columns))
        table.setHorizontalHeaderLabels([first] + columns)
        keys = sorted(matrix.keys(), key=lambda key: (labels.get(key) or "я" + key).lower())
        table.setRowCount(len(keys))
        for row, key in enumerate(keys):
            alive_any = any((matrix[key].get(column) or [0, 0])[0] for column in columns)
            checked_any = any((matrix[key].get(column) or [0, 0])[1] for column in columns)
            name = labels.get(key) or key
            head = QTableWidgetItem(("✕ " if checked_any and not alive_any else "") + name)
            head.setToolTip(plain_tip(key))
            if checked_any and not alive_any:
                head.setForeground(QColor(theme.RED))
                font = QFont()
                font.setBold(True)
                head.setFont(font)
            table.setItem(row, 0, head)
            for col, column in enumerate(columns, start=1):
                cell = matrix[key].get(column)
                reason = unchecked.get(key, {}).get(column)
                if not cell and reason:
                    item = SortItem(t("не проверен"))
                    item.setForeground(QColor(theme.MUTED))
                    item.setToolTip(plain_tip(t("агент не проверил узел: %s") % unchecked_reason(reason)))
                elif not cell:
                    item = SortItem("-")
                    item.setForeground(QColor(theme.MUTED))
                else:
                    alive, total = cell
                    item = SortItem("%d / %d" % (alive, total), alive / total if total else -1)
                    ratio = alive / total if total else 0
                    color = theme.GREEN if ratio >= 0.8 else theme.RED if ratio == 0 else theme.AMBER
                    item.setForeground(QColor(color))
                    font = QFont()
                    font.setBold(True)
                    item.setFont(font)
                    tips = [t("в части отчётов не проверен: %s") % unchecked_reason(reason)] if reason else []
                    why = dead_reason(reasons.get(key, {}).get(column))
                    if why:
                        tips.append(t("последний раз мёртв: %s") % why)
                    if tips:
                        item.setToolTip(plain_tip("\n".join(tips)))
                item.setTextAlignment(Qt.AlignCenter)
                table.setItem(row, col, item)
        table.resizeColumnsToContents()
        table.horizontalHeader().setStretchLastSection(True)
        table.setSortingEnabled(True)
        for hint in (self.matrix_hint, self.sites_hint):
            hint.sync()


    def push_nodes(self):
        if not self.need_api():
            return None
        panel, squad = self.panel.currentText(), self.squad.currentText().strip()
        if not squad:
            return QMessageBox.warning(self, t("Узлы"), t("Укажите сквад"))
        self.log(t("загружаю узлы %s / %s…") % (panel, squad))
        self.push_nodes_button.setEnabled(False)

        def work(say):
            panel_config = self.connections["panels"].get(panel)
            if not panel_config:
                raise ValueError(t("панель не настроена - Файл → Подключения в главном окне"))
            targets, release = subscription.from_panel(panel_config, squad,
                                                       only_443=bool(self.settings.get("only_443", True)),
                                                       limit=(AGENT_USER_MB, AGENT_USER_DAYS))
            user = agent_user(release)
            try:
                release()
                if len(targets) > MAX_AGENT_NODES:
                    say(t("⚠ узлов в скваде: %d, агентам можно не больше %d - выкладываю %d, "
                          "поровну из каждой локации") % (len(targets), MAX_AGENT_NODES, MAX_AGENT_NODES))
                    targets = pick_spread(targets, MAX_AGENT_NODES)
                return self.api.set_nodes(targets, expire=user.get("expire"), user=user.get("username"))
            except Exception:
                if user.get("uuid"):
                    try:
                        subscription.Panel.from_config(panel_config).delete_user(user["uuid"])
                    except Exception as exc:  # noqa: BLE001 - учётка с лимитом истечёт сама
                        say(t("✖ учётка %s не удалена: %s") % (user.get("username"), exc))
                raise
        def done(answer):
            self.push_nodes_button.setEnabled(True)
            self.log(t("выложено узлов: %s (учётка на %d дней, %d МБ) - через %d дней выложить заново")
                     % (answer.get("nodes"), AGENT_USER_DAYS, AGENT_USER_MB, AGENT_USER_DAYS))
            self.refresh()

        def failed(error):
            self.push_nodes_button.setEnabled(True)
            self.log_error(t("✖ узлы: %s"), error)
        self.run(work, done, failed, on_progress=self.log)
        return None

    def show_pairing(self):
        from .pairing import PairingDialog
        server = self.server.text().strip()
        if not server:
            return QMessageBox.warning(self, t("Подключить агента"), t("Сначала укажите адрес сервера агентов"))
        show_dialog(PairingDialog(server, signing_key(), self,
                                  app_missing=self._state_seen and not self._published_app.get("url"),
                                  nodes_missing=self._state_seen and not self._node_count,
                                  tls=agentapi.tls_for(server),
                                  manifest=self._manifest if self._state_seen else None))
        return None

    def set_connections(self, connections):
        """Панели поменяли в «Подключениях» главного окна - обновить список здесь."""
        self.connections = connections
        current = self.panel.currentText()
        self.fill_panels()
        if current in connections["panels"]:
            self.panel.setCurrentText(current)

    def fill_panels(self):
        self.panel.clear()
        for name in sorted(self.connections["panels"]):
            self.panel.addItem(name)
        self.panel.setPlaceholderText("" if self.panel.count() else t("нет панелей - добавьте в Файл → Подключения"))
        if self.panel.count():
            self.panel.setCurrentIndex(0)

    def run_now_all(self):
        if not self.need_api():
            return
        if QMessageBox.question(self, t("Проверить всех"),
                                t("Попросить всех агентов проверить узлы сейчас?")) != QMessageBox.Yes:
            return
        self.run(lambda: self.api.run_now(),
                 lambda _r: self.set_status(t("толчок отправлен: онлайн-агенты проверят сразу, остальные - при "
                                              "следующем выходе на связь (до 15 минут)")),
                 self.show_error)

    def update_now_all(self):
        if not self.need_api():
            return
        if QMessageBox.question(self, t("Обновить агентов"),
                                t("Разослать всем агентам команду обновить приложение?")) != QMessageBox.Yes:
            return
        self.run(lambda: self.api.update_now(),
                 lambda _r: (self.set_status(t("сигнал обновиться отправлен - «Ещё → Отчёт по версиям» "
                                               "обновляется по мере отчётов")),
                             self.show_version_report()),
                 self.show_error)

    def show_version_report(self):
        """Кто встал на выложенную версию, а кто ещё нет. Версия агента обновляется по его отчёту/пингу."""
        target = self._target_version
        if not target:
            return QMessageBox.information(self, t("Отчёт по версиям"),
                                           t("Приложение ещё не выложено - обновлять не на что."))
        done, pending = [], []
        for agent in sorted(self.agents, key=lambda item: -(item.get("last_seen") or 0)):
            name = "%s · %s" % (agent["agent_id"][:8], agent.get("model") or t("телефон"))
            when = t("онлайн сейчас") if agent.get("online") else (t("был %s") % ago(agent.get("last_seen")))
            line = "%s - %s (%s)" % (name, agent.get("app_version") or "?", when)
            (done if _is_updated(agent, target) else pending).append(line)
        text = [t("Выложена версия: %s") % target, "",
                t("✅ Обновились (%d):") % len(done)] + (done or ["  -"]) + \
               ["", t("⏳ Ещё не обновились (%d):") % len(pending)] + (pending or ["  -"]) + \
               ["", t("Версия обновится, когда телефон следующий раз выйдет на связь."),
                t("С открытым каналом команда доходит сразу, иначе до 15 минут.")]
        box = QMessageBox(self)
        box.setWindowTitle(t("Отчёт по версиям агентов"))
        box.setTextFormat(Qt.PlainText)
        box.setText("\n".join(text))
        box.setIcon(QMessageBox.Information)
        box.exec()

    def push_sites(self):
        if not self.need_api():
            return
        sites = []
        for line in self.sites_edit.toPlainText().splitlines():
            parts = line.strip().split(None, 1)
            if parts and parts[0].startswith(("http://", "https://")):
                sites.append({"url": parts[0], "name": parts[1].strip() if len(parts) > 1 else ""})
        self.run(lambda: self.api.set_state(sites=sites),
                 lambda _r: (self.log(t("сайтов на проверку: %d") % len(sites)), self._saved("sites")),
                 lambda e: self.log_error("✖ %s", e))

    def push_settings(self):
        if not self.need_api():
            return
        interval, message = self.interval.value(), self.message.text()
        self.run(lambda: self.api.set_state(interval_min=interval, message=message),
                 lambda _r: (self.log(t("настройки сохранены")), self._saved("interval", "message")),
                 lambda e: self.log_error("✖ %s", e))

    def push_params(self):
        """Сохранить параметры проверки; адреса сначала проверяются - иначе у всех агентов разом
        «все узлы мёртвые» из-за опечатки в адресе."""
        if not self.need_api():
            return None
        test_url, latency_url = self.test_url.text().strip(), self.latency_url.text().strip()
        rounding = int(self.location_round.currentData())
        for name, url in ((t("сервис IP"), test_url), (t("адрес задержки"), latency_url)):
            if not url.startswith("https://"):
                return QMessageBox.warning(self, t("Параметры"), t("%s: нужен адрес https://…") % name)
        self.log(t("проверяю адреса…"))

        def check():
            return check_probe_urls(test_url, latency_url)

        def save():
            self.run(lambda: self.api.set_state(test_url=test_url, latency_url=latency_url, location_round=rounding),
                     lambda _r: (self.log(t("параметры проверки сохранены - агенты возьмут их при следующей проверке")),
                                 self._saved("test_url", "latency_url", "location_round")),
                     lambda e: self.log_error("✖ %s", e))

        def checked(problems):
            if problems and QMessageBox.question(
                    self, t("Параметры"), t("Адреса отвечают не так, как нужно:\n\n%s\n\nВсё равно сохранить?")
                    % "\n".join(problems)) != QMessageBox.Yes:
                return self.log(t("параметры не сохранены"))
            save()

        self.run(check, checked, lambda e: self.log(t("✖ проверка адресов: %s") % e))

    def publish_apk(self):
        if not self.need_api():
            return None
        if not signing_key():
            return QMessageBox.warning(self, t("Обновление"),
                                       t("Ключа подписи обновлений на этом компьютере нет - без него агенты "
                                         "обновление не примут.\n\nСоздайте ключ: python tools/make_keys.py\n"
                                         "(один раз; сохраните копию папки keys вне этого компьютера)"))
        path, _ = QFileDialog.getOpenFileName(self, t("APK приложения"), "", "APK (*.apk)")
        if not path:
            return None
        problem = apk_problem(path)
        if problem:
            return QMessageBox.warning(self, t("Обновление"), problem)
        meta = apk_metadata(path)
        version_name, ok = self._ask_version(t("версия приложения (например 0.2.0)"), meta.get("version_name", ""))
        if not ok or not version_name.strip():
            return None
        code, ok = self._ask_version(t("versionCode (целое, больше прошлого)"), str(meta.get("version_code", "")))
        code = code.strip()
        if not ok or not code.isdigit():
            return None
        mismatch = [name for name, typed, built in ((t("версия"), version_name.strip(), meta.get("version_name")),
                                                    ("versionCode", code, meta.get("version_code")))
                    if built not in (None, "") and str(built) != typed]
        if mismatch and QMessageBox.question(
                self, t("Обновление"),
                t("Не совпадает с output-metadata.json рядом с APK: %s.\n\nВсё равно выложить?")
                % ", ".join(mismatch)) != QMessageBox.Yes:
            return None
        published = int(self._published_app.get("version_code") or 0)
        if published and int(code) <= published and QMessageBox.question(
                self, t("Обновление"),
                t("versionCode %s не больше выложенного (%d) - телефоны это обновление не поставят.\n\n"
                  "Всё равно выложить?") % (code, published)) != QMessageBox.Yes:
            return None
        version_name, name = version_name.strip(), os.path.basename(path)
        self.log(t("выкладываю %s (%.1f МБ)…") % (name, os.path.getsize(path) / 1e6))

        def work():
            sha = agentapi.sha256_file(path)
            self.api.upload(path)
            return self.api.publish_manifest(app={"version_code": int(code), "version_name": version_name,
                                                  "url": "/files/" + name, "sha256": sha})
        self.run(work, lambda m: (self.log(t("манифест подписан: приложение %s") % version_name), self.refresh()),
                 lambda e: self.log_error("✖ APK: %s", e))
        return None

    def _ask_version(self, prompt, default=""):
        return QInputDialog.getText(self, t("Обновление"), prompt, QLineEdit.Normal, default)


    def run(self, fn, on_done, on_error, on_progress=None):
        return run_task(self, fn, on_done, on_error, on_progress)

    def run_once(self, name, fn, on_done, on_error):
        """Периодический запрос: пока прежний такой же не вернулся, новый не запускаем.
        Ответ прошлого поколения (до смены сервера или сохранения) отбрасывается - он устарел."""
        key = (name, self._generation)
        if key in self._pending:
            return None
        self._pending.add(key)

        def done(result):
            self._pending.discard(key)
            if key[1] == self._generation:
                on_done(result)

        def failed(error):
            self._pending.discard(key)
            if key[1] == self._generation:
                on_error(error)
        return self.run(fn, done, failed)

    def log(self, text):
        self.update_log.append(time.strftime("%H:%M:%S  ") + text)

    def log_error(self, template, error):
        """В журнал выкладки - понятный текст и следом сырой, чтобы было что прислать разработчику."""
        short, raw = net_error(error)
        self.log(template % (short if short == raw else "%s (%s)" % (short, raw)))


def show_dialog(dialog):
    """Диалог с родителем удаляется после закрытия - иначе каждое открытие копит окно в памяти."""
    dialog.setAttribute(Qt.WA_DeleteOnClose)
    return dialog.exec()


def save_agent_file(cfg):
    """agent.json с админ-токеном: атомарно и только владельцу."""
    storage.write_json(agentapi.AGENT_CONFIG, cfg, indent=1, mode=0o600)


def agent_user(release):
    """Учётка агентов, созданная этой выкладкой: из release; у release без такого поля - из общей переменной."""
    if hasattr(release, "agent_user"):
        return dict(release.agent_user or {})
    return dict(getattr(subscription, "LAST_AGENT_USER", None) or {})


def apk_problem(path):
    """Почему APK выкладывать нельзя, или "": без ядра xray у всех волонтёров «ядро не запустилось»."""
    try:
        with zipfile.ZipFile(path) as archive:
            names = set(archive.namelist())
    except (OSError, zipfile.BadZipFile):
        return t("Это не APK: файл не открывается как архив.")
    if XRAY_LIB not in names:
        return t("В APK нет ядра проверки (%s) - у волонтёров проверка не запустится.\n\n"
                 "Перед сборкой скачайте его: python tools/fetch_binaries.py") % XRAY_LIB
    return ""


def apk_metadata(path):
    """versionName и versionCode из output-metadata.json, который Gradle кладёт рядом с APK; нет файла - {}."""
    try:
        with open(os.path.join(os.path.dirname(path), "output-metadata.json"), encoding="utf-8") as handle:
            data = json.load(handle)
        elements = data.get("elements") or []
        element = next((item for item in elements if item.get("outputFile") == os.path.basename(path)),
                       elements[0] if len(elements) == 1 else None)
    except (OSError, ValueError, AttributeError):
        return {}
    if not isinstance(element, dict):
        return {}
    result = {}
    if str(element.get("versionName") or "").strip():
        result["version_name"] = str(element["versionName"]).strip()
    if isinstance(element.get("versionCode"), int) and not isinstance(element.get("versionCode"), bool):
        result["version_code"] = element["versionCode"]
    return result


def signing_key():
    """Публичный ключ подписи обновлений в hex или "" - ключа на этом компьютере нет."""
    try:
        return agentapi.public_key_hex()
    except (OSError, ValueError):
        return ""


def geojson_text(path):
    """Текст geojson из assets, если это настоящий JSON: в runJavaScript уходит только проверенный JSON."""
    try:
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        json.loads(text)
    except (OSError, ValueError):
        return ""
    return text


def fetch_trends(api, limit=TRENDS_LIMIT):
    """Стабильность и сколько строк на сервере всего: (узлы, total или None у старого сервера)."""
    answer = api.trends(limit=limit)
    if not isinstance(answer, tuple) or len(answer) != 2 or not isinstance(answer[0], list):
        return [], None
    return answer


def no_data_text(new_agents):
    """Пустая матрица или стабильность: почему пусто и сколько агентов ждут своих суток."""
    if isinstance(new_agents, int) and not isinstance(new_agents, bool) and new_agents > 0:
        wait = t("Новых агентов: %d - появятся здесь в течение суток после подключения")
        return NO_DATA_YET + "\n\n" + wait % new_agents
    return NO_DATA_YET


def new_agents_count(answer):
    value = answer.get("new_agents") if isinstance(answer, dict) else None
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 0


def fetch_trends_with_new(api):
    """Стабильность и, если она пуста, сколько новых агентов ещё не попали в неё (один лёгкий запрос)."""
    nodes, total = fetch_trends(api)
    if nodes:
        return nodes, total, 0
    try:
        return nodes, total, new_agents_count(api._request("GET", "/v1/admin/trends?limit=1"))
    except Exception:  # noqa: BLE001 - старый сервер или сеть: подсказка без числа
        return nodes, total, 0


def alert_color(kind, text=""):
    """Цвет тревоги в истории: ⛔ (учётка истекла, у старых записей kind ещё «expiry») - красный."""
    if "⛔" in str(text or "")[:40]:
        return theme.RED
    return ALERT_COLORS.get(kind, theme.AMBER)


def alert_text(text):
    """Текст тревоги для таблицы: без HTML-разметки Telegram, сущности - обратно в символы."""
    return html.unescape(TAG_RE.sub("", str(text or ""))).strip()


def fetch_alerts(api, limit=ALERTS_LIMIT):
    """Последние тревоги с сервера: [{ts, kind, text}], свежие первыми; непонятный ответ - пусто."""
    answer = api._request("GET", "/v1/admin/alerts?limit=%d" % limit)
    rows = answer.get("alerts") if isinstance(answer, dict) else None
    alerts = []
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        ts = row.get("ts")
        ts = float(ts) if isinstance(ts, (int, float)) and not isinstance(ts, bool) else 0.0
        text = alert_text(row.get("text"))
        if text:
            alerts.append({"ts": ts, "kind": str(row.get("kind") or ""), "text": text})
    alerts.sort(key=lambda alert: alert["ts"], reverse=True)
    return alerts


def fleet_zero(agents, window=3 * 3600, minimum=3, now=None):
    """Сколько свежих агентов, если ВСЕ они (минимум трое) прислали 0 живых узлов; иначе 0.

    Операторы в разных регионах режут по-разному - одновременный ноль у всех значит поломку
    у нас: учётка узлов агентов истекла, узлы сменились в панели или панель лежит.
    Агенты с ненадёжным последним отчётом (белые списки, VPN, неполный) не считаются.
    """
    now = now or time.time()
    fresh = [agent for agent in agents if (agent.get("total") or 0) > 0 and agent.get("network") != "vpn"
             and not untrusted(agent) and now - (agent.get("last_seen") or 0) < window]
    if len(fresh) < minimum or any(agent.get("alive") for agent in fresh):
        return 0
    return len(fresh)


def check_probe_urls(test_url, latency_url, timeout=10):
    """Отвечает ли сервис IP голым адресом, а адрес задержки - успехом. Список проблем (пусто - всё хорошо).

    Проверяется с этого компьютера: если здесь стоит VPN-клиент, ответ придёт через него -
    для проверки формата ответа это не мешает.
    """
    import ipaddress
    problems = []
    text = ""
    try:
        with urllib.request.urlopen(urllib.request.Request(test_url, headers={"User-Agent": "curl/8"}),
                                    timeout=timeout) as response:
            text = response.read(200).decode("utf-8", "replace").strip()
        ipaddress.ip_address(text)
    except ValueError:
        problems.append(t("сервис IP ответил не IP-адресом, а «%s»") % text[:60])
    except Exception as exc:  # noqa: BLE001 - сеть, TLS, HTTP-ошибки: человеку нужна причина
        problems.append(t("сервис IP не открылся: %s") % exc)
    try:
        with urllib.request.urlopen(urllib.request.Request(latency_url, headers={"User-Agent": "curl/8"}),
                                    timeout=timeout) as response:
            if not 200 <= response.status < 400:
                problems.append(t("адрес задержки ответил кодом %d") % response.status)
    except Exception as exc:  # noqa: BLE001
        problems.append(t("адрес задержки не открылся: %s") % exc)
    return problems
