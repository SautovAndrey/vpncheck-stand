"""Левая колонка: карточка телефона и карточка «что проверять»."""
import html

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from .. import multiphone
from ..i18n import t
from . import theme
from .widgets import Card, SignalBars, StatusDot, ToggleRow, chip, muted


def restyle(widget, object_name):
    """Сменить имя объекта и перечитать стиль: без unpolish/polish Qt оставит старый цвет."""
    widget.setObjectName(object_name)
    widget.style().unpolish(widget)
    widget.style().polish(widget)


class SimRow(QWidget):
    make_data = Signal(int)

    def __init__(self, sim, parent=None):
        super().__init__(parent)
        self.sub_id = sim.sub_id
        grid = QGridLayout(self)
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setHorizontalSpacing(8)
        grid.setVerticalSpacing(2)
        self.slot = QLabel("SIM %d" % (sim.slot + 1))
        self.slot.setObjectName("small")
        self.name = QLabel()
        self.name.setStyleSheet("font-weight: 600;")
        self.bars = SignalBars()
        self.network = QLabel()
        self.network.setObjectName("small")
        self.badge = chip(t("ДАННЫЕ"), "chipBlue")
        self.button = QPushButton(t("→ данные"))
        self.button.setToolTip(t("сделать эту SIM основной для мобильных данных"))
        self.button.setObjectName("link")
        self.button.setCursor(Qt.PointingHandCursor)
        self.button.clicked.connect(lambda: self.make_data.emit(self.sub_id))
        self.number = QLabel()
        self.number.setObjectName("small")
        self.number.hide()
        grid.addWidget(self.slot, 0, 0)
        grid.addWidget(self.name, 0, 1)
        grid.addWidget(self.bars, 0, 2, alignment=Qt.AlignRight)
        grid.addWidget(self.network, 0, 3)
        grid.addWidget(self.badge, 0, 4)
        grid.addWidget(self.button, 0, 4)
        grid.addWidget(self.number, 1, 1, 1, 3)
        grid.setColumnStretch(1, 1)
        self.update_sim(sim)

    def set_number(self, number):
        """Номер SIM: телефон его не знает (поле пустое), приходит от оператора по USSD."""
        self.number.setText(number or "")
        self.number.setVisible(bool(number))

    def update_sim(self, sim):
        title = sim.name or sim.carrier or "SIM"
        if sim.carrier and sim.carrier.lower() not in title.lower():
            title = sim.carrier if title.lower() in sim.carrier.lower() else "%s · %s" % (title, sim.carrier)
        self.name.setText(title)
        self.bars.set_level(sim.signal)
        self.network.setText(sim.network if sim.network and sim.network != "Unknown" else t("нет сети"))
        self.badge.setVisible(sim.is_data)
        self.button.setVisible(not sim.is_data)


class PhonePanel(Card):
    wifi_clicked = Signal(bool)
    mobile_data_clicked = Signal(bool)
    airplane_clicked = Signal(bool)
    data_sim_requested = Signal(int)
    new_ip_requested = Signal()
    check_ip_requested = Signal()
    sim_manager_requested = Signal()
    sim_money_requested = Signal()
    phone_selected = Signal(str)

    def __init__(self, parent=None):
        super().__init__(t("Телефон"), parent)
        self.dot = StatusDot(theme.MUTED)
        self.header.insertWidget(0, self.dot)
        self.status = muted(t("не подключён"))
        self.header.addWidget(self.status)
        self.picker = QComboBox()
        self.picker.setToolTip(t("какой телефон показывать и какими кнопками управлять; проверяются все отмеченные"))
        self.picker.hide()
        self.picker.activated.connect(lambda index: self.phone_selected.emit(self.picker.itemData(index) or ""))

        self.model = QLabel("-")
        self.model.setObjectName("big")
        self.sub = muted(t("подключите телефон по кабелю с включённой отладкой по USB"))
        self.sub.setWordWrap(True)
        self.body.addWidget(self.picker)
        self.body.addWidget(self.model)
        self.body.addWidget(self.sub)

        battery_row = QHBoxLayout()
        battery_row.addWidget(muted(t("Батарея")))
        self.battery = QProgressBar()
        self.battery.setObjectName("battery")
        self.battery.setRange(0, 100)
        self.battery.setFixedHeight(10)
        self.battery.setTextVisible(False)
        self.battery_text = QLabel("-")
        battery_row.addWidget(self.battery, 1)
        battery_row.addWidget(self.battery_text)
        self.body.addLayout(battery_row)

        self.body.addWidget(self._divider())
        self.sims_box = QVBoxLayout()
        self.sims_box.setSpacing(6)
        self.sim_rows = {}
        self.sim_numbers = {}
        self.no_sims = muted(t("SIM-карты не видны"))
        self.sims_box.addWidget(self.no_sims)
        self.body.addLayout(self.sims_box)
        self.sim_manager = QPushButton(t("открыть диспетчер SIM на телефоне"))
        self.sim_manager.setObjectName("link")
        self.sim_manager.setCursor(Qt.PointingHandCursor)
        self.sim_manager.clicked.connect(self.sim_manager_requested.emit)
        self.body.addWidget(self.sim_manager, alignment=Qt.AlignLeft)
        self.sim_money = QPushButton(t("узнать баланс, трафик и номера"))
        self.sim_money.setObjectName("link")
        self.sim_money.setCursor(Qt.PointingHandCursor)
        self.sim_money.setToolTip(t("спросит операторов по USSD и прочитает ответные SMS - около минуты на SIM"))
        self.sim_money.clicked.connect(self.sim_money_requested.emit)
        self.body.addWidget(self.sim_money, alignment=Qt.AlignLeft)
        self.sim_money_view = QLabel("")
        self.sim_money_view.setTextFormat(Qt.RichText)
        self.sim_money_view.setWordWrap(True)
        self.sim_money_view.setObjectName("muted")
        self.sim_money_view.hide()
        self.body.addWidget(self.sim_money_view)

        self.body.addWidget(self._divider())
        self.wifi = ToggleRow("Wi-Fi")
        self.mobile = ToggleRow(t("Мобильные данные"))
        self.airplane = ToggleRow(t("Режим полёта"))
        self.wifi.clicked.connect(self.wifi_clicked.emit)
        self.mobile.clicked.connect(self.mobile_data_clicked.emit)
        self.airplane.clicked.connect(self.airplane_clicked.emit)
        self.body.addWidget(self.wifi)
        self.body.addWidget(self.mobile)
        self.body.addWidget(self.airplane)

        self.body.addWidget(self._divider())
        net_row = QHBoxLayout()
        self.transport = chip(t("нет сети"), "chip")
        self.ip = QLabel("IP: -")
        self.ip.setStyleSheet("font-weight: 600;")
        net_row.addWidget(self.transport)
        net_row.addWidget(self.ip)
        net_row.addStretch()
        self.body.addLayout(net_row)
        buttons = QHBoxLayout()
        self.check_ip = QPushButton(t("Проверить IP"))
        self.new_ip = QPushButton(t("Сменить IP (полёт)"))
        self.check_ip.clicked.connect(self.check_ip_requested.emit)
        self.new_ip.clicked.connect(self.new_ip_requested.emit)
        buttons.addWidget(self.check_ip)
        buttons.addWidget(self.new_ip)
        buttons.addStretch()
        self.body.addLayout(buttons)
        self.set_controls_enabled(False)

    def set_phones(self, phones, selected):
        """Список телефонов для переключателя. phones - [{"serial","tag","state"}]."""
        items = [(phone["serial"], "%s  ·  %s" % (phone["tag"], phone["serial"])) for phone in phones]
        current = [(self.picker.itemData(index), self.picker.itemText(index)) for index in range(self.picker.count())]
        if items != current:
            self.picker.blockSignals(True)
            self.picker.clear()
            for serial, text in items:
                self.picker.addItem(text, serial)
            self.picker.blockSignals(False)
        index = self.picker.findData(selected)
        if index >= 0 and index != self.picker.currentIndex():
            self.picker.setCurrentIndex(index)
        self.picker.setVisible(len(phones) > 1)

    def show_sim_money(self, text, rich=False):
        """Строка с балансом/остатками или сообщение о ходе запроса.
        Обычный текст экранируется; rich=True - уже собранная разметка, чужие данные в ней экранированы."""
        self.sim_money_view.setText(text if rich else html.escape(text or "").replace("\n", "<br>"))
        self.sim_money_view.setVisible(bool(text))

    @staticmethod
    def _divider():
        line = QWidget()
        line.setFixedHeight(1)
        line.setStyleSheet("background: %s;" % theme.BORDER)
        return line

    def set_controls_enabled(self, enabled):
        for widget in (self.wifi.switch, self.mobile.switch, self.airplane.switch,
                       self.check_ip, self.new_ip, self.sim_manager, self.sim_money):
            widget.setEnabled(enabled)
        for row in self.sim_rows.values():
            row.button.setEnabled(enabled)

    def set_ip(self, ip, note=""):
        self.ip.setText("IP: %s" % (ip or t("нет интернета")))
        self.ip.setStyleSheet("font-weight: 600; color: %s;" % (theme.GREEN if ip else theme.RED))
        self.ip.setToolTip(note)

    def show_adb_missing(self):
        """Первый запуск без adb: вместо «подключите телефон» - что поставить."""
        self.dot.set_color(theme.RED)
        self.status.setText(t("не найдена программа adb"))
        self.sub.setText(t("Не найдена программа adb - запустите install.ps1 ещё раз или: "
                           "winget install Google.PlatformTools"))

    def update_state(self, state):
        if not state.connected:
            self.dot.set_color(theme.RED if state.state else theme.MUTED)
            self.status.setText(state.error or t("не подключён"))
            self.model.setText(state.serial or "-")
            self.sub.setText(t("подключите телефон по кабелю с включённой отладкой по USB")
                             if not state.state else t("серийный номер %s") % state.serial)
            self._update_sims([])
            self.battery.setValue(0)
            self.battery_text.setText("-")
            self.transport.setText(t("нет связи"))
            restyle(self.transport, "chip")
            self.ip.setText("IP: -")
            self.ip.setToolTip("")
            self.ip.setStyleSheet("font-weight: 600; color: %s;" % theme.MUTED)
            self.set_controls_enabled(False)
            return
        self.dot.set_color(theme.GREEN)
        self.status.setText(t("на связи · %s") % state.serial)
        self.model.setText(state.model or "Android")
        self.sub.setText("Android %s" % state.android if state.android else "")
        if state.battery >= 0:
            self.battery.setValue(state.battery)
            restyle(self.battery, "battery" if state.battery > 20 else "batteryLow")
            self.battery_text.setText("%d%%%s" % (state.battery, " ⚡" if state.charging else ""))
        self._update_sims(state.sims)
        self.wifi.set_state(state.wifi_on, state.wifi_ssid if state.wifi_on else "")
        self.mobile.set_state(state.mobile_data_on)
        self.airplane.set_state(state.airplane)
        transport = {"wifi": ("Wi-Fi", "chipBlue"), "cellular": ("LTE", "chipGreen"),
                     "none": (t("нет сети"), "chipRed")}.get(state.transport, (t("сеть ?"), "chip"))
        if state.transport == "cellular":
            sim = state.data_sim()
            if sim:
                transport = ("%s · %s" % (sim.network or "LTE", sim.name or sim.carrier), "chipGreen")
        self.transport.setText(transport[0])
        restyle(self.transport, transport[1])
        self.set_controls_enabled(True)
        if state.error:
            self.status.setText(state.error)

    def _update_sims(self, sims):
        ids = [sim.sub_id for sim in sims]
        if ids != list(self.sim_rows.keys()):
            for row in self.sim_rows.values():
                self.sims_box.removeWidget(row)
                row.deleteLater()
            self.sim_rows = {}
            for sim in sims:
                row = SimRow(sim)
                row.make_data.connect(self.data_sim_requested.emit)
                self.sims_box.addWidget(row)
                self.sim_rows[sim.sub_id] = row
        for sim in sims:
            self.sim_rows[sim.sub_id].update_sim(sim)
            self.sim_rows[sim.sub_id].set_number(self.sim_numbers.get(sim.sub_id, ""))
        self.no_sims.setVisible(not sims)

    def set_sim_numbers(self, numbers):
        """Номера по sub_id. Держим у панели: строки SIM пересоздаются при смене состава."""
        self.sim_numbers = dict(numbers or {})
        for sub_id, row in self.sim_rows.items():
            row.set_number(self.sim_numbers.get(sub_id, ""))


class NetworksPanel(Card):
    """Какие сети гонять при проверке. Порядок: ДЦ → SIM-карты → Wi-Fi."""

    def __init__(self, parent=None):
        super().__init__(t("Что проверять"), parent)
        self.hint = muted(t("Каждая галочка - отдельная колонка в таблице"))
        self.hint.setWordWrap(True)
        self.body.addWidget(self.hint)
        self.boxes = {}
        self.box_layout = QVBoxLayout()
        self.box_layout.setSpacing(6)
        self.body.addLayout(self.box_layout)
        self.restore = QCheckBox(t("после проверки вернуть сеть как была"))
        self.restore.setChecked(True)
        self.body.addWidget(self.restore)
        self._checked = {}
        self.available = []
        self.headers = []

    def rebuild(self, phones, has_dc):
        """phones - [{"serial","tag","state"}] всех телефонов на кабеле (можно и один PhoneState -
        так зовёт демо-режим). С несколькими телефонами сети подписаны тегом и сгруппированы."""
        if phones is not None and not isinstance(phones, list):
            phones = [{"serial": phones.serial, "tag": "", "state": phones}]
        phones = [p for p in (phones or []) if p["state"] and p["state"].connected]
        multi = len(phones) > 1
        groups = multiphone.mode_groups(phones, has_dc)
        modes = [m for _, group in groups for m in group]
        if modes and [m.id for m in modes] == [m.id for m in self.available]:
            for mode, old in zip(modes, self.available, strict=True):
                if mode.label != old.label:
                    self.boxes[mode.id].setText(self._box_text(mode, multi))
                    old.label = mode.label
            return
        for widget in list(self.boxes.values()) + self.headers:
            self.box_layout.removeWidget(widget)
            widget.deleteLater()
        self.boxes, self.headers = {}, []
        self.available = modes
        for title, group in groups:
            if title:
                shared = group and multiphone.JOIN in multiphone.split_mode_id(group[0].id)[1]
                header = QLabel(("📶 " if shared else "📱 ") + title)
                header.setObjectName("small")
                header.setWordWrap(True)
                self.box_layout.addWidget(header)
                self.headers.append(header)
            for mode in group:
                box = QCheckBox(self._box_text(mode, multi))
                owners = multiphone.mode_serials(mode.id)
                if len(owners) > 1:
                    box.setToolTip(t("телефоны на одной точке Wi-Fi меряют одно и то же, поэтому колонка одна, "
                                     "а узлы делятся поровну между телефонами (их %d) - прогон короче") % len(owners))
                box.setChecked(self._checked.get(mode.id, True))
                box.toggled.connect(lambda on, mid=mode.id: self._checked.__setitem__(mid, on))
                self.box_layout.addWidget(box)
                self.boxes[mode.id] = box
        self.hint.setText((t("Каждая галочка - отдельная колонка; телефоны проверяются одновременно") if multi
                           else t("Каждая галочка - отдельная колонка в таблице")) if modes
                          else t("Сетей пока нет: подключите телефон или добавьте сервер-пробник "
                                 "(Файл → Подключения)"))

    @staticmethod
    def _box_text(mode, multi):
        shared = len(multiphone.mode_serials(mode.id)) > 1
        if multi and mode.kind != "dc" and not shared and " · " in mode.label:
            return mode.label.rsplit(" · ", 1)[0]
        return mode.label

    def selected(self):
        return [mode for mode in self.available if self.boxes[mode.id].isChecked()]

    def set_enabled(self, enabled):
        for box in self.boxes.values():
            box.setEnabled(enabled)
        self.restore.setEnabled(enabled)
