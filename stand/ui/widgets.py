"""Мелкие визуальные элементы: карточка, точка статуса, переключатель, шкала сигнала."""
import html

from PySide6.QtCore import QPoint, QRect, QSize, Qt, Signal
from PySide6.QtGui import QColor, QPainter
from PySide6.QtWidgets import (
    QAbstractButton,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLayout,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..errors import explain
from ..i18n import t
from . import theme

SORT_ROLE = Qt.UserRole + 1
LAST = 1e12


class SortItem(QTableWidgetItem):
    """Ячейка, которая сортируется по числу в SORT_ROLE, а не по тексту: «● 372 мс» раньше «● 1050 мс».
    Без числа - по тексту; ячейки без числа уходят в конец."""

    def __init__(self, text="", key=None):
        super().__init__(text)
        if key is not None:
            self.setData(SORT_ROLE, float(key))

    def __lt__(self, other):
        mine, theirs = self.data(SORT_ROLE), other.data(SORT_ROLE)
        if mine is None and theirs is None:
            return self.text() < other.text()
        if mine is None or theirs is None:
            return theirs is None
        if mine == theirs:
            return self.text() < other.text()
        return mine < theirs


class Card(QFrame):
    def __init__(self, title="", parent=None):
        super().__init__(parent)
        self.setObjectName("card")
        self.body = QVBoxLayout(self)
        self.body.setContentsMargins(16, 14, 16, 14)
        self.body.setSpacing(10)
        if title:
            self.header = QHBoxLayout()
            self.title = QLabel(title)
            self.title.setObjectName("cardTitle")
            self.header.addWidget(self.title)
            self.header.addStretch()
            self.body.addLayout(self.header)


class StatusDot(QWidget):
    def __init__(self, color=theme.MUTED, size=10, parent=None):
        super().__init__(parent)
        self._color = QColor(color)
        self._size = size
        self.setFixedSize(size + 4, size + 4)

    def set_color(self, color):
        self._color = QColor(color)
        self.update()

    def paintEvent(self, _event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setPen(Qt.NoPen)
        glow = QColor(self._color)
        glow.setAlpha(70)
        painter.setBrush(glow)
        painter.drawEllipse(0, 0, self._size + 4, self._size + 4)
        painter.setBrush(self._color)
        painter.drawEllipse(2, 2, self._size, self._size)


class Switch(QAbstractButton):
    """Переключатель-пилюля. Программная установка состояния - set_state(), сигнал только от клика."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setCheckable(True)
        self.setCursor(Qt.PointingHandCursor)
        self.setFixedSize(42, 22)

    def set_state(self, on):
        self.blockSignals(True)
        self.setChecked(bool(on))
        self.blockSignals(False)
        self.update()

    def sizeHint(self):
        return QSize(42, 22)

    def paintEvent(self, _event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        track = QColor(theme.ACCENT if self.isChecked() else theme.BORDER)
        if not self.isEnabled():
            track.setAlpha(110)
        painter.setPen(Qt.NoPen)
        painter.setBrush(track)
        painter.drawRoundedRect(0, 0, 42, 22, 11, 11)
        knob = QColor("#ffffff" if self.isEnabled() else "#9aa4ae")
        painter.setBrush(knob)
        painter.drawEllipse(22 if self.isChecked() else 2, 2, 18, 18)


class SignalBars(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.level = -1
        self.setFixedSize(26, 18)

    def set_level(self, level):
        self.level = level
        self.update()

    def paintEvent(self, _event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setPen(Qt.NoPen)
        heights = (5, 9, 13, 17)
        for index, height in enumerate(heights):
            filled = self.level >= index + 1
            color = QColor(theme.GREEN if self.level >= 3 else theme.AMBER if self.level >= 1 else theme.RED)
            painter.setBrush(color if filled else QColor(theme.BORDER))
            painter.drawRoundedRect(index * 6, 18 - height, 4, height, 1.5, 1.5)


def chip(text, kind="chip"):
    label = QLabel(text)
    label.setTextFormat(Qt.PlainText)
    label.setObjectName(kind)
    return label


def muted(text):
    label = QLabel(text)
    label.setTextFormat(Qt.PlainText)
    label.setObjectName("muted")
    return label


def plain_label(text):
    """QLabel для чужих данных (присланных агентом или телефоном): текст как есть, без разметки."""
    label = QLabel(text)
    label.setTextFormat(Qt.PlainText)
    return label


def plain_tip(text):
    """Подсказка с чужими данными: экранируем и явно делаем форматированной, чтобы переносы строк остались."""
    return "<qt>%s</qt>" % html.escape(str(text or "")).replace("\n", "<br>")


def cell_text(table, row, col):
    item = table.item(row, col)
    return item.text() if item else ""


def fill_squad_combo(combo, settings, panel):
    """Сквады панели из кэша настроек; введённый сквад остаётся, только если он есть у этой панели.
    False - кэша нет, список надо запросить у панели."""
    cached = (settings.get("squads_cache") or {}).get(panel) or []
    current = combo.currentText().strip()
    combo.clear()
    combo.addItems(cached)
    combo.setEditText((current if current in cached else cached[0]) if cached else current)
    return bool(cached)


def network_name(value):
    """Тип сети агента словами: cellular/wifi приходят кодами."""
    names = {"cellular": t("мобильная"), "wifi": "Wi-Fi", "vpn": "VPN", "ethernet": "Ethernet"}
    return names.get(str(value or "").lower(), value or "")


class ToggleRow(QWidget):
    """Строка «название - переключатель - подпись справа»."""
    clicked = Signal(bool)

    def __init__(self, title, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.title = QLabel(title)
        self.switch = Switch()
        self.note = muted("")
        layout.addWidget(self.title)
        layout.addStretch()
        layout.addWidget(self.note)
        layout.addSpacing(8)
        layout.addWidget(self.switch)
        self.switch.clicked.connect(self.clicked.emit)

    def set_state(self, on, note=""):
        self.switch.set_state(on)
        self.note.setText(note)


class FlowLayout(QLayout):
    """Элементы в строку с переносом: плашки не распирают окно, а уходят на следующую строку."""

    def __init__(self, parent=None, spacing=8):
        super().__init__(parent)
        self._items = []
        self.setSpacing(spacing)
        self.setContentsMargins(0, 0, 0, 0)

    def addItem(self, item):
        self._items.append(item)

    def count(self):
        return len(self._items)

    def itemAt(self, index):
        return self._items[index] if 0 <= index < len(self._items) else None

    def takeAt(self, index):
        return self._items.pop(index) if 0 <= index < len(self._items) else None

    def expandingDirections(self):
        return Qt.Orientation(0)

    def hasHeightForWidth(self):
        return True

    def heightForWidth(self, width):
        return self._place(QRect(0, 0, width, 0), dry=True)

    def setGeometry(self, rect):
        super().setGeometry(rect)
        self._place(rect, dry=False)

    def sizeHint(self):
        return self.minimumSize()

    def minimumSize(self):
        size = QSize()
        for item in self._items:
            size = size.expandedTo(item.minimumSize())
        return size

    def _place(self, rect, dry):
        x, y, line = rect.x(), rect.y(), 0
        gap = self.spacing()
        for item in self._items:
            hint = item.sizeHint()
            if x + hint.width() > rect.right() + 1 and line:
                x, y, line = rect.x(), y + line + gap, 0
            if not dry:
                item.setGeometry(QRect(QPoint(x, y), hint))
            x += hint.width() + gap
            line = max(line, hint.height())
        return y + line - rect.y()


def net_error(error):
    """Короткий понятный текст сетевой ошибки; сырой текст - для подсказки и журнала."""
    raw = str(error or "")
    return explain(error) or raw, raw


class EmptyHint(QLabel):
    """Серая подсказка поверх пустой таблицы: «данных пока нет» вместо пустой сетки."""

    def __init__(self, table, text):
        super().__init__(text, table.viewport())
        self.table = table
        self.setObjectName("muted")
        self.setAlignment(Qt.AlignCenter)
        self.setWordWrap(True)
        self.setAttribute(Qt.WA_TransparentForMouseEvents)
        table.viewport().installEventFilter(self)
        self.sync()

    def sync(self):
        self.setGeometry(self.table.viewport().rect())
        self.setVisible(self.table.rowCount() == 0)

    def eventFilter(self, obj, event):
        if event.type() == event.Type.Resize:
            self.setGeometry(obj.rect())
        return False
