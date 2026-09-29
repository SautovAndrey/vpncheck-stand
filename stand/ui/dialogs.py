"""Диалоги и мелкие составные виджеты главного окна."""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from .. import i18n
from ..i18n import t


class SettingsDialog(QDialog):
    def __init__(self, settings, parent=None):
        super().__init__(parent)
        self.setWindowTitle(t("Настройки"))
        self.setMinimumWidth(520)
        form = QFormLayout(self)
        self.batch = QSpinBox(); self.batch.setRange(1, 12); self.batch.setValue(int(settings["batch"]))
        self.wait = QSpinBox(); self.wait.setRange(3, 60); self.wait.setValue(int(settings["wait"]))
        self.net_wait = QSpinBox(); self.net_wait.setRange(10, 180); self.net_wait.setValue(int(settings["net_wait"]))
        self.poll = QSpinBox(); self.poll.setRange(2, 60); self.poll.setValue(int(settings["poll_seconds"]))
        self.only_443 = QCheckBox(t("По умолчанию только порт 443 (галочка «все порты» на главном экране - "
                                    "на один прогон)"))
        self.whitelist_mode = QComboBox()
        self.whitelist_mode.addItem(t("пропустить колонку - узлы там мертвы не по своей вине"), "skip")
        self.whitelist_mode.addItem(t("проверить узлы - искать обходы, которые пробивают белые списки"), "check")
        self.whitelist_mode.setSizeAdjustPolicy(QComboBox.AdjustToContents)
        self.whitelist_mode.setCurrentIndex(
            max(0, self.whitelist_mode.findData(settings.get("whitelist_mode", "skip"))))
        self.only_443.setChecked(bool(settings["only_443"]))
        self.language = QComboBox()
        for code, label in i18n.LANGUAGES:
            self.language.addItem(label, code)
        self.language.setCurrentIndex(max(0, self.language.findData(settings.get("language", "auto"))))
        language_row = QHBoxLayout()
        language_row.addWidget(self.language, 1)
        restart_note = QLabel(t("(после перезапуска)"))
        restart_note.setObjectName("muted")
        language_row.addWidget(restart_note)
        self.add_hinted(form, t("Узлов одновременно на телефоне"), self.batch,
                        t("Сколько узлов проверять на телефоне одновременно. Больше - быстрее, "
                          "но слабые телефоны начинают ошибаться"))
        self.add_hinted(form, t("Пауза на старт xray, с"), self.wait,
                        t("Сколько ждать запуска xray на телефоне перед проверкой узла"))
        self.add_hinted(form, t("Ждать интернет после смены сети, с"), self.net_wait,
                        t("Сколько ждать интернет после переключения SIM или Wi-Fi"))
        self.add_hinted(form, t("Опрос телефона, с"), self.poll, t("Как часто обновлять карточку телефона"))
        form.addRow("", self.only_443)
        form.addRow(t("Если SIM в белых списках"), self.whitelist_mode)
        form.addRow(t("Язык интерфейса"), language_row)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        form.addRow(buttons)

    @staticmethod
    def add_hinted(form, title, widget, hint):
        """Строка формы с серой подсказкой под полем; та же подсказка - при наведении."""
        box = QWidget()
        column = QVBoxLayout(box)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(2)
        widget.setMinimumWidth(120)
        column.addWidget(widget, alignment=Qt.AlignLeft)
        note = QLabel(hint)
        note.setObjectName("small")
        note.setWordWrap(True)
        column.addWidget(note)
        widget.setToolTip(hint)
        label = QLabel(title)
        label.setToolTip(hint)
        form.addRow(label, box)

    def apply(self, settings):
        settings.update({
            "batch": self.batch.value(), "wait": self.wait.value(), "net_wait": self.net_wait.value(),
            "poll_seconds": self.poll.value(), "only_443": self.only_443.isChecked(),
            "whitelist_mode": self.whitelist_mode.currentData(), "language": self.language.currentData()})


class HistoryCombo(QComboBox):
    """Список прогонов обновляется при каждом открытии - видны и прогоны из консоли.

    Ширину под самую длинную строку («2026-09-23 12:43 - ДЦ 59/160, MegaFon 48/160, …») не берём:
    так он просил полторы тысячи точек и сплющивал всю панель инструментов. Кнопка узкая,
    а раскрытый список - широкий, строки там видны целиком.
    """
    POPUP_WIDTH = 760

    def __init__(self, refresh, parent=None):
        super().__init__(parent)
        self.refresh = refresh
        self.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.setMinimumContentsLength(18)

    def showPopup(self):
        self.refresh()
        self.view().setMinimumWidth(max(self.width(), self.POPUP_WIDTH))
        super().showPopup()


class TextDialog(QDialog):
    def __init__(self, title, text, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(900, 650)
        layout = QVBoxLayout(self)
        view = QPlainTextEdit()
        view.setReadOnly(True)
        view.setPlainText(text)
        layout.addWidget(view)
        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
