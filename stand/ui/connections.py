"""Окно «Подключения»: панели Remnawave и сервер-пробник для колонки «ДЦ».

Всё, что здесь вводится (API-токены, SSH-пароль), хранится в connections.json в папке
настроек программы - вне папки с кодом, в репозиторий не попадает.
"""
import shiboken6
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from .. import dcprobe, storage
from ..i18n import t
from ..remnawave import Panel
from .widgets import muted
from .workers import run_task


def _mask(token):
    return (token[:4] + "…" + token[-4:]) if len(token) > 12 else "••••"


def _parse_headers(text):
    """«Имя: значение» по строке → dict. Пустые и кривые строки пропускаются."""
    headers = {}
    for line in text.splitlines():
        name, sep, value = line.partition(":")
        if sep and name.strip():
            headers[name.strip()] = value.strip()
    return headers


class PanelDialog(QDialog):
    """Одна панель: имя, адрес, API-токен и (редко нужно) заголовки доступа."""

    def __init__(self, name="", config=None, parent=None):
        super().__init__(parent)
        config = config or {}
        self.setWindowTitle(t("Панель Remnawave"))
        self.setMinimumWidth(560)
        form = QFormLayout(self)
        self.name = QLineEdit(name)
        self.name.setPlaceholderText(t("как называть в списке, например main"))
        self.url = QLineEdit(config.get("url", ""))
        self.url.setPlaceholderText("https://panel.example.com")
        self.token = QLineEdit(config.get("token", ""))
        self.token.setEchoMode(QLineEdit.Password)
        self.token.setPlaceholderText(t("Remnawave → Settings → API Tokens → создать"))
        self.verify = QCheckBox(t("проверять сертификат HTTPS"))
        self.verify.setChecked(bool(config.get("verify_tls", True)))
        self.headers = QPlainTextEdit("\n".join("%s: %s" % kv for kv in (config.get("headers") or {}).items()))
        self.headers.setPlaceholderText(t("обычно пусто; если панель за прокси с секретом -\n"
                                          "по заголовку на строку, например  X-Api-Key: …"))
        self.headers.setFixedHeight(70)
        form.addRow(t("Имя"), self.name)
        form.addRow(t("Адрес панели"), self.url)
        form.addRow(t("API-токен"), self.token)
        form.addRow("", self.verify)
        form.addRow(t("Доп. заголовки"), self.headers)
        note = muted(t("Стенд создаёт в выбранном скваде временного пользователя, берёт его подписку "
                       "и после проверки удаляет. Токену нужны права на пользователей и сквады."))
        note.setWordWrap(True)
        form.addRow(note)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        form.addRow(buttons)

    def value(self):
        return self.name.text().strip(), {
            "url": self.url.text().strip(), "token": self.token.text().strip(),
            "verify_tls": self.verify.isChecked(), "headers": _parse_headers(self.headers.toPlainText())}


class ConnectionsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(t("Подключения"))
        self.setMinimumWidth(720)
        self.tasks = []
        self.data = storage.load_connections()
        self._tested_key = {}
        layout = QVBoxLayout(self)

        panels = QGroupBox(t("Панели Remnawave - источник узлов"))
        box = QVBoxLayout(panels)
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels([t("Имя"), t("Адрес"), t("Токен")])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setFixedHeight(150)
        self.table.doubleClicked.connect(lambda _index: self.edit_panel())
        box.addWidget(self.table)
        row = QHBoxLayout()
        for text, handler in ((t("Добавить"), self.add_panel), (t("Изменить"), self.edit_panel),
                              (t("Удалить"), self.remove_panel), (t("Проверить"), self.test_panel)):
            button = QPushButton(text)
            button.clicked.connect(handler)
            row.addWidget(button)
        row.addStretch()
        box.addLayout(row)
        box.addWidget(muted(t("Без панели узлы можно брать по ссылке на подписку или из файла.")))
        layout.addWidget(panels)

        probe = QGroupBox(t("Сервер-пробник - колонка «ДЦ»"))
        form = QFormLayout(probe)
        spec = self.data["probe"]
        self.host = QLineEdit(spec.get("host", ""))
        self.host.setPlaceholderText(t("адрес своего Linux-сервера; пусто - колонки ДЦ не будет"))
        self.port = QSpinBox()
        self.port.setRange(1, 65535)
        self.port.setValue(int(spec.get("port") or 22))
        self.user = QLineEdit(spec.get("user") or "root")
        self.key = QLineEdit(spec.get("key", ""))
        self.key.setPlaceholderText(t("путь к SSH-ключу, например ~/.ssh/id_ed25519"))
        browse = QPushButton("…")
        browse.setFixedWidth(40)
        browse.clicked.connect(self.pick_key)
        key_row = QHBoxLayout()
        key_row.addWidget(self.key)
        key_row.addWidget(browse)
        self.password = QLineEdit(spec.get("password", ""))
        self.password.setEchoMode(QLineEdit.Password)
        self.password.setPlaceholderText(t("если без ключа"))
        self.place = QLineEdit(spec.get("place", ""))
        self.place.setPlaceholderText(t("как подписать колонку ДЦ, например Москва"))
        self.xray_path = QLineEdit(spec.get("xray_path", ""))
        self.xray_path.setPlaceholderText(t("пусто - стенд сам поставит официальный xray %s") % dcprobe.XRAY_VERSION)
        form.addRow(t("Адрес"), self.host)
        form.addRow(t("SSH-порт"), self.port)
        form.addRow(t("Пользователь"), self.user)
        form.addRow(t("Ключ"), key_row)
        form.addRow(t("Пароль"), self.password)
        form.addRow(t("Место"), self.place)
        form.addRow(t("Свой xray на сервере"), self.xray_path)
        test_probe = QPushButton(t("Проверить вход"))
        test_probe.clicked.connect(self.test_probe)
        form.addRow("", test_probe)
        note = muted(t("Лучше всего сервер в той же стране, что и телефоны: тогда разница между ДЦ и "
                       "оператором показывает, что режет именно оператор. На сервере нужны python3 и curl."))
        note.setWordWrap(True)
        form.addRow(note)
        layout.addWidget(probe)

        self.status = QLabel("")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Save).setText(t("Сохранить"))
        buttons.button(QDialogButtonBox.Cancel).setText(t("Отмена"))
        buttons.accepted.connect(self.save)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.fill()


    def fill(self):
        panels = self.data["panels"]
        self.table.setRowCount(len(panels))
        for row, (name, config) in enumerate(sorted(panels.items())):
            for col, text in enumerate((name, config.get("url", ""), _mask(config.get("token", "")))):
                self.table.setItem(row, col, QTableWidgetItem(text))
        self.table.resizeColumnsToContents()

    def selected_name(self):
        row = self.table.currentRow()
        item = self.table.item(row, 0) if row >= 0 else None
        return item.text() if item else ""

    def add_panel(self):
        dialog = PanelDialog(parent=self)
        if dialog.exec() == QDialog.Accepted:
            self.put_panel("", *dialog.value())

    def edit_panel(self):
        name = self.selected_name()
        if not name:
            return
        dialog = PanelDialog(name, self.data["panels"][name], self)
        if dialog.exec() == QDialog.Accepted:
            self.put_panel(name, *dialog.value())

    def put_panel(self, old_name, name, config):
        if not name or not config["url"] or not config["token"]:
            return QMessageBox.warning(self, t("Панель"), t("Нужны имя, адрес и API-токен"))
        if old_name and old_name != name:
            self.data["panels"].pop(old_name, None)
        self.data["panels"][name] = config
        self.fill()

    def remove_panel(self):
        name = self.selected_name()
        if name and QMessageBox.question(self, t("Панель"), t("Удалить панель «%s»?") % name) == QMessageBox.Yes:
            self.data["panels"].pop(name, None)
            self.fill()

    def test_panel(self):
        name = self.selected_name()
        if not name:
            return
        config = self.data["panels"][name]
        self.status.setText(t("проверяю панель %s…") % name)

        def work():
            return Panel.from_config(config).squads()

        def done(squads):
            names = ", ".join(squad["name"] for squad in squads) or t("сквадов нет")
            self.status.setText(t("✔ панель %s отвечает. Сквады: %s") % (name, names))

        self.run(work, done, lambda error: self.status.setText("✖ %s" % error))


    def run(self, work, on_done, on_error):
        """Проверка фоном. Задачу держит главное окно: диалог могут закрыть раньше ответа, тогда ответ
        просто не показывается, а выход из программы дожидается потока."""
        parent = self.parent()
        owner = parent if parent is not None and hasattr(parent, "tasks") else self

        def alive(handler):
            return lambda value: handler(value) if shiboken6.isValid(self) and self.isVisible() else None
        return run_task(owner, work, alive(on_done), alive(on_error))

    def pick_key(self):
        path, _ = QFileDialog.getOpenFileName(self, t("SSH-ключ"))
        if path:
            self.key.setText(path)

    def probe_spec(self):
        spec = {"host": self.host.text().strip(), "port": self.port.value(), "user": self.user.text().strip() or "root",
                "key": self.key.text().strip(), "password": self.password.text(),
                "xray_path": self.xray_path.text().strip(), "place": self.place.text().strip()}
        if not spec["host"]:
            return {}
        saved = self.data["probe"]
        extra = {key: value for key, value in saved.items() if key not in spec}
        same_server = saved.get("host") == spec["host"] and int(saved.get("port") or 22) == spec["port"]
        if not same_server:
            extra.pop("host_key", None)
        tested = self._tested_key.get((spec["host"], spec["port"]))
        if tested:
            extra["host_key"] = tested
        return {**extra, **{key: value for key, value in spec.items() if value not in ("", None)}}

    def test_probe(self):
        spec = self.probe_spec()
        if not spec:
            return self.status.setText(t("укажите адрес сервера"))
        self.status.setText(t("захожу на %s…") % spec["host"])

        def work():
            client = dcprobe.connect(spec)
            if spec.get("host_key"):
                self._tested_key[(spec["host"], spec["port"])] = spec["host_key"]
            try:
                out, _err, _code = dcprobe.run(client, "uname -m; command -v python3 >/dev/null && echo py; "
                                                       "command -v curl >/dev/null && echo curl", 30)
                path = spec.get("xray_path") or "%s/xray-%s/xray" % (dcprobe.REMOTE_DIR, dcprobe.XRAY_VERSION)
                xray, _err, _code = dcprobe.run(client, "%s version 2>&1 | head -1" % dcprobe.shell_quote(path), 30)
                return out.split(), xray.strip()
            finally:
                client.close()

        def done(result):
            facts, xray = result
            missing = [name for name, mark in (("python3", "py"), ("curl", "curl")) if mark not in facts]
            if missing:
                return self.status.setText(t("✖ вход есть, но на сервере нет: %s") % ", ".join(missing))
            note = (t("xray на месте: %s") % xray.split("(")[0].strip()) if "Xray" in xray else \
                (t("✖ по указанному пути нет xray") if spec.get("xray_path") else
                 t("xray стенд поставит сам при первой проверке из ДЦ"))
            self.status.setText(t("✔ вход есть (%s). %s") % (facts[0] if facts else "?", note))

        self.run(work, done, lambda error: self.status.setText("✖ %s" % error))

    def save(self):
        probe = self.probe_spec()
        on_disk = storage.load_connections()["probe"]
        if (probe and not probe.get("host_key") and on_disk.get("host_key") and on_disk.get("host") == probe["host"]
                and int(on_disk.get("port") or 22) == probe["port"]):
            probe["host_key"] = on_disk["host_key"]
        self.data["probe"] = probe
        storage.save_connections(self.data)
        self.accept()
