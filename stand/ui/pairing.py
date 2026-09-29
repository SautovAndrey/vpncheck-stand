"""Окно «Подключить агента»: два QR-кода - скачать приложение и подключить его к этому серверу.

Волонтёру не нужно ничего вводить: камера телефона видит первый QR - скачивается APK, видит
второй - открывается агент с вопросом «Подключиться к серверу?». В ссылке подключения - адрес
сервера и публичный ключ, которым сервер подписывает обновления: агент будет ставить обновления
только от этого сервера; если deploy сохранил TLS - ещё TLS-порт и отпечаток ключа сервера.
"""
import urllib.parse

from PySide6.QtCore import Qt
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
)

from ..i18n import t
from . import theme
from .widgets import muted


def manifest_issued(manifest):
    """issued текущего манифеста сервера (0 - манифеста нет или он без issued)."""
    issued = manifest.get("issued") if isinstance(manifest, dict) else None
    if isinstance(issued, bool) or not isinstance(issued, int) or issued <= 0:
        return 0
    return issued


def tls_matches(tls, manifest):
    """TLS стенда совпадает с tls в текущем манифесте сервера - только тогда его можно класть в QR вместе с ti."""
    current = manifest.get("tls") if isinstance(manifest, dict) else None
    if not tls or not tls.get("port") or not tls.get("pin") or not isinstance(current, dict):
        return False
    return current.get("port") == int(tls["port"]) and current.get("pin") == str(tls["pin"])


def pairing_link(server, key_hex, tls=None, manifest=None):
    """vpncheck://pair?server=…&key=…&tp=…&pin=…&ti=… - её понимает агент с версии 0.10. tp (TLS-порт) и pin
    (sha256/… ключа сервера) - из agent.json стенда (tls_for), ti - issued текущего манифеста сервера: агент 0.12.12+
    не принимает манифестов старше ti (старый pin или старый манифест без tls его не собьют). tp/pin кладутся только
    вместе с ti и только если совпадают с tls манифеста; ti без tp/pin - просто нижняя граница. Агент 0.12.11+ с pin
    сразу ходит по https, более старые эти параметры не читают."""
    query = {"server": server.rstrip("/")}
    if key_hex:
        query["key"] = key_hex
    issued = manifest_issued(manifest)
    if issued and tls_matches(tls, manifest):
        query["tp"] = str(int(tls["port"]))
        query["pin"] = str(tls["pin"])
    if issued:
        query["ti"] = str(issued)
    return "vpncheck://pair?" + urllib.parse.urlencode(query)


def qr_pixmap(text, scale=6):
    """QR-код в картинку Qt. segno - маленькая библиотека без зависимостей."""
    import io

    import segno
    buffer = io.BytesIO()
    segno.make(text, error="m").save(buffer, kind="png", scale=scale, border=2, dark="#0e1319", light="#ffffff")
    pixmap = QPixmap()
    pixmap.loadFromData(buffer.getvalue(), "PNG")
    return pixmap


class PairingDialog(QDialog):
    def __init__(self, server, key_hex, parent=None, app_missing=False, nodes_missing=False, tls=None,
                 manifest=None):
        super().__init__(parent)
        self.setWindowTitle(t("Подключить агента"))
        layout = QVBoxLayout(self)
        layout.addWidget(muted(t("Покажите волонтёру этот экран. Обе картинки читаются обычной камерой телефона.")))
        warnings = []
        if app_missing:
            warnings.append(t("⚠ На сервере ещё нет приложения - первый QR-код откроет ошибку. Выложите его: "
                              "«Узлы и обновления» → «Выложить APK приложения…»"))
        if nodes_missing:
            warnings.append(t("⚠ Узлы для агентов не выложены - агент подключится, но проверять ему будет нечего"))
        if not key_hex:
            warnings.append(t("⚠ Ключа подписи обновлений на этом компьютере нет - агент подключится, но "
                              "обновления от этого сервера ставить не сможет. "
                              "Создайте ключ: python tools/make_keys.py"))
        if tls and not (manifest_issued(manifest) and tls_matches(tls, manifest)):
            warnings.append(t("⚠ TLS этого стенда не совпадает с манифестом на сервере (или манифест ещё не "
                              "загружен) - в QR нет отпечатка, агент начнёт по http. Перевыкатите сервер: "
                              "python server/deploy.py"))
        for text in warnings:
            warning = muted(text)
            warning.setWordWrap(True)
            warning.setStyleSheet("color: %s;" % theme.AMBER)
            layout.addWidget(warning)
        row = QHBoxLayout()
        apk_url = server.rstrip("/") + "/agent.apk"
        link = pairing_link(server, key_hex, tls, manifest)
        codes = [(t("1. Скачать приложение"), qr_pixmap(apk_url),
                  t("Скачать и установить APK (разрешить установку из этого источника). Если камера не "
                    "открывает ссылку - отсканируйте любым сканером QR или откройте ссылку на телефоне")),
                 (t("2. Подключить к серверу"), qr_pixmap(link),
                  t("Откроется агент и спросит «Подключиться к серверу?» - нажать «Подключить»"))]
        tallest = max(pixmap.height() for _title, pixmap, _hint in codes)
        for title, pixmap, hint in codes:
            box = QVBoxLayout()
            head = QLabel(title)
            head.setObjectName("cardTitle")
            box.addWidget(head, alignment=Qt.AlignHCenter)
            image = QLabel()
            image.setPixmap(pixmap)
            image.setFixedHeight(tallest)
            image.setAlignment(Qt.AlignHCenter | Qt.AlignVCenter)
            box.addWidget(image, alignment=Qt.AlignHCenter)
            note = muted(hint)
            note.setWordWrap(True)
            note.setAlignment(Qt.AlignLeft | Qt.AlignTop)
            note.setFixedWidth(max(300, image.pixmap().width()))
            box.addWidget(note, alignment=Qt.AlignHCenter | Qt.AlignTop)
            box.addStretch(1)
            row.addLayout(box)
        layout.addLayout(row)
        copy_row = QHBoxLayout()
        field = QLineEdit(link)
        field.setReadOnly(True)
        field.setCursorPosition(0)
        copy = QPushButton(t("Копировать ссылку"))
        copy.clicked.connect(lambda: QApplication.clipboard().setText(link))
        copy_row.addWidget(field, 1)
        copy_row.addWidget(copy)
        layout.addLayout(copy_row)
        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.button(QDialogButtonBox.Close).setText(t("Закрыть"))
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
