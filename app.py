#!/usr/bin/env python3
"""VPNCheck Stand - телефон на кабеле как стенд проверки VPN-узлов.

    python app.py                 # запуск
    python app.py --screenshot x.png   # снять окно и выйти (для проверки внешнего вида)
"""
import argparse
import os
import sys

from PySide6.QtCore import QLibraryInfo, QTimer, QTranslator
from PySide6.QtGui import QFont, QIcon
from PySide6.QtWidgets import QApplication

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from stand import i18n  # noqa: E402
from stand.i18n import t  # noqa: E402
from stand.ui import mapscheme  # noqa: E402
from stand.ui.main_window import MainWindow  # noqa: E402
from stand.ui.theme import QSS  # noqa: E402


def keep_on_screen(window, avail):
    """Подстраховка после show(): двигаем окно так, чтобы полоса заголовка была видна.

    Размеры рамки известны только когда окно показано, поэтому проверяем здесь, а не до show().
    Без этого окно, закрытое развёрнутым, открывалось с заголовком выше экрана и не двигалось мышью.
    """
    frame = window.frameGeometry()
    x, y = frame.x(), frame.y()
    if frame.width() <= avail.width():
        x = min(max(x, avail.left()), avail.right() - frame.width())
    else:
        x = avail.left()
    y = min(max(y, avail.top()), max(avail.bottom() - frame.height(), avail.top()))
    if (x, y) != (frame.x(), frame.y()):
        window.move(x, y)


def install_qt_translation(app):
    """Стандартные кнопки и диалоги Qt (Yes/No, OK/Cancel, выбор файла) - на языке интерфейса."""
    if i18n.language() != "ru":
        return
    translator = QTranslator(app)
    if translator.load("qtbase_ru", QLibraryInfo.path(QLibraryInfo.TranslationsPath)):
        app.installTranslator(translator)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--screenshot", help=t("сохранить снимок окна в файл и выйти"))
    parser.add_argument("--demo", action="store_true", help=t("показать окно с выдуманными данными"))
    parser.add_argument("--screen", action="store_true", help=t("сразу открыть экран телефона"))
    parser.add_argument("--delay", type=int, default=3, help=t("секунд до снимка (для --screenshot)"))
    args = parser.parse_args()

    from stand import errorlog
    errorlog.install_excepthook()
    mapscheme.register()
    app = QApplication(sys.argv)
    app.setApplicationName("VPNCheck Stand")
    install_qt_translation(app)
    here = os.path.dirname(os.path.abspath(__file__))
    app.setWindowIcon(QIcon(os.path.join(here, "stand", "ui", "assets", "icon.ico")))
    app.setStyle("Fusion")
    app.setStyleSheet(QSS)
    app.setFont(QFont("Segoe UI", 10))
    window = MainWindow(demo=args.demo)
    avail = app.primaryScreen().availableGeometry()
    geometry = window.settings.get("window")
    maximized = bool(window.settings.get("window_maximized")) and not args.screenshot
    if geometry and len(geometry) == 4:
        x, y, width, height = geometry
        width, height = min(width, avail.width()), min(height, avail.height())
        x = min(max(x, avail.left()), max(avail.right() - width, avail.left()))
        y = min(max(y, avail.top()), max(avail.bottom() - height, avail.top()))
        window.resize(width, height)
        window.move(x, y)
    else:
        window.resize(min(1400, avail.width()), min(860, avail.height()))
        maximized = not args.screenshot
    if maximized:
        window.showMaximized()
    else:
        window.show()
        keep_on_screen(window, avail)
    if args.demo:
        window.load_demo()
    if args.screen:
        window.screen_action.setChecked(True)
    if args.screenshot:
        def shoot():
            window.grab().save(args.screenshot)
            window.close()
        QTimer.singleShot(args.delay * 1000, shoot)
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
