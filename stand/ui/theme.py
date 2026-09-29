"""Тёмная тема приложения: цвета и таблица стилей Qt."""
import os

ASSETS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets").replace("\\", "/")

BG = "#0e1319"
PANEL = "#161d26"
PANEL2 = "#1d2733"
BORDER = "#283340"
FIELD_BORDER = "#627186"
TEXT = "#e6edf3"
MUTED = "#8a97a6"
ACCENT = "#3b82f6"
ACCENT_DARK = "#2563eb"
ACCENT_DARKER = "#1d4ed8"
GREEN = "#22c55e"
GREEN_BG = "#14301f"
RED = "#ef4444"
RED_BG = "#3a1a1c"
RED_TEXT = "#f87171"
AMBER = "#f59e0b"
AMBER_BG = "#3a2d12"

QSS = """
QMainWindow, QDialog { background: %(bg)s; }
/* окно целиком лежит в прокручиваемой области: ей и её холсту нужен тот же фон,
   иначе вокруг содержимого лезет светлая системная палитра */
QScrollArea#windowScroll, QScrollArea#windowScroll > QWidget > QWidget { background: %(bg)s; }
QScrollArea#windowScroll { border: none; }
QWidget { color: %(text)s; font-family: 'Segoe UI', 'Inter', sans-serif; font-size: 10pt; }
QFrame#card { background: %(panel)s; border: 1px solid %(border)s; border-radius: 12px; }
QLabel#cardTitle { font-size: 11pt; font-weight: 600; color: %(text)s; }
QLabel#muted { color: %(muted)s; }
QLabel#small { color: %(muted)s; font-size: 9pt; }
QLabel#big { font-size: 15pt; font-weight: 600; }
QLabel#chip { background: %(panel2)s; border: 1px solid %(border)s; border-radius: 10px; padding: 4px 10px; }
QLabel#chipGreen { background: %(green_bg)s; border: 1px solid %(green)s; color: %(green)s;
                   border-radius: 10px; padding: 4px 10px; font-weight: 600; }
QLabel#chipRed { background: %(red_bg)s; border: 1px solid %(red)s; color: %(red_text)s;
                 border-radius: 10px; padding: 4px 10px; font-weight: 600; }
QLabel#chipAmber { background: %(amber_bg)s; border: 1px solid %(amber)s; color: %(amber)s;
                   border-radius: 10px; padding: 4px 10px; font-weight: 600; }
QLabel#chipBlue { background: #172a4a; border: 1px solid %(accent)s; color: #93c5fd;
                  border-radius: 10px; padding: 4px 10px; font-weight: 600; }

QPushButton { background: %(panel2)s; border: 1px solid %(border)s; border-radius: 8px;
              padding: 6px 14px; color: %(text)s; }
QPushButton:hover { background: #243040; border-color: #35424f; }
QPushButton:pressed { background: #141b23; }
QPushButton:disabled { color: #5b6772; background: %(panel)s; border-color: %(border)s; }
QPushButton#primary { background: %(accent_dark)s; border-color: %(accent_dark)s; color: white; font-weight: 600;
                      padding: 8px 20px; }
QPushButton#primary:hover { background: %(accent_darker)s; border-color: %(accent_darker)s; }
QPushButton#primary:disabled { background: #24344d; border-color: #24344d; color: #6b7c94; }
QPushButton#danger { background: %(red_bg)s; border-color: %(red)s; color: %(red_text)s; font-weight: 600; }
QPushButton#danger:hover { background: #4a2124; }
QPushButton#flat { background: transparent; border: none; color: %(muted)s; padding: 4px 8px; }
QPushButton#flat:hover { color: %(text)s; background: %(panel2)s; }
QPushButton#link { background: transparent; border: none; color: #93c5fd; padding: 2px 6px; }
QPushButton#link:hover { color: white; text-decoration: underline; }

QLineEdit, QComboBox, QSpinBox { background: %(bg)s; border: 1px solid %(field_border)s; border-radius: 8px;
                                 padding: 6px 10px; color: %(text)s; selection-background-color: %(accent_dark)s; }
QLineEdit:focus, QComboBox:focus, QSpinBox:focus { border-color: %(accent)s; }
QComboBox::drop-down { border: none; width: 24px; }
QComboBox::down-arrow { image: url(%(assets)s/arrow.svg); width: 10px; height: 6px; margin-right: 8px; }
QSpinBox { padding-right: 24px; }
QSpinBox::up-button, QSpinBox::down-button { subcontrol-origin: border; width: 22px; border: none;
                                             background: transparent; }
QSpinBox::up-button { subcontrol-position: top right; margin-top: 3px; }
QSpinBox::down-button { subcontrol-position: bottom right; margin-bottom: 3px; }
QSpinBox::up-button:hover, QSpinBox::down-button:hover { background: %(panel2)s; border-radius: 4px; }
QSpinBox::up-arrow { image: url(%(assets)s/arrow_up.svg); width: 10px; height: 6px; }
QSpinBox::down-arrow { image: url(%(assets)s/arrow.svg); width: 10px; height: 6px; }
QComboBox QAbstractItemView { background: %(panel2)s; border: 1px solid %(border)s;
                              selection-background-color: %(accent_dark)s; outline: none; }

QCheckBox { spacing: 8px; }
QCheckBox::indicator { width: 16px; height: 16px; border: 1px solid %(field_border)s; border-radius: 4px;
                       background: %(bg)s; }
QCheckBox::indicator:checked { background: %(accent_dark)s; border-color: %(accent_dark)s;
                               image: url(%(assets)s/check.svg); }
QCheckBox::indicator:hover { border-color: %(accent)s; }

QProgressBar { background: %(bg)s; border: 1px solid %(border)s; border-radius: 5px; height: 10px;
               text-align: center; color: transparent; }
QProgressBar::chunk { background: %(accent)s; border-radius: 4px; }
QProgressBar#battery::chunk { background: %(green)s; }
QProgressBar#batteryLow::chunk { background: %(amber)s; }

QTableWidget { background: %(panel)s; border: 1px solid %(border)s; border-radius: 12px;
               gridline-color: %(border)s; selection-background-color: #24344d; outline: none; }
QTableWidget::item { padding: 6px 10px; border-bottom: 1px solid #1f2933; }
QTableView { background: %(panel)s; }
QHeaderView { background: %(panel)s; border: none; }
QHeaderView::section { background: %(panel2)s; color: %(muted)s; padding: 8px 10px; border: none;
                       border-bottom: 1px solid %(border)s; border-right: 1px solid %(border)s;
                       font-weight: 600; }
QTableWidget#totals { border-top: 2px solid %(border)s; border-top-left-radius: 0; border-top-right-radius: 0;
                      background: %(panel2)s; }
QTableWidget#totals::item { border-bottom: none; }
QTableCornerButton::section { background: %(panel2)s; border: none; }

QPlainTextEdit, QTextEdit { background: #0b1015; border: 1px solid %(border)s; border-radius: 10px;
                 color: #aab6c3; font-family: Consolas, 'Cascadia Mono', monospace; font-size: 9pt;
                 padding: 6px; }
QStatusBar { background: %(panel)s; border-top: 1px solid %(border)s; color: %(muted)s; }
QMenuBar { background: %(bg)s; }
QMenuBar::item:selected { background: %(panel2)s; border-radius: 6px; }
QMenu { background: %(panel2)s; border: 1px solid %(border)s; padding: 4px; }
QMenu::item { padding: 6px 20px; border-radius: 6px; }
QMenu::item:selected { background: %(accent_dark)s; color: white; }
QScrollBar:vertical { background: transparent; width: 18px; margin: 2px; }
QScrollBar::handle:vertical { background: %(amber)s; border-radius: 7px; min-height: 44px; }
QScrollBar::handle:vertical:hover { background: #fbbf24; }
QScrollBar::add-line, QScrollBar::sub-line { height: 0; width: 0; }
QScrollBar::add-page, QScrollBar::sub-page { background: transparent; }
QScrollBar:horizontal { background: transparent; height: 18px; margin: 2px; }
QScrollBar::handle:horizontal { background: %(amber)s; border-radius: 7px; min-width: 44px; }
QScrollBar::handle:horizontal:hover { background: #fbbf24; }
QTabWidget::pane { border: 1px solid %(border)s; border-radius: 10px; top: -1px; }
QTabBar::tab { background: %(panel)s; color: %(muted)s; border: 1px solid %(border)s; border-bottom: none;
               padding: 7px 16px; margin-right: 4px; border-top-left-radius: 8px; border-top-right-radius: 8px; }
QTabBar::tab:selected { background: %(panel2)s; color: %(text)s; }
QTabBar::tab:hover { color: %(text)s; }
QToolTip { background: %(panel2)s; color: %(text)s; border: 1px solid %(border)s; padding: 4px; }
QSplitter::handle { background: transparent; }
""" % {"bg": BG, "panel": PANEL, "panel2": PANEL2, "border": BORDER, "text": TEXT, "muted": MUTED,
       "accent": ACCENT, "accent_dark": ACCENT_DARK, "accent_darker": ACCENT_DARKER,
       "field_border": FIELD_BORDER, "red_text": RED_TEXT, "green": GREEN, "green_bg": GREEN_BG,
       "red": RED, "red_bg": RED_BG, "amber": AMBER, "amber_bg": AMBER_BG, "assets": ASSETS}
