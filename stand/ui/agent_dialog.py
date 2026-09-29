"""Карточка агента: что за телефон, где, какими сетями пользовался, история проверок, сайты."""
import json
import time
from collections import Counter

import shiboken6
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QDialogButtonBox,
    QGridLayout,
    QHBoxLayout,
    QInputDialog,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from .. import places
from ..i18n import t
from . import theme
from .widgets import Card, chip, muted, network_name, plain_label, plain_tip
from .workers import run_task

ONLINE_HOURS = 3
STALE_HOURS = 12
ABANDONED_DAYS = 7


def ago(ts):
    """Сколько прошло: «12 мин», «3 ч», «2 дн»."""
    if not ts:
        return t("никогда")
    delta = time.time() - ts
    if delta < 90:
        return t("только что")
    if delta < 3600:
        return t("%d мин") % (delta // 60)
    if delta < 86400:
        return t("%d ч") % (delta // 3600)
    return t("%d дн") % (delta // 86400)


def ago_long(ts):
    """Когда был на связи: «12 мин назад», «3 ч назад»."""
    if not ts:
        return t("никогда")
    delta = time.time() - ts
    if delta < 90:
        return t("только что")
    if delta < 3600:
        return t("%d мин назад") % (delta // 60)
    if delta < 86400:
        return t("%d ч назад") % (delta // 3600)
    return t("%d дн назад") % (delta // 86400)


def _when(ts):
    return time.strftime("%d.%m %H:%M", time.localtime(ts)) if ts else "-"


def report_doubt(report):
    """Почему отчёту нельзя верить, или "". Сервер отдаёт trusted/partial; старый сервер - смотрим payload."""
    payload = report.get("payload") or {}
    reasons = []
    if str(report.get("operator") or "").startswith("VPN") or report.get("network") == "vpn":
        reasons.append(t("отчёт сделан с включённым VPN"))
    direct_ok = report.get("direct_ok", payload.get("direct_ok"))
    if direct_ok is False:
        reasons.append(t("в этой сети нет обычного интернета (белые списки?) - «0 из N» не значит, что узлы мертвы"))
    elif report.get("core_direct_ok", payload.get("core_direct_ok")) is False:
        reasons.append(t("ядро xray не вышло в интернет через эту сеть, хотя обычный запрос прошёл - "
                         "узлы не проверены"))
    if report.get("same_ip_as") or payload.get("same_ip_as"):
        reasons.append(t("IP тот же, что у Wi-Fi - результат мог пройти не через эту сеть"))
    if report.get("route_mismatch") or payload.get("route_mismatch"):
        reasons.append(t("результат мог пройти не через эту сеть, а через другую (например, Wi-Fi)"))
    if (report.get("bind") or payload.get("bind")) == "ip":
        reasons.append(t("маршрут под сомнением: ядро держалось сети только по адресу, без привязки к интерфейсу"))
    if "trusted" in report and report["trusted"] is not None and not report["trusted"] and not reasons:
        reasons.append(t("сервер пометил отчёт как ненадёжный"))
    if report.get("partial") or payload.get("partial"):
        reasons.append(t("проверены не все узлы - проверка прервалась"))
    deferred = payload.get("deferred_s")
    if report.get("deferred") or (isinstance(deferred, (int, float)) and deferred > 600):
        reasons.append(t("отчёт отправлен с опозданием - сеть и место могут быть уже другими"))
    return "\n".join(reasons)


def unchecked_reason(code):
    """Почему агент не проверил узел: код из unchecked_nodes или error непроверенного результата."""
    code = str(code or "")
    if code == "unsupported":
        return t("приложение не поддерживает настройки этого узла")
    if code == "core-direct":
        return t("ядро xray не вышло в интернет через эту сеть")
    if code == "vpn":
        return t("на телефоне включён VPN")
    if code.startswith("core-exit"):
        exit_code = code.partition(":")[2]
        if exit_code:
            return t("ядро xray упало на этом узле (код %s)") % exit_code
        return t("ядро xray упало на этом узле")
    return t("агент отказался: адрес узла ведёт в частную сеть или настройки небезопасны")


def dead_reason(code):
    """Почему узел мёртв, если агент знает причину: dns-sinkhole / dns-fail; иначе ""."""
    if code == "dns-sinkhole":
        return t("DNS сети подменил адрес")
    if code == "dns-fail":
        return t("DNS сети не нашёл имя")
    return ""


def dead_reasons(report):
    """{узел: причина словами} мёртвых узлов отчёта: поле dead_reasons сервера или error результата."""
    listed = report.get("dead_reasons")
    if not isinstance(listed, dict):
        results = (report.get("payload") or {}).get("results")
        listed = {key: value.get("error") for key, value in (results.items() if isinstance(results, dict) else ())
                  if isinstance(value, dict) and not value.get("ok")}
    found = {str(key): dead_reason(code) for key, code in listed.items()}
    return {key: text for key, text in found.items() if text}


def unchecked_nodes(payload):
    """{ключ: причина} непроверенных узлов отчёта: поле unchecked_nodes (агент 0.12+) или помеченные
    unchecked результаты."""
    found = {}
    results = payload.get("results") if isinstance(payload.get("results"), dict) else {}
    for key, value in results.items():
        if isinstance(value, dict) and value.get("unchecked"):
            found[key] = unchecked_reason(value.get("error"))
    listed = payload.get("unchecked_nodes")
    if isinstance(listed, dict):
        found.update({str(key): unchecked_reason(code) for key, code in listed.items()})
    return found


def version_tuple(version):
    """«0.10.2» → (0, 10, 2): строками «0.10» < «0.6», а числами - нет."""
    parts = []
    for piece in str(version).split("."):
        digits = "".join(ch for ch in piece if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


class AgentDialog(QDialog):
    def __init__(self, agent, reports, parent=None, api=None):
        super().__init__(parent)
        self.agent = agent
        self.api = api
        self.reports = reports
        self.tasks = []
        self._owner = parent if hasattr(parent, "tasks") else self
        self._results_seen = set()
        self._polling = False
        self.setWindowTitle(t("Агент %s") % agent["agent_id"][:8])
        self.resize(900, 640)
        root = QVBoxLayout(self)
        root.setSpacing(10)
        root.addWidget(self._build_head(agent, reports))
        root.addLayout(self._build_networks(reports))
        root.addWidget(self._build_reports_table(reports), 1)
        root.addLayout(self._build_actions())
        self._build_commands(root)

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.button(QDialogButtonBox.Close).setText(t("Закрыть"))
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)
        self.finished.connect(self._results_timer.stop)
        self.finished.connect(self.deleteLater)


    def _build_head(self, agent, reports):
        """Шапка: модель и статус связи, что мешает работать, основные факты об агенте."""
        head = Card()
        title_row = QHBoxLayout()
        title = plain_label("%s · Android %s" % (agent.get("model") or t("телефон"), agent.get("android") or "?"))
        title.setObjectName("big")
        title_row.addWidget(title)
        silence = time.time() - (agent.get("last_seen") or 0)
        seen = ago_long(agent.get("last_seen"))
        if agent.get("online"):
            title_row.addWidget(chip(t("● онлайн сейчас"), "chipGreen"))
        elif silence < ONLINE_HOURS * 3600:
            title_row.addWidget(chip(t("● на связи, был %s") % seen, "chipGreen"))
        elif silence < STALE_HOURS * 3600:
            title_row.addWidget(chip(t("● был недавно (%s)") % seen, "chip"))
        elif silence < ABANDONED_DAYS * 86400:
            title_row.addWidget(chip(t("● молчит, был %s") % seen, "chipAmber"))
        else:
            title_row.addWidget(chip(t("● не выходит, был %s") % seen, "chipRed"))
        title_row.addStretch()
        head.body.addLayout(title_row)

        problems = self._problems(agent, reports, silence)
        if problems:
            box = plain_label("⚠ " + "\n⚠ ".join(problems))
            box.setWordWrap(True)
            box.setStyleSheet("background:%s; border:1px solid %s; border-radius:8px; padding:8px; color:%s;"
                              % (theme.AMBER_BG, theme.AMBER, theme.AMBER))
            head.body.addWidget(box)
        head.body.addLayout(self._build_facts(agent))
        return head

    @staticmethod
    def _problems(agent, reports, silence):
        """Что мешает агенту работать - прямым текстом, чтобы не гадать по таблице."""
        problems = []
        vpn_reports = [report for report in reports if str(report.get("operator") or "").startswith("VPN")]
        if silence > 6 * 3600:
            problems.append(t("нет отчётов %s - телефон усыпил приложение (батарея/автозапуск) или нет сети")
                            % ago(agent.get("last_seen")))
        if reports and len(vpn_reports) == len(reports):
            problems.append(
                t("все отчёты сделаны с включённым VPN - проверка узлов через чужой туннель ничего не значит"))
        if not any(report["total"] for report in reports):
            problems.append(t("ни одной успешной проверки узлов"))
        return problems

    @staticmethod
    def _build_facts(agent):
        """Сетка «название - значение»: версия, место, IP, сеть, когда был, push."""
        grid = QGridLayout()
        grid.setHorizontalSpacing(18)
        place = places.describe(agent) or t("неизвестно")
        coords = " · %.2f, %.2f" % (agent["lat"], agent["lon"]) if agent.get("lat") is not None else ""
        facts = [
            (t("Агент"), agent["agent_id"]),
            (t("Версия"), t("%s · ядро xray %s") % (agent.get("app_version") or "?", agent.get("core_version") or "?")),
            (t("Где"), place + coords),
            (t("Последний IP"), "%s · %s" % (agent.get("ip") or "-", agent.get("org") or "")),
            (t("Последняя сеть"), "%s · %s" % (network_name(agent.get("network")) or "-", agent.get("operator") or "")),
            (t("Впервые / последний раз"), "%s / %s" % (_when(agent.get("first_seen")), _when(agent.get("last_seen")))),
            (t("Push"),
             (t("токен есть; доходит по Wi-Fi, на мобильных сетях Google недоступен - там опрос раз в 15 мин")
              if agent.get("push") else t("нет - ждёт опроса раз в 15 мин"))),
        ]
        for row, (name, value) in enumerate(facts):
            grid.addWidget(muted(name), row, 0, alignment=Qt.AlignTop)
            label = plain_label(value)
            label.setWordWrap(True)
            label.setTextInteractionFlags(Qt.TextSelectableByMouse)
            grid.addWidget(label, row, 1)
        grid.setColumnStretch(1, 1)
        return grid

    @staticmethod
    def _build_networks(reports):
        """Операторы и сети, которые встречались в отчётах, - плашками."""
        seen = Counter()
        sims = Counter()
        for report in reports:
            network = report["payload"].get("network") or {}
            seen[(report.get("network") or network.get("type") or "?",
                  report.get("operator") or network.get("operator") or "")] += 1
            if network.get("sim_operator"):
                sims[network["sim_operator"]] += 1
        chips = QHBoxLayout()
        chips.addWidget(muted(t("Сети в отчётах:")))
        for (net_type, operator), count in seen.most_common():
            kind = "chipAmber" if str(operator).startswith("VPN") else "chipBlue" if net_type == "wifi" else "chipGreen"
            chips.addWidget(chip("%s · %s × %d" % (network_name(net_type), operator or "?", count), kind))
        for sim, _count in sims.most_common(3):
            chips.addWidget(chip("SIM: %s" % sim, "chip"))
        chips.addStretch()
        return chips

    @staticmethod
    def _build_reports_table(reports):
        """История отчётов: когда, какая сеть, сколько узлов и сайтов живо; ненадёжные отчёты - серым с причиной."""
        table = QTableWidget(len(reports), 7)
        table.setHorizontalHeaderLabels([t("Когда"), t("Сеть"), t("Оператор"), t("Регион"), t("Узлы"), t("Сайты"),
                                         t("Длительность")])
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setShowGrid(False)
        table.horizontalHeader().setStretchLastSection(True)
        for row, report in enumerate(reports):
            payload = report["payload"]
            sites = payload.get("sites") or {}
            sites_ok = sum(1 for value in sites.values() if value.get("ok"))
            doubt = report_doubt(report)
            alive, total = report["alive"], report["total"]
            skipped = unchecked_nodes(payload)
            nodes_text = t("%d из %d") % (alive, total) if total else "-"
            if skipped:
                nodes_text += t(" · не проверено %d") % len(skipped)
            values = [_when(report["ts"]), network_name(report.get("network")), report.get("operator") or "",
                      places.describe(report), nodes_text,
                      t("%d из %d") % (sites_ok, len(sites)) if sites else "-",
                      t("%s с") % payload.get("duration_s") if payload.get("duration_s") is not None else ""]
            for col, text in enumerate(values):
                item = QTableWidgetItem(text)
                if col == 4 and total:
                    item.setForeground(QColor(theme.MUTED if doubt else theme.GREEN if alive == total
                                              else theme.RED if alive == 0 else theme.AMBER))
                    font = QFont()
                    font.setBold(True)
                    item.setFont(font)
                if doubt:
                    item.setForeground(QColor(theme.MUTED))
                    item.setToolTip(plain_tip(t("ненадёжный отчёт: %s") % doubt))
                if col == 4:
                    why = dead_reasons(report)
                    lines = "\n".join("%s %s%s" % ("●" if value.get("ok") else "✕", key,
                                                   " - " + why[key] if key in why and not value.get("ok") else "")
                                      for key, value in (payload.get("results") or {}).items()
                                      if isinstance(value, dict) and key not in skipped)
                    if skipped:
                        lines += "\n\n" + t("не проверены:") + "\n" + "\n".join(
                            "⊘ %s - %s" % (key, reason) for key, reason in sorted(skipped.items()))
                    item.setToolTip(plain_tip((t("ненадёжный отчёт: %s") % doubt + "\n\n" if doubt else "") + lines))
                if col == 5:
                    item.setToolTip(plain_tip("\n".join("%s %s %s" % ("●" if value.get("ok") else "✕", url,
                                                                      value.get("error") or "")
                                                        for url, value in sites.items())))
                table.setItem(row, col, item)
        table.resizeColumnsToContents()
        return table

    def _build_actions(self):
        """Кнопки-просьбы к телефону: проверить, обновиться, прислать точку, сообщение, выключить VPN."""
        actions = QHBoxLayout()
        self.run_button = QPushButton(t("▶ Проверить сейчас"))
        self.run_button.setToolTip(
            t("телефон запустит проверку узлов вне расписания на ближайшем пинге (до 15 мин), по Wi-Fi - сразу"))
        self.run_button.clicked.connect(self._run_now)
        actions.addWidget(self.run_button)
        self.update_button = QPushButton(t("⬆ Обновить приложение"))
        self.update_button.setToolTip(
            t("только этому телефону: заберёт свежий APK по ближайшему пингу и предложит установку"))
        self.update_button.clicked.connect(self._update_now)
        actions.addWidget(self.update_button)
        self.locate_button = QPushButton(t("📍 Уточнить местоположение (GPS, разово)"))
        self.locate_button.setToolTip(
            t("телефон включит GPS на один замер и пришлёт точку; если нет разрешения - попросит открыть приложение"))
        self.locate_button.clicked.connect(self._locate)
        actions.addWidget(self.locate_button)
        self.message_button = QPushButton(t("✉ Сообщение"))
        self.message_button.setToolTip(t("мгновенно показать текст на экране телефона через резервный канал"))
        self.message_button.clicked.connect(self._message)
        actions.addWidget(self.message_button)
        self.vpn_button = QPushButton(t("🚫 Попросить выключить VPN"))
        self.vpn_button.setToolTip(t("телефон покажет просьбу отключить VPN - под ним проверка узлов не идёт"))
        self.vpn_button.clicked.connect(self._ask_vpn_off)
        actions.addWidget(self.vpn_button)
        self.status_line = muted("")
        actions.addWidget(self.status_line)
        actions.addStretch()
        return actions

    def _build_commands(self, root):
        """Команды с результатом: телефон выполняет и присылает ответ, он появляется в панели ниже."""
        commands = QHBoxLayout()
        commands.addWidget(muted(t("Команды с ответом:")))
        for text, tip, handler in (
            (t("🌐 Проверить сайт…"),
             t("открыть указанный адрес без VPN из сети телефона - доступен или заблокирован"), self._cmd_site),
            (t("🩺 Диагностика"),
             t("заряд, сеть, сигнал, не душит ли система приложение, последние ошибки"), self._cmd_diag),
            (t("📜 Лог xray узла…"),
             t("поднять ядро по мёртвому узлу и прислать, почему не прошло рукопожатие"), self._cmd_xray_log),
            (t("⚡ Скорость узла…"), t("реальная скорость через узел из сети телефона, Мбит/с"), self._cmd_speed),
            (t("🧱 Проверить заглушку белых списков"),
             t("что показывает оператор вместо сайта в режиме белых списков"), self._cmd_banner),
        ):
            button = QPushButton(text)
            button.setToolTip(tip)
            button.clicked.connect(handler)
            commands.addWidget(button)
        commands.addStretch()
        root.addLayout(commands)
        self.results_view = QPlainTextEdit()
        self.results_view.setReadOnly(True)
        self.results_view.setPlaceholderText(t("ответы телефона на команды появятся здесь (обновляется каждые 5 с)"))
        self.results_view.setMaximumHeight(170)
        root.addWidget(self.results_view)
        self._results_timer = QTimer(self)
        self._results_timer.setInterval(5000)
        self._results_timer.timeout.connect(self._poll_results)
        if self.api:
            self._results_timer.start()
            self._poll_results()

    def _alive(self):
        return shiboken6.isValid(self) and shiboken6.isValid(self.status_line)

    def _ask(self, call, describe, button=None):
        """Просьба к телефону через сервер фоном: ответ сервера → строка статуса, ошибка → «✖ …»."""
        if not self.api:
            return
        if button:
            button.setEnabled(False)

        def finish(text):
            if not self._alive():
                return
            self.status_line.setText(text)
            if button:
                button.setEnabled(True)
        run_task(self._owner, call, lambda answer: finish(describe(answer)), lambda error: finish("✖ %s" % error))

    @staticmethod
    def _pushed(answer):
        return t("да") if answer.get("pushed") else t("нет, ждём пинга")

    def _run_now(self):
        self._ask(lambda: self.api.run_now(self.agent["agent_id"]),
                  lambda answer: t("проверка заказана (push: %s), пойдёт по ближайшему пингу") % self._pushed(answer),
                  self.run_button)

    def _update_now(self):
        self._ask(lambda: self.api.update_now(self.agent["agent_id"]),
                  lambda answer: t("обновление заказано (push: %s), телефон предложит установку")
                  % self._pushed(answer),
                  self.update_button)

    def _message(self):
        if not self.api:
            return
        text, ok = QInputDialog.getText(self, t("Сообщение агенту"), t("Текст покажется на экране телефона:"))
        if not ok or not text.strip():
            return
        self._ask(lambda: self.api.message(self.agent["agent_id"], text.strip()),
                  lambda answer: t("отправлено %s") % (t("сейчас (канал открыт)") if answer.get("online")
                                                       else t("- дойдёт, когда телефон откроет канал")))

    def _ask_vpn_off(self):
        self._ask(lambda: self.api.message(self.agent["agent_id"], vpn_off=True),
                  lambda answer: t("просьба выключить VPN отправлена %s")
                  % (t("(канал открыт)") if answer.get("online") else t("- дойдёт по открытию канала")))


    def _node_keys(self):
        """Ключи узлов из последнего отчёта телефона - чтобы выбрать, какой узел логировать/мерить."""
        for report in self.reports:
            results = (report.get("payload") or {}).get("results") or {}
            if results:
                return sorted(results.keys())
        return []

    def _send_cmd(self, action, text="", label=""):
        self._ask(lambda: self.api.command(self.agent["agent_id"], action, text),
                  lambda answer: t("%s: отправлено %s - ответ появится ниже") % (
                      label or action, t("сразу (канал открыт)") if answer.get("online") else t("по открытию канала")))

    def _cmd_site(self):
        url, ok = QInputDialog.getText(self, t("Проверить сайт"), t("Адрес (https://…) - телефон откроет его без VPN:"))
        if ok and url.strip():
            self._send_cmd("site_check", url.strip(), t("сайт"))

    def _cmd_diag(self):
        self._send_cmd("diag", label=t("диагностика"))

    def _pick_node(self, title):
        keys = self._node_keys()
        if not keys:
            self.status_line.setText(t("нет отчётов с узлами - сначала пусть телефон проверится"))
            return None
        key, ok = QInputDialog.getItem(self, title, t("Узел:"), keys, 0, False)
        return key if ok and key else None

    def _cmd_xray_log(self):
        key = self._pick_node(t("Лог xray узла"))
        if key:
            self._send_cmd("xray_log", key, t("лог xray"))

    def _cmd_speed(self):
        key = self._pick_node(t("Скорость через узел"))
        if key:
            self._send_cmd("speed", key, t("скорость"))

    def _cmd_banner(self):
        self._send_cmd("whitelist_banner", label=t("баннер"))

    def _poll_results(self):
        if not self.api or self._polling:
            return
        self._polling = True
        agent_id = self.agent["agent_id"]
        run_task(self._owner, lambda: self.api.results(agent_id, limit=20), self._show_results, self._poll_failed)

    def _poll_failed(self, _error):
        self._polling = False

    def _show_results(self, items):
        self._polling = False
        if not self._alive():
            return
        fresh = [item for item in reversed(items) if item["id"] not in self._results_seen]
        for item in fresh:
            self._results_seen.add(item["id"])
            self.results_view.appendPlainText(self._render_result(item))

    @staticmethod
    def _render_result(item):
        when = time.strftime("%H:%M:%S", time.localtime(item.get("ts") or 0))
        r = item.get("result") or {}
        action = item.get("action")
        network = r.get("network") or {}
        net_s = ("%s · %s" % (network.get("type", ""), network.get("operator", ""))).strip(" ·") if network else ""
        if r.get("error") and action not in ("whitelist_banner", "site_check"):
            return t("[%s] %s - ошибка: %s") % (when, action, r["error"])
        if action == "site_check":
            status = t("открылся, HTTP %s за %s мс") % (r.get("code"), r.get("ms")) if r.get("ok") \
                else t("НЕ открылся: %s") % (r.get("error") or ("HTTP %s" % r.get("code")))
            return t("[%s] сайт %s (%s): %s") % (when, r.get("url"), net_s, status)
        if action == "diag":
            flags = []
            if r.get("background_restricted"):
                flags.append(t("⚠ фон ограничен системой"))
            if r.get("ignores_battery_optimizations") is False:
                flags.append(t("⚠ нет исключения из экономии батареи"))
            if r.get("power_save_mode"):
                flags.append(t("режим энергосбережения"))
            errors = r.get("recent_errors") or []
            return (t("[%s] диагностика: батарея %s%%%s · сигнал %s/4 · %s · сетей с интернетом %s · v%s · "
                      "последняя проверка «%s»%s%s") % (
                        when, r.get("battery_pct"), t(" (заряжается)") if r.get("charging") else "",
                        r.get("signal_level", "?"), net_s or t("сеть ?"), r.get("usable_networks", "?"),
                        r.get("app_version"), r.get("last_summary", ""),
                        (" · " + ", ".join(flags)) if flags else "",
                        (t(" · ошибок в логе: %d") % len(errors)) if errors else ""))
        node = r.get("location") or r.get("node")
        if action == "xray_log":
            return t("[%s] лог xray узла %s (%s):\n%s") % (when, node, net_s, r.get("log", ""))
        if action == "speed":
            if r.get("ok"):
                return t("[%s] скорость через %s (%s): %s Мбит/с (%s КБ за %s мс)") % (
                    when, node, net_s, r.get("mbps"), (r.get("bytes") or 0) // 1024, r.get("ms"))
            return t("[%s] скорость через %s: не удалось - %s") % (when, node, r.get("error"))
        if action == "whitelist_banner":
            if r.get("error"):
                return t("[%s] баннер: страница не открылась - %s (сеть режет даже HTTP)") % (when, r["error"])
            verdict = (t("похоже на заглушку оператора") if r.get("looks_like_banner")
                       else t("обычная страница, заглушки нет"))
            where = (" → " + r["location"]) if r.get("location") else ""
            return t("[%s] баннер (%s%s): %s · «%s» · %s") % (
                when, r.get("status") or ("HTTP %s" % r.get("code")), where, verdict,
                r.get("title", ""), (r.get("snippet") or "")[:300])
        return "[%s] %s: %s" % (when, action, json.dumps(r, ensure_ascii=False)[:600])

    def _locate(self):
        self._ask(lambda: self.api.locate(self.agent["agent_id"]),
                  lambda answer: t("телефон получил запрос (push: %s), точка придёт через минуту")
                  % self._pushed(answer),
                  self.locate_button)
