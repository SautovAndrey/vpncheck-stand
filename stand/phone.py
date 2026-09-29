"""Состояние телефона через ADB: батарея, SIM, сигнал, Wi-Fi, режим полёта - и управление ими.

Разбор вывода вынесен в чистые функции (покрыты тестами), сами вызовы adb - в PhoneControl.
"""
import re
import time
from dataclasses import dataclass, field

from .adb import AdbError
from .i18n import t


@dataclass
class Sim:
    sub_id: int
    slot: int
    name: str = ""
    carrier: str = ""
    network: str = ""
    signal: int = -1
    is_data: bool = False


@dataclass
class PhoneState:
    connected: bool = False
    serial: str = ""
    state: str = ""
    model: str = ""
    android: str = ""
    battery: int = -1
    charging: bool = False
    sims: list = field(default_factory=list)
    data_sub_id: int = -1
    wifi_on: bool = False
    wifi_ssid: str = ""
    mobile_data_on: bool = True
    airplane: bool = False
    transport: str = ""
    error: str = ""

    def data_sim(self):
        for sim in self.sims:
            if sim.is_data:
                return sim
        return None


def parse_battery(text):
    level = re.search(r"level:\s*(\d+)", text)
    status = re.search(r"status:\s*(\d+)", text)
    charging = bool(status and status.group(1) in ("2", "5"))
    if not charging:
        charging = bool(re.search(r"(AC|USB|Wireless) powered:\s*true", text))
    return (int(level.group(1)) if level else -1), charging


def parse_siminfo_content(text):
    """`content query --uri content://telephony/siminfo`:
    Row: 0 _id=1, sim_id=0, display_name=MegaFon, carrier_name=MegaFon, ..."""
    sims = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("Row:"):
            continue
        body = line.split(" ", 2)[2] if line.count(" ") >= 2 else ""
        fields = dict(re.findall(r"(\w+)=([^,]*)", body))
        try:
            sub_id = int(fields.get("_id", "-1"))
            slot = int(fields.get("sim_id", "-1"))
        except ValueError:
            continue
        if slot < 0:
            continue
        sims.append(Sim(sub_id=sub_id, slot=slot,
                        name=fields.get("display_name", "").strip(),
                        carrier=fields.get("carrier_name", "").strip()))
    sims.sort(key=lambda s: s.slot)
    return sims


def parse_isub(text):
    """`dumpsys isub` - запасной источник списка SIM и активной SIM для данных."""
    sims = []
    seen = set()
    for match in re.finditer(r"SubscriptionInfo(?:Internal)?[:{]\s*(id=\d+.*?)(?:\]\s*$|\}|$)", text, re.M):
        body = match.group(1)
        sub = re.search(r"\bid=(\d+)", body)
        slot = re.search(r"simSlotIndex=(-?\d+)", body)
        if not sub or not slot or int(slot.group(1)) < 0:
            continue
        sub_id = int(sub.group(1))
        if sub_id in seen:
            continue
        seen.add(sub_id)
        name = re.search(r"displayName=(.*?)\s+(?:carrierName|displayNameSource|nameSource)=", body)
        carrier = re.search(r"carrierName=(.*?)\s+\w+=", body)
        sims.append(Sim(sub_id=sub_id, slot=int(slot.group(1)),
                        name=(name.group(1) if name else "").strip(),
                        carrier=(carrier.group(1) if carrier else "").strip()))
    sims.sort(key=lambda s: s.slot)
    data = re.search(r"[dD]efaultDataSubId=(-?\d+)", text)
    return sims, (int(data.group(1)) if data else -1)


def parse_signal_levels(text):
    """`dumpsys telephony.registry`: уровень сигнала (0..4) по каждому Phone Id."""
    levels = {}
    chunks = re.split(r"Phone Id=(\d+)", text)
    if len(chunks) < 3:
        found = re.findall(r"level=(\d)", text)
        return {0: int(found[0])} if found else {}
    for i in range(1, len(chunks) - 1, 2):
        phone_id = int(chunks[i])
        body = chunks[i + 1]
        primary = re.search(r"primary=Cell\w+:.*?level=(\d)", body, re.S)
        if primary:
            levels[phone_id] = int(primary.group(1))
        else:
            found = re.findall(r"mSignalStrength=.*?level=(\d)", body, re.S)
            if found:
                levels[phone_id] = int(found[0])
    return levels


def parse_getprop_list(text):
    return [item.strip() for item in text.strip().split(",")]


def parse_wifi_status(text):
    """`cmd wifi status`: Wifi is enabled / Wifi is connected to "SSID"."""
    enabled = "Wifi is enabled" in text
    ssid = re.search(r'connected to "([^"]*)"', text)
    return enabled, (ssid.group(1) if ssid else "")


def parse_active_sub(text):
    """`dumpsys connectivity`: subId SIM-карты, через которую сейчас идёт интернет; -1 если Wi-Fi/нет сети."""
    active = re.search(r"Active default network:\s*(\d+)", text)
    if not active:
        return -1
    marker = "NetworkAgentInfo{network{%s}" % active.group(1)
    for line in text.splitlines():
        if marker in line.replace(" ", ""):
            sub = re.search(r"mSubId = (\d+)", line)
            return int(sub.group(1)) if sub else -1
    return -1


def parse_transport(text):
    """`dumpsys connectivity`: какой сетью телефон пользуется прямо сейчас."""
    active = re.search(r"Active default network:\s*(\d+)", text)
    if active:
        net_id = active.group(1)
        block = re.search(r"network\{%s\}.*?Transports:\s*([A-Z_|]+)" % net_id, text, re.S)
        if block:
            return "wifi" if "WIFI" in block.group(1) else "cellular"
    if re.search(r"Active default network:\s*none", text):
        return "none"
    return ""


UI_NODE = re.compile(r'<node[^>]*?text="([^"]*)"[^>]*?resource-id="([^"]*)"[^>]*?class="([^"]*)"'
                     r'[^>]*?content-desc="([^"]*)"[^>]*?checkable="(\w+)"[^>]*?checked="(\w+)"'
                     r'[^>]*?bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"')
DATA_ROW_TITLES = ("Мобильные данные", "Mobile data", "Mobile Data", "Мобильный интернет")
OFF_TITLES = ("Выключено", "Выкл.", "Off", "None", "Нет")


def parse_ui_nodes(xml):
    """`uiautomator dump` → список узлов экрана с текстом и координатами центра."""
    nodes = []
    for text, rid, cls, desc, checkable, checked, x0, y0, x1, y1 in UI_NODE.findall(xml):
        nodes.append({"text": text, "id": rid.split("/")[-1], "class": cls.split(".")[-1], "desc": desc,
                      "checkable": checkable == "true", "checked": checked == "true",
                      "x": (int(x0) + int(x1)) // 2, "y": (int(y0) + int(y1)) // 2, "y0": int(y0)})
    return nodes


def find_node(nodes, texts):
    for node in nodes:
        if node["text"] in texts:
            return node
    return None


def _data_sim_items(nodes):
    items = [n for n in nodes if n["checkable"] and n["class"] == "CheckedTextView"
             and n["text"] and n["text"] not in OFF_TITLES]
    items.sort(key=lambda n: n["y0"])
    return items


def _sim_chooser_present(nodes):
    """Экран уже показывает выбор дата-SIM (≥2 пунктов-галочек с именами SIM), а не список настроек."""
    return len(_data_sim_items(nodes)) >= 2


def pick_data_sim_from_dialog(nodes, slot):
    """Диалог «Мобильные данные» Samsung: пункты SIM по порядку слотов, последним «Выключено»."""
    items = _data_sim_items(nodes)
    return items[slot] if slot < len(items) else None


USSD_BY_OPERATOR = (
    (("мегафон", "megafon"), (("баланс", "*100#"), ("остаток пакетов", "*558#"))),
    (("мтс", "mts"), (("баланс", "*100#"), ("остаток пакетов", "*217#"))),
    (("билайн", "beeline"), (("баланс", "*102#"), ("остаток пакетов", "*107#"))),
    (("теле2", "tele2", "t2"), (("баланс", "*105#"), ("остаток пакетов", "*155*0#"))),
    (("yota", "йота"), (("баланс", "*100#"), ("остаток пакетов", "*106#"))),
)
USSD_STUBS = ("выполнение", "запрос принят", "заявка принята", "спасибо за обращение",
              "ожидайте", "отправлена в смс", "отправлена в sms", "направим ответ")
CANCEL_TITLES = ("Отменить", "Отмена", "Закрыть", "Cancel", "ОТМЕНИТЬ")
CONFIRM_TITLES = ("OK", "ОК", "Ок")


NUMBER_BY_OPERATOR = (
    (("мегафон", "megafon"), "*205#"),
    (("мтс", "mts"), "*111*0887#"),
    (("билайн", "beeline"), "*110*10#"),
    (("теле2", "tele2", "t2"), "*201#"),
    (("yota", "йота"), "*103#"),
)
PHONE_RE = re.compile(r"(?:\+7|8|7)[\s-]*\(?(\d{3})\)?[\s-]*(\d{3})[\s-]*(\d{2})[\s-]*(\d{2})")
BARE_PHONE_RE = re.compile(r"(?<!\d)(9\d{2})(\d{3})(\d{2})(\d{2})(?!\d)")


def sim_key(sim, serial=""):
    """Ключ для запоминания номера: телефон, слот и оператор - ICCID телефон отдаёт замазанным.
    Серийник обязателен, когда телефонов несколько: у двух может быть МегаФон в первом слоте."""
    key = "%d:%s" % (sim.slot, (sim.name or sim.carrier or "").strip().lower())
    return "%s|%s" % (serial, key) if serial else key


def saved_number(numbers, sim, serial="", only_phone=True):
    """Номер из памяти. Старые записи (до поддержки нескольких телефонов) без серийника -
    берём их, только если телефон на кабеле один, иначе можно подсунуть номер соседа."""
    numbers = numbers or {}
    number = numbers.get(sim_key(sim, serial)) if serial else None
    if not number and only_phone:
        number = numbers.get(sim_key(sim))
    return number or ""


def number_code_for(operator):
    """USSD-код «узнать свой номер» или None для незнакомого оператора."""
    low = (operator or "").lower()
    for keys, code in NUMBER_BY_OPERATOR:
        if any(key in low for key in keys):
            return code
    return None


def extract_phone_number(text):
    """Вытащить российский номер из ответа оператора и привести к +7XXXXXXXXXX."""
    clean = (text or "").replace(" ", " ")
    match = PHONE_RE.search(clean) or BARE_PHONE_RE.search(clean)
    if not match:
        return ""
    return "+7" + "".join(match.groups())


BALANCE_RE = re.compile(r"(-?\d[\d ]*(?:[.,]\d{1,2})?)\s*(?:руб|₽|rub|р(?![а-яёa-z]))", re.I)


def parse_balance(text):
    """Сумма на счёте из ответа оператора: «Баланс:75,05р», «Ваш баланс: 105 руб.», «баланс: 910 р.»."""
    match = BALANCE_RE.search((text or "").replace(" ", " "))
    if not match:
        return None
    try:
        return float(match.group(1).replace(" ", "").replace(",", "."))
    except ValueError:
        return None


def whitelist_verdict(balance_text):
    """Почему SIM в белых списках - по балансу. Деньги есть: почти наверняка ограничения у оператора."""
    amount = parse_balance(balance_text)
    if amount is None:
        return t("баланс узнать не удалось")
    if amount <= 0:
        return t("на счёте %g ₽ - похоже, кончились деньги: пополните SIM") % amount
    return (t("на счёте %g ₽ - деньги есть: вероятнее ограничения мобильного интернета у оператора "
              "(или кончился пакет трафика)") % amount)


def ussd_codes_for(operator):
    """Пары (что спрашиваем, код) по названию оператора; для незнакомого - только баланс."""
    low = (operator or "").lower()
    for keys, codes in USSD_BY_OPERATOR:
        if any(key in low for key in keys):
            return codes
    return (("баланс", "*100#"),)


def answer_is_stub(text):
    """Оператор ответил отпиской «ждите SMS», а не цифрами."""
    low = (text or "").lower()
    return any(stub in low for stub in USSD_STUBS)


def node_by_id(nodes, fragment):
    for node in nodes:
        if fragment in (node.get("id") or ""):
            return node
    return None


def dialer_sim_title(nodes):
    """Подпись кнопки выбора SIM на экране набора (например «Megafon1» / «MTS2»)."""
    node = node_by_id(nodes, "title_view")
    return (node.get("text") or "").strip() if node else ""


def same_sim(dialer_title, sim_name):
    """Кнопка набора зовётся «Megafon1», а SIM в системе - «MegaFon»: сверяем по буквам."""
    letters = "".join(ch for ch in (dialer_title or "").lower() if ch.isalpha())
    wanted = "".join(ch for ch in (sim_name or "").lower() if ch.isalpha())
    if not letters or not wanted:
        return False
    return letters.startswith(wanted[:3]) or wanted.startswith(letters[:3])


def ussd_answer(nodes):
    """Текст ответа оператора из окна USSD (кнопки и «выполняется…» отбрасываем)."""
    skip = ("ok", "отмена", "отправить", "cancel", "send")
    for node in nodes:
        text = (node.get("text") or "").strip()
        if len(text) > 6 and text.lower() not in skip and "выполнение кода" not in text.lower():
            return text
    return ""


SMS_ROW = re.compile(r"^Row: \d+ address=(?P<address>.*?), date=(?P<date>-?\d+), "
                     r"sub_id=(?P<sub>-?\d+), body=(?P<body>.*)$", re.S)


def parse_sms_rows(out):
    """`content query content://sms/inbox` → список писем.

    Тело SMS содержит и запятые, и переносы строк, поэтому режем не по строкам,
    а по границам «Row: N», и body (он последний в проекции) берём целиком.
    """
    chunks = re.split(r"(?m)^(?=Row: \d+ )", out or "")
    messages = []
    for chunk in chunks:
        match = SMS_ROW.match(chunk.strip("\n"))
        if not match:
            continue
        try:
            date = int(match.group("date"))
            sub = int(match.group("sub"))
        except ValueError:
            continue
        messages.append({"address": match.group("address").strip(), "date": date,
                         "sub_id": sub, "body": match.group("body").strip()})
    return messages


class PhoneControl:
    def __init__(self, adb, should_stop=None):
        self.adb = adb
        self.should_stop = should_stop or (lambda: False)

    def sh(self, command, timeout=20):
        return self.adb.shell(command, timeout=timeout)

    def read_state(self):
        state = PhoneState()
        devices = self.adb.devices()
        if self.adb.serial:
            devices = [d for d in devices if d["serial"] == self.adb.serial]
        elif len(devices) > 1:
            state.error = t("подключено несколько телефонов - выберите, с каким работать")
            return state
        if not devices:
            return state
        device = devices[0]
        state.serial, state.state = device["serial"], device["state"]
        if device["state"] != "device":
            state.error = (t("подтвердите отладку по USB на телефоне") if device["state"] == "unauthorized"
                           else t("телефон в состоянии %s") % device["state"])
            return state
        state.connected = True
        try:
            state.model = self.sh("getprop ro.product.model").strip()
            state.android = self.sh("getprop ro.build.version.release").strip()
            state.battery, state.charging = parse_battery(self.sh("dumpsys battery"))
            state.airplane = self.sh("settings get global airplane_mode_on").strip() == "1"
            state.mobile_data_on = self.sh("settings get global mobile_data").strip() != "0"
            state.wifi_on, state.wifi_ssid = parse_wifi_status(self.sh("cmd wifi status"))
            if not state.wifi_on:
                state.wifi_on = self.sh("settings get global wifi_on").strip() == "1"
            state.transport = parse_transport(self.sh("dumpsys connectivity", timeout=30))
            state.sims, state.data_sub_id = self.read_sims()
        except AdbError as exc:
            state.error = str(exc)
        return state

    def read_sims(self):
        sims = []
        try:
            sims = parse_siminfo_content(self.sh(
                "content query --uri content://telephony/siminfo "
                "--projection _id:sim_id:display_name:carrier_name"))
        except AdbError:
            pass
        isub_sims, data_sub = parse_isub(self.sh("dumpsys isub", timeout=30))
        if not sims:
            sims = isub_sims
        if data_sub < 0:
            raw = self.sh("settings get global multi_sim_data_call").strip()
            data_sub = int(raw) if raw.lstrip("-").isdigit() else -1
        types = parse_getprop_list(self.sh("getprop gsm.network.type"))
        operators = parse_getprop_list(self.sh("getprop gsm.operator.alpha"))
        levels = parse_signal_levels(self.sh("dumpsys telephony.registry", timeout=30))
        for sim in sims:
            sim.is_data = sim.sub_id == data_sub
            if sim.slot < len(types):
                sim.network = types[sim.slot]
            if not sim.carrier and sim.slot < len(operators):
                sim.carrier = operators[sim.slot]
            sim.signal = levels.get(sim.slot, -1)
        return sims, data_sub


    def set_wifi(self, on):
        self.sh("svc wifi %s" % ("enable" if on else "disable"))

    def auto_wifi(self):
        """Samsung «Автоматическое включение Wi-Fi»: телефон сам поднимает Wi-Fi рядом со знакомой
        сетью - посреди замера по SIM это уводит трафик в домашний интернет. Возвращает 0/1 или None."""
        raw = (self.sh("settings get global auto_wifi") or "").strip()
        return int(raw) if raw.isdigit() else None

    def set_auto_wifi(self, on):
        self.sh("settings put global auto_wifi %d" % (1 if on else 0))

    def set_mobile_data(self, on):
        self.sh("svc data %s" % ("enable" if on else "disable"))

    def set_airplane(self, on):
        self.sh("cmd connectivity airplane-mode %s" % ("enable" if on else "disable"))

    def airplane_cycle(self, pause=4):
        self.set_airplane(True)
        time.sleep(pause)
        self.set_airplane(False)

    def current_data_sub(self):
        return parse_isub(self.sh("dumpsys isub", timeout=30))[1]

    def _wait_data_sub(self, sub_id, seconds):
        deadline = time.time() + seconds
        while time.time() < deadline and not self.should_stop():
            if self.current_data_sub() == sub_id:
                return True
            time.sleep(1.5)
        return False

    def active_sub(self):
        return parse_active_sub(self.sh("dumpsys connectivity", timeout=30))

    def active_transport(self):
        return parse_transport(self.sh("dumpsys connectivity", timeout=30))

    def wait_transport(self, kind, timeout=30):
        """Дождаться, пока сеть ПО УМОЛЧАНИЮ станет нужного типа (wifi/cellular) - иначе трафик уходит не туда."""
        deadline = time.time() + timeout
        while time.time() < deadline and not self.should_stop():
            if self.active_transport() == kind:
                return True
            time.sleep(2)
        return False

    def wait_active_sub(self, sub_id, timeout=40):
        """После смены SIM интернет ещё какое-то время идёт через старую - ждём, пока переедет."""
        deadline = time.time() + timeout
        while time.time() < deadline and not self.should_stop():
            if self.active_sub() == sub_id:
                return True
            time.sleep(2)
        return False

    def set_data_sim(self, sub_id, verify_seconds=4):
        """Переключить SIM для мобильных данных: сначала штатной настройкой, затем нажатиями
        в «Диспетчере SIM-карт» (One UI её игнорирует - проверено на A07 / One UI 8)."""
        if self.current_data_sub() == sub_id:
            return True
        self.sh("settings put global multi_sim_data_call %d" % sub_id)
        if self._wait_data_sub(sub_id, verify_seconds):
            return True
        if self.should_stop():
            return False
        return self.set_data_sim_via_ui(sub_id)


    def ui_nodes(self):
        self.sh("rm -f /sdcard/vpnstand_ui.xml; uiautomator dump /sdcard/vpnstand_ui.xml >/dev/null 2>&1; true",
                timeout=40)
        return parse_ui_nodes(self.sh("cat /sdcard/vpnstand_ui.xml", timeout=30))

    def tap(self, node, pause=1.5):
        self.sh("input tap %d %d" % (node["x"], node["y"]))
        time.sleep(pause)

    def wake(self):
        self.sh("input keyevent KEYCODE_WAKEUP; wm dismiss-keyguard")

    def home(self):
        self.sh("input keyevent KEYCODE_HOME")

    def set_data_sim_via_ui(self, sub_id):
        sims, _ = parse_isub(self.sh("dumpsys isub", timeout=30))
        slot = next((sim.slot for sim in sims if sim.sub_id == sub_id), None)
        if slot is None:
            return False
        self.wake()
        self.home()
        self.sh("am start -a android.settings.MANAGE_ALL_SIM_PROFILES_SETTINGS")
        item = None
        for _ in range(4):
            time.sleep(2.5)
            nodes = self.ui_nodes()
            if _sim_chooser_present(nodes):
                item = pick_data_sim_from_dialog(nodes, slot)
                if item:
                    break
            row = find_node(nodes, DATA_ROW_TITLES)
            if row:
                self.tap(row)
                item = pick_data_sim_from_dialog(self.ui_nodes(), slot)
                if item:
                    break
        if not item:
            self.home()
            return self.current_data_sub() == sub_id
        self.tap(item, pause=2)
        ok = self._wait_data_sub(sub_id, 15)
        self.home()
        return ok or self.current_data_sub() == sub_id

    def open_captcha_page(self, url="http://neverssl.com/"):
        """Белые списки: открыть в браузере телефона любую HTTP-страницу - оператор подменит её капчей."""
        self.set_wifi(False)
        time.sleep(5)
        self.wake()
        self.sh("am start -a android.intent.action.VIEW -d %s" % url)

    def open_sim_manager(self):
        """Запасной путь: открыть экран выбора SIM (Samsung / AOSP) для нажатия рукой или автоматом."""
        for intent in ("-n com.samsung.android.app.telephonyui/"
                       "com.samsung.android.app.telephonyui.simcardmanager.activity.SimCardMgrActivity",
                       "-a android.settings.MANAGE_ALL_SIM_PROFILES_SETTINGS",
                       "-a android.settings.NETWORK_OPERATOR_SETTINGS"):
            out = self.sh("am start %s" % intent)
            if "Error" not in out and "does not exist" not in out:
                return True
        return False

    def ussd(self, code, sim_name="", wait=40):
        """Отправить USSD с нужной SIM и вернуть (какая SIM выбрана, ответ с экрана).

        Подсказки слота в intent (extra.slot, simSlot, subscription) One UI игнорирует -
        проверено на A07: обе симки отвечали одинаково. Поэтому идём через экран набора,
        внизу там кнопка выбора SIM: жмём её, если стоит не та.
        """
        self.wake()
        self.dismiss_dialog()
        self.home()
        time.sleep(0.5)
        self.sh('am start -a android.intent.action.DIAL -d "tel:%s"' % code.replace("#", "%23"))
        time.sleep(3.5)
        nodes = self.ui_nodes()
        chosen = dialer_sim_title(nodes)
        if sim_name and not same_sim(chosen, sim_name):
            toggle = node_by_id(nodes, "dialpad_bottom_toggle_view")
            if toggle:
                self.tap(toggle, pause=1.5)
                nodes = self.ui_nodes()
                chosen = dialer_sim_title(nodes)
        button = node_by_id(nodes, "dialButton")
        if not button:
            self.home()
            return chosen, ""
        self.tap(button, pause=2)
        answer = ""
        deadline = time.time() + wait
        while time.time() < deadline and not self.should_stop():
            time.sleep(2.5)
            answer = ussd_answer(self.ui_nodes())
            if answer:
                break
        self.dismiss_dialog()
        self.home()
        return chosen, answer

    def dismiss_dialog(self, tries=3):
        """Закрыть висящее окно USSD: ответ, ошибку или интерактивное меню оператора.

        Меню («1.Мои услуги…») кнопкой «назад» не закрывается и блокирует экран набора,
        поэтому ищем кнопку. Сначала отмену, потом OK - у меню кнопка OK означала бы «отправить».
        """
        closed = False
        for _ in range(tries):
            nodes = self.ui_nodes()
            button = find_node(nodes, CANCEL_TITLES) or find_node(nodes, CONFIRM_TITLES)
            if not button:
                break
            self.tap(button, pause=1.0)
            closed = True
        if not closed:
            self.sh("input keyevent KEYCODE_BACK")
        return closed

    def read_sms(self, limit=15, since_ms=0, sub_id=None):
        """Входящие SMS: на USSD операторы часто отвечают письмом, а не на экране."""
        out = self.sh('content query --uri content://sms/inbox '
                      '--projection address:date:sub_id:body --sort "date DESC"', timeout=45)
        items = parse_sms_rows(out)
        if since_ms:
            items = [m for m in items if m["date"] > since_ms]
        if sub_id is not None:
            items = [m for m in items if m["sub_id"] in (sub_id, -1)]
        return items[:limit]

    def sim_balance(self, sim_name, sub_id, wait_sms=30):
        """Баланс одной SIM текстом оператора (с экрана или из ответной SMS); пусто - не ответил."""
        code = ussd_codes_for(sim_name)[0][1]
        started = int(time.time() * 1000)
        _chosen, answer = self.ussd(code, sim_name=sim_name)
        if answer and not answer_is_stub(answer) and parse_balance(answer) is not None:
            return answer
        deadline = time.time() + wait_sms
        while time.time() < deadline and not self.should_stop():
            time.sleep(4)
            for message in self.read_sms(since_ms=started, sub_id=sub_id):
                if parse_balance(message["body"]) is not None:
                    return message["body"]
        return answer if answer and not answer_is_stub(answer) else ""

    def sim_number(self, sim, progress=None):
        """Спросить у оператора собственный номер SIM. Ответ бывает и на экране, и в SMS."""
        code = number_code_for(sim.name or sim.carrier)
        if not code:
            return ""
        name = sim.name or sim.carrier or ""
        if progress:
            progress(t("%s: узнаю номер (%s)") % (name, code))
        started = int(time.time() * 1000)
        _chosen, answer = self.ussd(code, sim_name=name)
        number = extract_phone_number(answer)
        if number:
            return number
        deadline = time.time() + 35
        while time.time() < deadline and not number and not self.should_stop():
            time.sleep(4)
            for message in self.read_sms(since_ms=started, sub_id=sim.sub_id):
                number = extract_phone_number(message["body"])
                if number:
                    break
        return number

    def sim_report(self, progress=None, known_numbers=None, only_phone=True):
        """По каждой SIM: номер, баланс и остаток пакетов - USSD плюс ответные SMS оператора.

        known_numbers - уже известные номера по ключу из sim_key(): номер не меняется,
        второй раз оператора не дёргаем.
        """
        sims, _ = self.read_sims()
        known = known_numbers or {}
        report = []
        for sim in sims:
            name = sim.name or sim.carrier or "SIM %d" % (sim.slot + 1)
            number = saved_number(known, sim, self.adb.serial or "", only_phone)
            if not number:
                number = self.sim_number(sim, progress=progress)
            started = int(time.time() * 1000)
            lines = []
            for title, code in ussd_codes_for(name):
                if progress:
                    progress("%s: %s (%s)" % (name, t(title), code))
                _chosen, answer = self.ussd(code, sim_name=name)
                if answer and not answer_is_stub(answer):
                    lines.append("%s: %s" % (t(title), answer))
            if progress:
                progress(t("%s: жду ответ оператора по SMS…") % name)
            messages = []
            deadline = time.time() + 40
            while time.time() < deadline and not self.should_stop():
                time.sleep(4)
                messages = self.read_sms(since_ms=started, sub_id=sim.sub_id)
                if messages:
                    break
            report.append({"name": name, "sub_id": sim.sub_id, "slot": sim.slot, "number": number,
                           "key": sim_key(sim, self.adb.serial or ""), "ussd": lines,
                           "sms": [m["body"] for m in messages]})
        return report

    def diagnostics(self):
        """Сырые выводы для настройки парсеров под конкретную прошивку."""
        commands = [
            "getprop ro.product.model", "getprop ro.build.version.release",
            "dumpsys battery", "cmd wifi status", "settings get global wifi_on",
            "settings get global airplane_mode_on", "settings get global mobile_data",
            "settings get global multi_sim_data_call",
            "content query --uri content://telephony/siminfo --projection _id:sim_id:display_name:carrier_name",
            "getprop gsm.network.type", "getprop gsm.operator.alpha",
            "dumpsys isub", "dumpsys telephony.registry", "dumpsys connectivity",
            "ls -la /data/local/tmp/vpnstand",
        ]
        report = []
        for command in commands:
            try:
                out = self.sh(command, timeout=40)
            except AdbError as exc:
                out = t("ОШИБКА: %s") % exc
            report.append("$ %s\n%s\n" % (command, out.strip()[:6000]))
        return "\n".join(report)
