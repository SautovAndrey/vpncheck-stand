"""Снимки окон для README на выдуманных данных: python tools/screenshots.py [--lang en|ru] [--out docs/screenshots]

Настройки и ключи берутся из временной папки (в подключениях - выдуманный пробник ДЦ), к серверу агентов,
панелям и пробнику скрипт не ходит.
"""
import argparse
import importlib.util
import json
import os
import random
import subprocess
import sys
import tempfile
import time
import traceback

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER = "http://203.0.113.10:8787"
MAX_WIDTH = 1400

CITIES = [
    ("Москва", "Москва", 55.75, 37.62, "MTS", "cellular", True, 0.2),
    ("Санкт-Петербург", "Санкт-Петербург", 59.94, 30.31, "MegaFon", "cellular", True, 0.4),
    ("Казань", "Татарстан", 55.79, 49.12, "Beeline", "cellular", False, 1.5),
    ("Екатеринбург", "Свердловская область", 56.84, 60.60, "Tele2", "cellular", False, 2.2),
    ("Новосибирск", "Новосибирская область", 55.03, 82.92, "MTS", "wifi", False, 0.7),
    ("Краснодар", "Краснодарский край", 45.04, 38.98, "MegaFon", "cellular", True, 0.1),
    ("Нижний Новгород", "Нижегородская область", 56.33, 44.00, "Beeline", "cellular", False, 5.0),
    ("Самара", "Самарская область", 53.20, 50.15, "Tele2", "cellular", False, 16.0),
    ("Ростов-на-Дону", "Ростовская область", 47.23, 39.72, "MTS", "cellular", False, 1.1),
    ("Владивосток", "Приморский край", 43.12, 131.89, "MegaFon", "cellular", False, 30.0),
    ("Пермь", "Пермский край", 58.01, 56.25, "Beeline", "wifi", True, 0.3),
    ("Тюмень", "Тюменская область", 57.15, 65.53, "Tele2", "cellular", False, 3.4),
]
MODELS = [("SM-A075F", "15"), ("SM-A175F", "15"), ("Redmi Note 13", "14"), ("Pixel 7a", "16"),
          ("SM-A155F", "14"), ("POCO X6", "14"), ("Galaxy S21 FE", "15"), ("Honor X8b", "14"),
          ("SM-A055F", "14"), ("Redmi 13C", "14"), ("SM-A256E", "15"), ("Realme C67", "14")]
ORGS = {"MTS": "MTS PJSC", "MegaFon": "PJSC MegaFon", "Beeline": "PJSC VimpelCom", "Tele2": "T2 Mobile LLC"}
NODES = [("203.0.113.21:443", "🇩🇪 Германия", "🇩🇪 Germany"), ("203.0.113.22:443", "🇩🇪 Германия-2", "🇩🇪 Germany-2"),
         ("198.51.100.31:443", "🇳🇱 Нидерланды", "🇳🇱 Netherlands"), ("198.51.100.45:443", "🇵🇱 Польша", "🇵🇱 Poland"),
         ("192.0.2.61:443", "🇨🇭 Швейцария", "🇨🇭 Switzerland"), ("203.0.113.71:443", "🇫🇮 Финляндия", "🇫🇮 Finland"),
         ("198.51.100.81:443", "🇦🇹 Австрия", "🇦🇹 Austria"), ("192.0.2.90:8443", "🇸🇪 Швеция", "🇸🇪 Sweden")]
SITES = [("https://example.com", "Example"), ("https://shop.example.org", "Shop"),
         ("https://news.example.net", "News")]
HOSTERS = {"203.0.113.21": ("Example Hosting GmbH", "DE"), "203.0.113.22": ("Example Hosting GmbH", "DE"),
           "198.51.100.31": ("Sample Cloud B.V.", "NL"), "198.51.100.45": ("Demo Net Sp. z o.o.", "PL"),
           "192.0.2.61": ("Test Datacenter AG", "CH"), "192.0.2.62": ("Test Datacenter AG", "CH"),
           "203.0.113.71": ("Nordic Example Oy", "FI"), "198.51.100.81": ("Alpine Demo GmbH", "AT"),
           "198.51.100.82": ("Alpine Demo GmbH", "AT")}


def fake_hex(rng, size):
    return "".join(rng.choice("0123456789abcdef") for _ in range(size))


def make_agents(rng, now):
    agents = []
    for index, (city, region, lat, lon, operator, network, online, hours) in enumerate(CITIES):
        model, android = MODELS[index]
        total = len(NODES)
        alive = 0 if index == 7 else total - rng.choice([0, 0, 1, 2, 3])
        agents.append({
            "agent_id": fake_hex(rng, 32), "city": city, "region": region, "lat": lat, "lon": lon,
            "operator": operator, "network": network, "online": online, "alive": alive, "total": total,
            "last_seen": now - hours * 3600, "first_seen": now - (20 + index) * 86400,
            "app_version": "0.12.0" if index % 4 else "0.11.3", "core_version": "26.6.27",
            "model": model, "android": android, "org": ORGS[operator], "push": index % 3 == 0,
            "ip": "198.51.100.%d" % (100 + index),
        })
    return agents


def make_state(lang, now):
    return {
        "nodes": [{"key": key, "location": ru if lang == "ru" else en} for key, ru, en in NODES],
        "sites": [{"url": url, "name": name} for url, name in SITES],
        "manifest": {"app": {"version_code": 120, "version_name": "0.12.0", "url": "/files/agent-0.12.0.apk",
                             "sha256": "9f2c" + "0" * 60},
                     "core": {"version": "26.6.27", "url": "/files/xray-26.6.27", "sha256": "4b1e" + "0" * 60}},
        "interval_min": 180, "nodes_expire": now + 21 * 86400, "test_url": "https://api.ipify.org",
        "latency_url": "https://www.google.com/generate_204", "location_round": 20, "message": "",
    }


def make_matrix(rng, agents):
    from stand import places
    columns = {}
    for agent in agents[:9]:
        name = "%s · %s" % (places.region(agent["region"]), agent["operator"])
        columns[name] = {"region": agent["region"], "operator": agent["operator"], "reports": rng.randint(3, 9)}
    matrix, sites = {}, {}
    for key, _ru, _en in NODES:
        blocked = key.startswith("198.51.100.45")
        matrix[key] = {}
        for column in columns:
            total = rng.randint(4, 8)
            alive = 0 if blocked or (key.startswith("192.0.2.61") and "MTS" in column) else \
                total - rng.choice([0, 0, 0, 1, total // 2])
            matrix[key][column] = [alive, total]
    for url, _name in SITES:
        sites[url] = {column: [rng.randint(0, 3) if "news" in url else 3, 3] for column in columns}
    return {"columns": columns, "matrix": matrix, "sites": sites, "since": 0}


def make_trends(rng, matrix, now):
    trends = []
    for key, cells in matrix["matrix"].items():
        for scope, (alive, total) in list(cells.items())[:4]:
            checks = rng.randint(30, 60)
            rate = alive / total if total else 0.0
            if 0.05 < rate < 0.95:
                rate = rng.choice([rate, 0.97, 1.0])
            ok = rng.random() < rate
            trends.append({"node": key, "scope": scope, "ok": ok, "rate": rate, "checks": checks,
                           "changed": now - rng.randint(1, 72) * 3600,
                           "checks_all": checks * 3, "ok_checks_all": round(checks * 3 * rate)})
    for url, cells in matrix["sites"].items():
        for scope, (alive, total) in list(cells.items())[:2]:
            trends.append({"node": "site:" + url, "scope": scope, "ok": alive == total, "rate": alive / total,
                           "checks": 2 if "news" in url else 24, "changed": now - 5 * 3600})
    return trends


def make_reports(rng, agent, now):
    reports = []
    for index in range(14):
        wifi = index % 5 == 3
        total = len(NODES)
        alive = total - rng.choice([0, 0, 1, 1, 2, 8 if index == 6 else 0])
        results = {key: {"ok": position < alive} for position, (key, _ru, _en) in enumerate(NODES)}
        sites = {url: {"ok": not ("news" in url and index % 2)} for url, _name in SITES}
        reports.append({
            "ts": now - (index * 3 + 0.3) * 3600, "network": "wifi" if wifi else "cellular",
            "operator": "HomeNet" if wifi else agent["operator"], "region": agent["region"], "city": agent["city"],
            "alive": max(alive, 0), "total": total,
            "payload": {"results": results, "sites": sites, "duration_s": rng.randint(38, 95),
                        "network": {"type": "wifi" if wifi else "cellular", "operator": agent["operator"],
                                    "sim_operator": agent["operator"]}},
        })
    return reports


def fit(path):
    from PIL import Image
    image = Image.open(path)
    if image.width > MAX_WIDTH:
        height = round(image.height * MAX_WIDTH / image.width)
        image = image.resize((MAX_WIDTH, height), Image.LANCZOS)
    image.save(path, optimize=True)


def shoot(lang, out):
    appdata = tempfile.mkdtemp(prefix="vpncheck-shots-")
    os.environ["APPDATA"] = appdata
    os.environ["VPNCHECK_LANG"] = lang
    os.makedirs(os.path.join(appdata, "VPNCheckStand"), exist_ok=True)
    with open(os.path.join(appdata, "VPNCheckStand", "connections.json"), "w", encoding="utf-8") as f:
        json.dump({"probe": {"host": "203.0.113.50", "port": 22, "user": "root", "key": "~/.ssh/id_ed25519",
                             "place": "Москва" if lang == "ru" else "Moscow"}}, f)
    sys.path.insert(0, ROOT)
    from PySide6.QtCore import QTimer
    from PySide6.QtGui import QFont
    from PySide6.QtWidgets import QApplication, QLineEdit

    from stand import agentapi, geo
    from stand.ui import center as center_module
    from stand.ui import main_window as main_module
    from stand.ui.agent_dialog import AgentDialog
    from stand.ui.pairing import PairingDialog
    from stand.ui.theme import QSS

    class NoAdb:
        def __init__(self, *_args, **_kwargs):
            raise main_module.AdbError("demo")

    def cached(host):
        org, country = HOSTERS.get(host, ("", ""))
        return {"ip": host, "org": org, "country": country} if org else {}

    geo.cached = cached
    geo.lookup_many = lambda hosts, workers=8: {host: cached(host) for host in hosts}
    main_module.Adb = NoAdb
    agentapi.load_agent_config = lambda: {"server": SERVER, "token": "demo-token"}
    agentapi.save_agent_config = lambda *_args, **_kwargs: None
    center_module.CenterWindow.connect_server = lambda self: self.status.setText(
        center_module.t("сервер на связи · агентов: %d") % len(CITIES))
    center_module.CenterWindow.refresh = lambda self: None

    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setStyleSheet(QSS)
    app.setFont(QFont("Segoe UI", 10))
    rng = random.Random(42)
    now = time.time()
    agents = make_agents(rng, now)
    windows = {}
    failed = []

    def guarded(step):
        def run():
            try:
                step()
            except Exception:
                traceback.print_exc()
                failed.append(step.__name__)
                app.exit(1)
        return run

    def save(widget, name):
        path = os.path.join(out, "%s-%s.png" % (name, lang))
        widget.grab().save(path)
        fit(path)
        print(path)

    def step_main():
        window = main_module.MainWindow(demo=True)
        window.resize(1920, 900)
        window.show()
        window.load_demo()
        window.statusBar().clearMessage()
        windows["main"] = window
        QTimer.singleShot(2500, guarded(lambda: (save(window, "main"), step_center())))

    def step_center():
        windows["main"].hide()
        window = center_module.CenterWindow({"squads_cache": {}, "squad": ""}, {"panels": {"demo": {}}})
        window.timer.stop()
        window.resize(1920, 900)
        window.map.parent().setSizes([860, 1060])
        window.show()
        window.on_agents(agents)
        window.on_state(make_state(lang, now))
        matrix = make_matrix(rng, agents)
        window.on_matrix(matrix)
        window.fill_trends(make_trends(rng, matrix, now))
        window.map.loadFinished.connect(lambda _ok: window.push_agents_to_map())
        windows["center"] = window
        QTimer.singleShot(9000, guarded(lambda: (window.push_agents_to_map(),
                                                 QTimer.singleShot(1500, guarded(center_shots)))))

    def center_shots():
        window = windows["center"]
        save(window, "center")
        window.tabs.setCurrentIndex(1)
        QTimer.singleShot(500, guarded(lambda: (save(window, "center-matrix"), step_agent())))

    def step_agent():
        agent = dict(agents[0])
        dialog = AgentDialog(agent, make_reports(rng, agent, now), windows["center"])
        stamp = now - 600
        dialog.results_view.appendPlainText(AgentDialog._render_result({
            "ts": stamp, "action": "diag",
            "result": {"battery_pct": 76, "charging": True, "signal_level": 3, "usable_networks": 1,
                       "app_version": "0.12.0", "last_summary": "7/8",
                       "network": {"type": "cellular", "operator": agent["operator"]}}}))
        dialog.results_view.appendPlainText(AgentDialog._render_result({
            "ts": stamp + 40, "action": "site_check",
            "result": {"url": "https://example.com", "ok": True, "code": 200, "ms": 412,
                       "network": {"type": "cellular", "operator": agent["operator"]}}}))
        dialog.results_view.appendPlainText(AgentDialog._render_result({
            "ts": stamp + 95, "action": "speed",
            "result": {"ok": True, "location": NODES[0][1 if lang == "ru" else 2], "mbps": 38.4,
                       "bytes": 5242880, "ms": 1092, "network": {"type": "cellular", "operator": agent["operator"]}}}))
        dialog.resize(1100, 940)
        dialog.show()
        windows["agent"] = dialog
        QTimer.singleShot(800, guarded(lambda: (save(dialog, "agent"), dialog.hide(), step_pairing())))

    def step_pairing():
        dialog = PairingDialog(SERVER, fake_hex(random.Random(7), 64), windows["center"])
        dialog.show()
        dialog.adjustSize()
        dialog.findChild(QLineEdit).setCursorPosition(0)
        windows["pairing"] = dialog
        QTimer.singleShot(800, guarded(lambda: (save(dialog, "pairing"), app.quit())))

    QTimer.singleShot(300, guarded(step_main))
    code = app.exec()
    return 1 if failed else code


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--lang", choices=["en", "ru"])
    parser.add_argument("--out", default=os.path.join(ROOT, "docs", "screenshots"))
    args = parser.parse_args()
    if importlib.util.find_spec("PIL") is None:
        sys.exit("Pillow is needed: python -m pip install -r requirements-dev.txt")
    os.makedirs(args.out, exist_ok=True)
    if args.lang:
        return shoot(args.lang, args.out)
    for lang in ("en", "ru"):
        code = subprocess.run([sys.executable, os.path.abspath(__file__), "--lang", lang, "--out", args.out]).returncode
        if code:
            return code
    return 0


if __name__ == "__main__":
    sys.exit(main())
