"""Инварианты тревог сервера на переборе сценариев (фиксированные seed): два узла, два подтверждённых места
(по две сети) и выдуманное место с одним свидетелем, падения, мигания, пропуски агентов и молчание Telegram.
Вызываются настоящие update_trends / scope_witnesses / notify / flush_alert_digest с подменённым временем.
- I1: каждое «перестал отвечать» и «работает с перебоями» получает «снова отвечает» или итог;
- I2: падение от 3 ч в подтверждённом месте даёт сообщение (с учётом паузы по узлу) или запись в истории;
- I3: выдуманное место не глушит сообщения подтверждённых;
- I4: не больше 8 сообщений по месту за сутки."""
import contextlib
import os
import random
import shutil
import sqlite3
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "server"))
import app as srv  # noqa: E402

H = 3600
T0 = 1_790_000_000.0
FLUSH_EVERY = 600
MAX_PER_DAY = 8
PLACES = {"A": ("Москва · MTS", [("a1", "10.0.1.0/24"), ("a2", "10.0.2.0/24")]),
          "B": ("Казань · Beeline", [("b1", "10.0.3.0/24"), ("b2", "10.0.4.0/24")]),
          "C": ("Выдумка · Fake", [("c1", "10.0.9.0/24")])}
SCOPE_PLACE = {scope: place for place, (scope, _agents) in PLACES.items()}
SEEDS = range(40)
FLAPPING = [(2 * H + i * 2.5 * H, 3.5 * H + i * 2.5 * H) for i in range(6)]
HAND = {
    "known_flapper_elsewhere": {"truth": {(0, "A"): FLAPPING, (0, "B"): [(30 * H, 44 * H)]}, "tg": []},
    "flap_while_telegram_silent": {"truth": {(0, "A"): FLAPPING, (0, "B"): []}, "tg": [(7 * H, 60 * H)]},
    "flap_stale_then_real_outage": {"truth": {(0, "A"): FLAPPING, (0, "B"): [(66 * H, 80 * H)]},
                                    "tg": [(7 * H, 60 * H)]},
}


class Clock:
    now = T0

    def time(self):
        return self.now

    def monotonic(self):
        return self.now

    def sleep(self, _seconds):
        pass

    def strftime(self, fmt, moment=None):
        import time as real_time
        return real_time.strftime(fmt, moment or real_time.localtime(self.now))


class Harness:
    def __init__(self, monkeypatch, tmp):
        self.clock = Clock()
        self.log, self.tg_down = [], []
        monkeypatch.setattr(srv, "DB_PATH", os.path.join(tmp, "agents.db"))
        monkeypatch.setattr(srv, "time", self.clock)
        monkeypatch.setattr(srv, "telegram_send", self.telegram)
        monkeypatch.setattr(srv, "check_expiry", lambda now: False)
        monkeypatch.setattr(srv, "check_db_room", lambda now: False)
        monkeypatch.setattr(srv, "server_error", lambda *args, **kwargs: None)
        monkeypatch.setenv("TG_BOT_TOKEN", "1:test")
        monkeypatch.setenv("TG_ADMIN", "1")
        srv.init_db()
        self.conn = sqlite3.connect(srv.DB_PATH, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA synchronous=OFF")
        monkeypatch.setattr(srv, "db", self.db)
        mark = srv._mark_alerted
        monkeypatch.setattr(srv, "_mark_alerted",
                            lambda conn, rows, now, lines=(): self.sent(mark, conn, rows, now, lines))
        srv._alert_sent.clear()
        srv._telegram_status[0] = 0

    @contextlib.contextmanager
    def db(self):
        with self.conn:
            yield self.conn

    def close(self):
        self.conn.close()

    def telegram(self, _text):
        if any(start <= self.clock.now < end for start, end in self.tg_down):
            srv._telegram_status[0] = 0
            srv._telegram_error[0] = "down"
            return False
        return True

    def sent(self, mark, conn, rows, now, lines):
        for row in rows:
            self.log.append((now - T0, row["node"], SCOPE_PLACE[row["scope"]], int(row["ok"]),
                             row["key"].startswith(srv.FLAP_PREFIX)))
        return mark(conn, rows, now, lines)

    def reset(self):
        with self.db() as conn:
            for table in ("node_state", "alert_pending", "alert_last", "alerts", "scope_agents", "reports", "agents"):
                conn.execute("DELETE FROM %s" % table)
        srv._alert_sent.clear()
        srv._telegram_status[0] = 0
        self.log = []

    def history(self):
        with self.db() as conn:
            rows = conn.execute("SELECT ts, kind, node, text FROM alerts").fetchall()
        return [(row["ts"] - T0, row["kind"], row["node"], row["text"]) for row in rows]

    def run(self, scenario, with_fake):
        self.reset()
        rng, rng_fake = random.Random(scenario["seed"]), random.Random(scenario["seed"] + 1)
        self.clock.now = T0
        self.tg_down = [(T0 + start, T0 + end) for start, end in scenario["tg"]]
        end = scenario["horizon"] + scenario["tail"]
        agents = {agent: rng.uniform(0, scenario["period"][agent]) for agent in scenario["period"]}
        if not with_fake:
            agents.pop("c1")
        flush_at = 0.0
        while True:
            moment = min(min(agents.values()), flush_at)
            if moment > end:
                break
            self.clock.now = T0 + moment
            if flush_at <= moment:
                srv.flush_alert_digest(T0 + moment)
                flush_at += FLUSH_EVERY
                continue
            agent = min(agents, key=agents.get)
            source = rng_fake if agent == "c1" else rng
            agents[agent] += scenario["period"][agent] * source.uniform(0.8, 1.2)
            gap = scenario["gaps"].get(agent)
            if gap and gap[0] <= moment < gap[1]:
                continue
            place = next(key for key, (_scope, items) in PLACES.items() if agent in dict(items))
            scope, items = PLACES[place]
            results = {node_name(n): {"ok": self.answers(scenario, n, place, moment, source)}
                       for n in range(scenario["nodes"])}
            with self.db() as conn:
                events = srv.update_trends(conn, scope, results, {}, None, dict(items)[agent], agent)
                witnesses = srv.scope_witnesses(conn, scope, agent, T0 + moment, dict(items)[agent])
            srv.notify(events, scope, agent, witnesses, dict(items)[agent])
        return list(self.log), self.history()

    @staticmethod
    def answers(scenario, n, place, moment, rng):
        if place == "C":
            mode, share = scenario["fake"]
            if moment >= scenario["horizon"] or mode == "off":
                return True
            if mode == "random":
                return rng.random() < share
            if mode == "down":
                return False
            if mode == "flap":
                return int(moment // (share * 2 * H)) % 2 == 0
            return not down_at(scenario["truth"], n, "A", moment - 1800)
        return not down_at(scenario["truth"], n, place, moment) and rng.random() >= scenario["noise"]


def node_name(n):
    return "n%d.example.net:443 · xhttp" % n


def down_at(truth, n, place, moment):
    return any(start <= moment < end for start, end in truth.get((n, place), []))


def generate(seed, horizon=3 * 86400, nodes=2):
    rng = random.Random(seed)
    truth = {}
    for n in range(nodes):
        for place in ("A", "B"):
            segments, moment = [], rng.uniform(2, 20) * H
            while moment < horizon:
                kind = rng.random()
                if kind < 0.45:
                    length = rng.choice([0.5, 1, 2, 3, 4, 6, 9, 26]) * H
                    if rng.random() < 0.5 and place == "B" and truth.get((n, "A")):
                        start, stop = rng.choice(truth[(n, "A")])
                        moment, length = start + rng.uniform(-1, 2) * H, stop - start
                    segments.append((moment, moment + length))
                    moment += length + rng.uniform(0.5, 30) * H
                elif kind < 0.6:
                    stop = moment + rng.uniform(6, 30) * H
                    while moment < stop:
                        length = rng.uniform(0.3, 1.5) * H
                        segments.append((moment, moment + length))
                        moment += length + rng.uniform(0.3, 2) * H
                    moment += rng.uniform(1, 20) * H
                else:
                    moment += rng.uniform(3, 30) * H
            truth[(n, place)] = [(start, min(stop, horizon)) for start, stop in segments if start < horizon]
    tg = []
    for _ in range(rng.choice([0, 0, 1, 2])):
        start = rng.uniform(0, horizon)
        tg.append((start, start + rng.choice([0.2, 1, 5, 20]) * H))
    period = {agent: rng.choice([15, 20, 30, 45, 60]) * 60 for place in PLACES for agent, _net in PLACES[place][1]}
    gaps = {}
    for place in ("A", "B"):
        for agent, _net in PLACES[place][1]:
            if rng.random() < 0.2:
                start = rng.uniform(0, horizon)
                gaps[agent] = (start, start + rng.choice([2, 8]) * H)
    return {"truth": truth, "fake": (rng.choice(["off", "random", "down", "flap", "mirror"]), rng.uniform(0.2, 0.9)),
            "tg": tg, "period": period, "gaps": gaps, "nodes": nodes, "horizon": horizon, "tail": 2 * 86400,
            "noise": rng.choice([0.0, 0.02, 0.05]), "seed": seed}


def hand(name):
    scenario = dict(HAND[name], fake=("off", 0.0), period={agent: 900 for agent in ("a1", "a2", "b1", "b2", "c1")},
                    gaps={}, nodes=1, horizon=3 * 86400, tail=2 * 86400, noise=0.0, seed=7)
    return scenario


def in_history(history, node, place, start, stop):
    scope = PLACES[place][0].split(" · ")[1]
    return any(item[2] == node and item[1] in ("down", "flap") and scope in item[3] and start <= item[0] <= stop
               for item in history)


def violations(scenario, log, history):
    bad = []
    by_place = {}
    for moment, node, place, ok, flap in log:
        by_place.setdefault((node, place), []).append((moment, ok, flap))
    for key, items in by_place.items():
        last = items[-1]
        if last[2] or not last[1]:
            bad.append(("I1 без пары или итога", key, round(last[0] / H, 1), "перебои" if last[2] else "не отвечает"))
        stamps = [item[0] for item in items]
        for first in stamps:
            if sum(1 for moment in stamps if first <= moment < first + 86400) > MAX_PER_DAY:
                bad.append(("I4 больше %d в сутки" % MAX_PER_DAY, key, round(first / H, 1)))
                break
    late = srv.ALERT_COOLDOWN + 3 * H
    for (n, place), segments in scenario["truth"].items():
        node = node_name(n)
        for start, stop in segments:
            if stop - start < 3 * H:
                continue
            items = by_place.get((node, place), [])
            before = [item for item in items if item[0] <= start and not item[2]]
            if before and not before[-1][1]:
                continue
            if any(item[4] and item[1] == node and start - srv.FLAP_MEMORY <= item[0] <= start + late for item in log):
                continue
            if any(start <= item[0] <= start + late and (item[2] or not item[1]) for item in items):
                continue
            if in_history(history, node, place, start, stop + late):
                continue
            bad.append(("I2 падение без сообщения", node, place, round(start / H, 1), round((stop - start) / H, 1)))
    return bad


def confirmed_downs(log):
    return [(moment, node, place) for moment, node, place, ok, flap in log if place != "C" and not ok and not flap]


@pytest.fixture
def harness(monkeypatch):
    tmp = tempfile.mkdtemp(prefix="vpncheck-alerts-")
    sim = Harness(monkeypatch, tmp)
    yield sim
    sim.close()
    shutil.rmtree(tmp, ignore_errors=True)


@pytest.mark.parametrize("name", sorted(HAND))
def test_known_flapper_cases(harness, name):
    scenario = hand(name)
    log, history = harness.run(scenario, with_fake=False)
    assert violations(scenario, log, history) == []
    if name != "flap_while_telegram_silent":
        assert any(place == "B" and not ok and not flap for _t, _n, place, ok, flap in log), log


def test_stale_flap_is_not_sent_but_kept_in_history(harness):
    log, history = harness.run(hand("flap_while_telegram_silent"), with_fake=False)
    assert not [item for item in log if item[4] and item[0] > 60 * H - 1]
    assert [item for item in history if item[1] == "flap"]


def test_invariants_on_generated_scenarios(harness):
    problems = []
    for seed in SEEDS:
        scenario = generate(seed)
        log, history = harness.run(scenario, with_fake=True)
        problems += [(seed, "с выдумкой") + item for item in violations(scenario, log, history)]
        if scenario["fake"][0] == "off":
            continue
        base, base_history = harness.run(scenario, with_fake=False)
        problems += [(seed, "без выдумки") + item for item in violations(scenario, base, base_history)]
        with_fake = confirmed_downs(log)
        for moment, node, place in confirmed_downs(base):
            window = srv.ALERT_COOLDOWN + H
            if not any(other[1:] == (node, place) and abs(other[0] - moment) <= window for other in with_fake) \
                    and not in_history(history, node, place, moment - window, moment + window):
                problems.append((seed, "I3 выдумка заглушила", node, place, round(moment / H, 1)))
    assert problems == []
