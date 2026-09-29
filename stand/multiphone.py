"""Несколько телефонов на одном компьютере: раскладка прогона по телефонам и сборка общего отчёта.

Каждый телефон гоняется своим CheckWorker в своём потоке, со своим окном локальных портов
(xray.port_shift) и своим локом. ДЦ-пробник от телефона не зависит - ему отдельный поток.
В конце прогоны склеиваются в один: колонки «MTS RUS · A075F», «MegaFon · A175F» и т.д.

Телефоны на одной точке Wi-Fi меряют одно и то же, поэтому их Wi-Fi - ОДНА общая колонка,
а узлы в ней делятся между телефонами поровну: оба заканчивают раньше, никто не простаивает.

С одним телефоном всё как раньше: id сетей без приставок (sim1, wifi), история не ломается.
"""
import re
import time
from collections import namedtuple

from . import portlock
from .checker import CheckWorker, Mode
from .i18n import t
from .xray import port_shift

SEP = "@"
JOIN = "+"

Job = namedtuple("Job", "serial shift tag modes mode_targets")
DC_TAG = "ДЦ"


def phone_tag(model, serial, taken=()):
    """Короткое имя телефона для подписей колонок: модель без «SM-», при совпадении - хвост серийника."""
    name = (model or "").strip()
    if name.upper().startswith("SM-"):
        name = name[3:]
    name = name or serial[-6:]
    if name in taken:
        name = "%s·%s" % (name, serial[-4:])
    return name


def describe_phones(adb_factory, serials):
    """[{serial, index, model, tag, state}] по порядку серийников.

    adb_factory(serial) → Adb для этого телефона. state - PhoneState (сети, SIM, Wi-Fi).
    """
    from .phone import PhoneControl
    phones, taken = [], []
    for index, serial in enumerate(serials):
        state = PhoneControl(adb_factory(serial)).read_state()
        tag = phone_tag(state.model, serial, taken)
        taken.append(tag)
        phones.append({"serial": serial, "index": index, "model": state.model, "tag": tag, "state": state})
    return phones


def assign_port_windows(phones, serials):
    """phone["index"] - место серийника среди всех готовых телефонов на кабеле (по алфавиту), по нему
    xray.port_shift. Окно и консольный run_check на разных телефонах так получают разные окна портов
    и не перебивают друг другу adb forward, даже если каждый гоняет только «свой» телефон."""
    order = sorted(set(serials) | {phone["serial"] for phone in phones})
    for phone in phones:
        phone["index"] = order.index(phone["serial"])
    return phones


def lease_port_windows(jobs):
    """Каждому потоку телефона - своё свободное окно портов (portlock) вместо места по алфавиту.

    Возвращает (потоки с новым shift, занятые окна) или (None, []), если свободных окон не хватило.
    Окна отпускает вызывающий (portlock.release_all), когда потоки закончат.
    """
    held, leased = [], []
    for job in jobs:
        if job.serial is None:
            leased.append(job)
            continue
        index = portlock.acquire()
        if index is None:
            portlock.release_all(held)
            return None, []
        held.append(index)
        leased.append(job._replace(shift=portlock.shift(index)))
    return leased, held


def make_worker(job, targets, settings, connections, adb, raw=None):
    """CheckWorker одного потока прогона (телефон или ДЦ) - одинаково для окна и run_check.
    adb - Adb этого телефона (у потока ДЦ - любой или None)."""
    return CheckWorker(targets, job.modes, adb, settings, connections, shift=job.shift, tag=job.tag,
                       mode_targets=job.mode_targets, raw=raw)


def dc_label(connections):
    """Подпись колонки ДЦ: «ДЦ» и место пробника, если оно задано в «Подключениях»."""
    place = str(((connections or {}).get("probe") or {}).get("place") or "").strip()
    return t("ДЦ") + (" · " + place if place else "")


def phone_modes(state, tag="", serial="", multi=False, with_wifi=True):
    """Сети одного телефона. Если телефонов несколько - id с приставкой серийника, подпись с тегом."""
    modes = []
    if not state or not state.connected:
        return modes
    for sim in state.sims:
        label = sim.name or sim.carrier or "SIM %d" % (sim.slot + 1)
        modes.append(Mode("sim%d" % sim.sub_id, "sim", label, sim.sub_id, sim.slot))
    if with_wifi:
        modes.append(Mode("wifi", "wifi", "Wi-Fi" + (" · " + state.wifi_ssid if state.wifi_ssid else "")))
    if multi:
        modes = [Mode(m.id + SEP + serial, m.kind, "%s · %s" % (m.label, tag), m.sub_id, m.slot) for m in modes]
    return modes


def wifi_groups(phones):
    """{сеть Wi-Fi: [серийники]} телефонов на связи, в порядке телефонов."""
    groups = {}
    for phone in phones:
        state = phone["state"]
        if state and state.connected and state.wifi_ssid:
            groups.setdefault(state.wifi_ssid, []).append(phone["serial"])
    return groups


def shared_wifi_mode(ssid, serials):
    """Общая колонка Wi-Fi для телефонов на одной точке."""
    return Mode("wifi" + SEP + JOIN.join(serials), "wifi", "Wi-Fi · %s" % ssid)


def mode_groups(phones, has_dc):
    """Что можно проверить: [(заголовок группы, [Mode…])] - ДЦ, общий Wi-Fi, потом телефоны.

    Общий Wi-Fi стоит до SIM: телефоны и так на Wi-Fi, переключаться ради него не надо.
    has_dc - подпись колонки ДЦ (dc_label) или просто True/False.
    """
    phones = [p for p in phones if p["state"] and p["state"].connected]
    multi = len(phones) > 1
    groups = []
    if has_dc:
        groups.append(("", [Mode("dc", "dc", has_dc if isinstance(has_dc, str) else t("ДЦ"))]))
    shared = {ssid: serials for ssid, serials in wifi_groups(phones).items() if multi and len(serials) > 1}
    in_shared = {serial for serials in shared.values() for serial in serials}
    if shared:
        groups.append((t("общий Wi-Fi - узлы делятся между телефонами"),
                       [shared_wifi_mode(ssid, serials) for ssid, serials in shared.items()]))
    for phone in phones:
        modes = phone_modes(phone["state"], phone["tag"], phone["serial"], multi,
                            with_wifi=phone["serial"] not in in_shared)
        groups.append((phone["tag"] if multi else "", modes))
    return groups


def split_mode_id(mode_id):
    """«sim1@SERIAL» → («sim1», «SERIAL»); одиночный «sim1» → («sim1», «»)."""
    base, _, serial = mode_id.partition(SEP)
    return base, serial


def mode_serials(mode_id):
    """Серийники телефонов, которые ведут эту колонку (у общего Wi-Fi - несколько)."""
    _, serial = split_mode_id(mode_id)
    return [s for s in serial.split(JOIN) if s]


CARRIER_ALIASES = (("билайн", "beeline"), ("мтс", "mts"), ("мегафон", "megafon"), ("теле2", "tele2"),
                   ("йота", "yota"), ("тинькофф", "tinkoff"))
SIM_TOKEN = re.compile(r"^sim(\d+)$")


def _owners(mode, phones):
    """Телефоны колонки: у одиночного телефона id без серийника - тогда это он сам."""
    serials = mode_serials(mode.id)
    if not serials and mode.kind != "dc" and len(phones) == 1:
        serials = [phones[0]["serial"]]
    return [p for p in phones if p["serial"] in serials]


def mode_token(mode, phones=()):
    """Как назвать сеть в --modes: dc, wifi, sim<слот>; при нескольких телефонах - с @ТЕГОМ."""
    base, _ = split_mode_id(mode.id)
    if mode.kind == "sim" and mode.slot >= 0:
        base = "sim%d" % (mode.slot + 1)
    owners = _owners(mode, phones)
    if len(phones) > 1 and len(owners) == 1:
        base += SEP + owners[0]["tag"]
    return base


def describe_mode(mode, phones=()):
    """«sim2 (Билайн, слот 2)», «dc (ДЦ · Москва)» - для --list-modes и сообщений об ошибке."""
    token = mode_token(mode, phones)
    if mode.kind == "sim" and mode.slot >= 0:
        return "%s (%s, %s)" % (token, mode.label, t("слот %d") % (mode.slot + 1))
    return "%s (%s)" % (token, mode.label)


def _carrier_variants(word):
    variants = {word}
    for ru, en in CARRIER_ALIASES:
        if ru in word:
            variants.add(word.replace(ru, en))
        if en in word:
            variants.add(word.replace(en, ru))
    return variants


def _match_token(name, pool, phones):
    if name == "dc":
        return [m for m in pool if m.kind == "dc"]
    if name == "wifi":
        return [m for m in pool if m.kind == "wifi"]
    slot = SIM_TOKEN.match(name)
    if slot:
        found = [m for m in pool if m.kind == "sim" and m.slot == int(slot.group(1)) - 1]
        return found or [m for m in pool if m.kind == "sim" and split_mode_id(m.id)[0] == name]
    variants = _carrier_variants(name)
    found = [m for m in pool if m.kind == "sim"
             and any(v in m.label.split(" · ")[0].lower() for v in variants)]
    per_phone = {}
    for mode in found:
        for owner in _owners(mode, phones) or [None]:
            per_phone.setdefault(owner and owner["serial"], []).append(mode)
    if any(len(group) > 1 for group in per_phone.values()):
        raise ValueError(t("«%s» подходит к нескольким сетям: %s - уточните номером слота (sim1, sim2)")
                         % (name, ", ".join(describe_mode(m, phones) for m in found)))
    return found


def resolve_modes(tokens, modes, phones=()):
    """Сети из --modes. Токен: dc, wifi, sim1/sim2 (номер слота SIM; если такого слота нет - старый id
    sim<subId>), имя оператора (mts, билайн, megafon) или полный id колонки; суффикс @ТЕГ или @СЕРИЙНИК -
    только этот телефон. Возвращает (сети в порядке колонок, [(токен, [сети])]). Непонятный токен или
    неоднозначное имя - ValueError с перечнем доступного."""
    picks, unknown = [], []
    for raw in tokens:
        token = raw.strip().lower()
        if not token:
            continue
        found = [m for m in modes if m.id.lower() == token]
        if not found:
            name, _, owner = token.partition(SEP)
            pool = modes
            if owner:
                pool = [m for m in modes if any(owner in (p["serial"].lower(), p["tag"].lower())
                                                for p in _owners(m, phones))]
            found = _match_token(name, pool, phones) if pool else []
        if not found:
            unknown.append(raw.strip())
        picks.append((raw.strip(), found))
    if unknown:
        raise ValueError(t("нет таких сетей: %s. Доступны: %s")
                         % (", ".join(unknown), ", ".join(describe_mode(m, phones) for m in modes) or "-"))
    chosen = {m.id for _, found in picks for m in found}
    return [m for m in modes if m.id in chosen], picks


def split_targets(targets, parts):
    """Поровну через один: живые и мёртвые узлы (мёртвый ждёт таймаут) расходятся честно."""
    return [targets[i::parts] for i in range(parts)]


def plan(modes, phones, targets=None):
    """Разложить выбранные сети по потокам: [Job(serial или None для ДЦ, shift, tag, [Mode…], {id: узлы})].

    Порядок потоков = порядок колонок в отчёте: сначала ДЦ, потом телефоны по очереди.
    Общую колонку Wi-Fi получают все её телефоны, каждый - со своим куском узлов; телефону, которому
    кусок не достался (узлов меньше, чем телефонов), колонку не даём - незачем переключать ему сеть.
    """
    single = phones[0]["serial"] if len(phones) == 1 else ""
    present = [p["serial"] for p in phones]
    jobs = []
    dc = [m for m in modes if m.kind == "dc"]
    if dc:
        jobs.append(Job(None, 0, DC_TAG, dc, {}))
    slices = {}
    for mode in modes:
        owners = [s for s in mode_serials(mode.id) if s in present]
        if len(owners) > 1 and targets is not None:
            slices[mode.id] = dict(zip(owners, split_targets(list(targets), len(owners)), strict=True))
    for phone in phones:
        mine, mode_targets = [], {}
        for mode in modes:
            if mode.kind == "dc":
                continue
            owners = mode_serials(mode.id) or ([single] if single else [])
            if phone["serial"] not in owners:
                continue
            if mode.id in slices:
                share = slices[mode.id][phone["serial"]]
                if not share:
                    continue
                mode_targets[mode.id] = share
            mine.append(mode)
        if mine:
            jobs.append(Job(phone["serial"], port_shift(phone["index"]),
                            phone["tag"] if len(phones) > 1 else "", mine, mode_targets))
    return jobs


def merge_runs(runs, targets):
    """Склеить прогоны потоков в один отчёт. runs - в порядке plan(), пустые пропускаются.

    Куски общей колонки (одинаковый id от разных телефонов) сливаются в одну колонку.
    Если упал только один кусок - колонка остаётся, причина в «partial_error».
    """
    runs = [r for r in runs if r]
    merged = {"started": min((r.get("started") for r in runs if r.get("started")),
                             default=time.strftime("%Y-%m-%d %H:%M:%S")),
              "finished": max((r.get("finished") for r in runs if r.get("finished")),
                              default=time.strftime("%Y-%m-%d %H:%M:%S")),
              "modes": [], "stopped": any(r.get("stopped") for r in runs),
              "targets": [{"location": target["location"], "key": target["key"], "sni": target.get("sni")}
                          for target in targets]}
    by_id = {}
    geo_by_phone = {}
    for run in runs:
        for record in run.get("modes") or []:
            known = by_id.get(record["id"])
            if known is None:
                known = dict(record)
                known["results"] = dict(record.get("results") or {})
                known["parts"] = 1
                by_id[record["id"]] = known
                merged["modes"].append(known)
                continue
            known["parts"] += 1
            known["results"].update(record.get("results") or {})
            known["ip"] = known.get("ip") or record.get("ip", "")
            errors = [e for e in (known.get("error"), known.get("partial_error"), record.get("error")) if e]
            known["error"], known["partial_error"] = "", "; ".join(errors)
        geo = run.get("geo")
        if geo:
            geo_by_phone[run.get("phone_tag") or ""] = geo
            merged.setdefault("geo", geo)
    for record in merged["modes"]:
        if record.get("partial_error") and not record["results"]:
            record["error"] = record.pop("partial_error")
        if record.get("parts") == 1:
            record.pop("parts")
    if len(geo_by_phone) > 1:
        merged["geo_by_phone"] = geo_by_phone
    phones = [r.get("phone_tag") for r in runs if r.get("phone_tag")]
    if phones:
        merged["phones"] = phones
    return merged
