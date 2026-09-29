import base64
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from stand import phone, storage, subscription  # noqa: E402
from stand.xray import socks_config  # noqa: E402

BATTERY = """Current Battery Service state:
  AC powered: false
  USB powered: true
  Wireless powered: false
  status: 2
  health: 2
  present: true
  level: 84
  scale: 100
"""

SIMINFO = """Row: 0 _id=1, sim_id=0, display_name=MegaFon, carrier_name=MegaFon
Row: 1 _id=2, sim_id=1, display_name=MTS RUS, carrier_name=MTS
Row: 2 _id=3, sim_id=-1, display_name=Old card, carrier_name=Tele2
"""

ISUB = """SubscriptionManagerService:
 defaultSubId=1
 defaultDataSubId=2
 defaultVoiceSubId=1
 mAllSubscriptionInfo:
  SubscriptionInfoInternal{id=1 iccId=8970199 simSlotIndex=0 portIndex=0 displayName=MegaFon carrierName=MegaFon displayNameSource=CARRIER mcc=250 mnc=02}
  SubscriptionInfoInternal{id=2 iccId=8970101 simSlotIndex=1 portIndex=0 displayName=MTS RUS carrierName=MTS displayNameSource=USER_INPUT mcc=250 mnc=01}
  SubscriptionInfoInternal{id=3 iccId=8970200 simSlotIndex=-1 portIndex=-1 displayName=Old carrierName=Tele2 displayNameSource=CARRIER}
"""

ISUB_ONEUI = """SubscriptionManagerService:
defaultDataSubId=1
 mAllSubscriptionInfo:
  [SubscriptionInfoInternal: id=1 iccId=897010201[****] simSlotIndex=0 portIndex=0 isEmbedded=0 carrierId=1016 displayName=MegaFon carrierName=MegaFon isOpportunistic=0 groupUuid= displayNameSource=SIM_SPN mcc=250 mnc=02]
  [SubscriptionInfoInternal: id=2 iccId=897010182[****] simSlotIndex=1 portIndex=0 isEmbedded=0 carrierId=1678 displayName=MTS RUS carrierName=MTS RUS isOpportunistic=0 groupUuid= displayNameSource=SIM_SPN mcc=250 mnc=01]
"""

REGISTRY = """Phone Id=0
  mCallState=0
  mSignalStrength=SignalStrength:{mCdma=CellSignalStrengthCdma: cdmaDbm=2147483647 level=0,mLte=CellSignalStrengthLte: rssi=-85 rsrp=-101 rsrq=-9 rssnr=8 level=3 parametersUseForLevel=0,primary=CellSignalStrengthLte: rssi=-85 rsrp=-101 rsrq=-9 level=3}
Phone Id=1
  mCallState=0
  mSignalStrength=SignalStrength:{mLte=CellSignalStrengthLte: rssi=-97 rsrp=-112 level=2,primary=CellSignalStrengthLte: rssi=-97 rsrp=-112 level=2}
"""

WIFI_ON = 'Wifi is enabled\nWifi scanner is only available while wifi is enabled\nWifi is connected to "HomeNet"\n'
WIFI_OFF = "Wifi is disabled\n"

CONNECTIVITY = """Active default network: 105
Current Networks:
  NetworkAgentInfo{ network{104}  handle{...}  ni{[type: MOBILE[LTE]...]}  nc{[ Transports: CELLULAR Capabilities: ...]}
  NetworkAgentInfo{ network{105}  handle{...}  ni{[type: WIFI[]...]}  nc{[ Transports: WIFI Capabilities: SUPL&DUN ...]}
"""

SIM_DIALOG = """<?xml version='1.0' encoding='UTF-8' standalone='yes' ?><hierarchy rotation="0">
<node index="0" text="Megafon1" resource-id="" class="android.widget.CheckedTextView" package="p" content-desc="" checkable="true" checked="true" clickable="true" enabled="true" focusable="true" focused="false" scrollable="false" long-clickable="false" password="false" selected="false" bounds="[19,921][400,1007]" />
<node index="1" text="MTS2" resource-id="" class="android.widget.CheckedTextView" package="p" content-desc="" checkable="true" checked="false" clickable="true" enabled="true" focusable="true" focused="false" scrollable="false" long-clickable="false" password="false" selected="false" bounds="[19,1007][400,1093]" />
<node index="2" text="Выключено" resource-id="" class="android.widget.CheckedTextView" package="p" content-desc="" checkable="true" checked="false" clickable="true" enabled="true" focusable="true" focused="false" scrollable="false" long-clickable="false" password="false" selected="false" bounds="[19,1093][400,1179]" />
<node index="3" text="Мобильные данные" resource-id="android:id/title" class="android.widget.TextView" package="x" content-desc="" checkable="false" checked="false" clickable="false" enabled="true" focusable="false" focused="false" scrollable="false" long-clickable="false" password="false" selected="false" bounds="[53,947][370,991]" />
</hierarchy>"""

VLESS = ("vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?type=tcp&security=reality"
         "&pbk=PUBKEY&fp=chrome&sni=apple.com&sid=abcd12&flow=xtls-rprx-vision&spx=%2F#%F0%9F%87%A9%F0%9F%87%AA%20Germany")


class BatteryTest(unittest.TestCase):
    def test_level_and_charging(self):
        self.assertEqual(phone.parse_battery(BATTERY), (84, True))

    def test_discharging(self):
        text = BATTERY.replace("status: 2", "status: 3").replace("USB powered: true", "USB powered: false")
        self.assertEqual(phone.parse_battery(text), (84, False))


class SimTest(unittest.TestCase):
    def test_content_query_skips_removed_sim(self):
        sims = phone.parse_siminfo_content(SIMINFO)
        self.assertEqual([(s.sub_id, s.slot, s.name, s.carrier) for s in sims],
                         [(1, 0, "MegaFon", "MegaFon"), (2, 1, "MTS RUS", "MTS")])

    def test_isub(self):
        sims, data_sub = phone.parse_isub(ISUB)
        self.assertEqual(data_sub, 2)
        self.assertEqual([(s.sub_id, s.slot, s.name, s.carrier) for s in sims],
                         [(1, 0, "MegaFon", "MegaFon"), (2, 1, "MTS RUS", "MTS")])

    def test_isub_one_ui_8(self):
        sims, data_sub = phone.parse_isub(ISUB_ONEUI)
        self.assertEqual(data_sub, 1)
        self.assertEqual([(s.sub_id, s.slot, s.name, s.carrier) for s in sims],
                         [(1, 0, "MegaFon", "MegaFon"), (2, 1, "MTS RUS", "MTS RUS")])

    def test_signal_levels_per_phone(self):
        self.assertEqual(phone.parse_signal_levels(REGISTRY), {0: 3, 1: 2})

    def test_getprop_list(self):
        self.assertEqual(phone.parse_getprop_list("LTE,Unknown\n"), ["LTE", "Unknown"])


class UiAutomationTest(unittest.TestCase):
    def test_parse_nodes_and_pick_sim(self):
        nodes = phone.parse_ui_nodes(SIM_DIALOG)
        self.assertEqual(len(nodes), 4)
        row = phone.find_node(nodes, phone.DATA_ROW_TITLES)
        self.assertEqual((row["x"], row["y"]), (211, 969))
        self.assertEqual(phone.pick_data_sim_from_dialog(nodes, 0)["text"], "Megafon1")
        self.assertEqual(phone.pick_data_sim_from_dialog(nodes, 1)["text"], "MTS2")
        self.assertIsNone(phone.pick_data_sim_from_dialog(nodes, 2))


class NetworkTest(unittest.TestCase):
    def test_wifi(self):
        self.assertEqual(phone.parse_wifi_status(WIFI_ON), (True, "HomeNet"))
        self.assertEqual(phone.parse_wifi_status(WIFI_OFF), (False, ""))

    def test_active_sub(self):
        text = ("Active default network: 112\n"
                "  NetworkAgentInfo{network{106} ni{MOBILE[LTE] CONNECTED extra: ims} nc{[ Transports: CELLULAR "
                "Specifier: <TelephonyNetworkSpecifier [mSubId = 1]> ]}\n"
                "  NetworkAgentInfo{network{112} ni{MOBILE[LTE] CONNECTED extra: internet.mts.ru} nc{[ Transports: "
                "CELLULAR Specifier: <TelephonyNetworkSpecifier [mSubId = 2]> SubscriptionIds: {2}]}\n")
        self.assertEqual(phone.parse_active_sub(text), 2)
        self.assertEqual(phone.parse_active_sub(text.replace("network: 112", "network: 106")), 1)
        self.assertEqual(phone.parse_active_sub("Active default network: none"), -1)

    def test_transport(self):
        self.assertEqual(phone.parse_transport(CONNECTIVITY), "wifi")
        self.assertEqual(phone.parse_transport(CONNECTIVITY.replace("network: 105", "network: 104")), "cellular")
        self.assertEqual(phone.parse_transport("Active default network: none"), "none")


class SubscriptionTest(unittest.TestCase):
    def test_vless_reality_link(self):
        remark, outbound = subscription.vless_link_to_outbound(VLESS)
        self.assertEqual(remark, "🇩🇪 Germany")
        vnext = outbound["settings"]["vnext"][0]
        self.assertEqual((vnext["address"], vnext["port"]), ("1.2.3.4", 443))
        self.assertEqual(vnext["users"][0]["flow"], "xtls-rprx-vision")
        reality = outbound["streamSettings"]["realitySettings"]
        self.assertEqual((reality["serverName"], reality["publicKey"], reality["shortId"]),
                         ("apple.com", "PUBKEY", "abcd12"))

    def test_bad_link(self):
        self.assertIsNone(subscription.vless_link_to_outbound("vless://garbage"))
        self.assertIsNone(subscription.vless_link_to_outbound("ss://abc"))

    def test_parse_any_base64_links(self):
        raw = base64.b64encode((VLESS + "\n" + VLESS.replace("1.2.3.4", "5.6.7.8").replace("Germany", "NL")).encode())
        targets = subscription.parse_any(raw)
        self.assertEqual([t["key"] for t in targets], ["1.2.3.4:443", "5.6.7.8:443"])
        self.assertEqual(targets[0]["location"], "🇩🇪 Germany")
        self.assertEqual(targets[0]["sni"], "apple.com")

    def test_parse_any_json(self):
        _, outbound = subscription.vless_link_to_outbound(VLESS)
        raw = json.dumps([{"remarks": "DE", "outbounds": [outbound]}])
        targets = subscription.parse_any(raw)
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0]["location"], "DE")

    def test_non_finite_numbers_refused(self):
        _, outbound = subscription.vless_link_to_outbound(VLESS)
        raw = json.dumps([{"remarks": "DE", "outbounds": [outbound]}])
        for value in ("1e400", "-1e999", "Infinity", "NaN"):
            with self.assertRaises(ValueError):
                subscription.parse_any(raw.replace('"port": 443', '"port": 443, "level": %s' % value, 1))

    def test_main_tag_not_string_skips_only_that_node(self):
        _, outbound = subscription.vless_link_to_outbound(VLESS)
        odd = json.loads(json.dumps(outbound))
        odd["tag"] = ["x"]
        odd["settings"]["vnext"][0]["address"] = "5.6.7.8"
        raw = json.dumps([{"remarks": "DE", "outbounds": [outbound]}, {"remarks": "NL", "outbounds": [odd]}])
        self.assertEqual([t["key"] for t in subscription.parse_any(raw)], ["1.2.3.4:443"])
        self.assertEqual([row["location"] for row in subscription.unsupported(raw)], ["NL"])

    def test_non_443_filtered(self):
        link = VLESS.replace(":443?", ":2053?")
        self.assertEqual(subscription.parse_any(link), [])
        self.assertEqual(len(subscription.parse_any(link, only_443=False)), 1)


class XrayConfigTest(unittest.TestCase):
    def test_direct_config(self):
        config = socks_config(10800)
        self.assertEqual(config["inbounds"][0]["port"], 10800)
        self.assertEqual([o["protocol"] for o in config["outbounds"]], ["freedom"])

    def test_node_config_puts_node_first(self):
        _, outbound = subscription.vless_link_to_outbound(VLESS)
        config = socks_config(10811, outbound)
        self.assertEqual([o["protocol"] for o in config["outbounds"]], ["vless", "freedom"])


class StorageTest(unittest.TestCase):
    def test_run_label(self):
        run = {"started": "2026-09-09 12:00:00",
               "targets": [{"key": "a"}, {"key": "b"}],
               "modes": [{"id": "sim1", "label": "MegaFon", "results": {"a": {"exit_ip": "1.1.1.1"}, "b": {"exit_ip": ""}}},
                         {"id": "wifi", "label": "Wi-Fi", "results": {}}]}
        self.assertEqual(storage.run_label(run), "2026-09-09 12:00:00 - MegaFon 1/2, Wi-Fi 0/2")

    def test_run_label_names_subscription_source(self):
        from stand import i18n
        run = {"started": "2026-09-09 12:00:00", "targets": [], "modes": [], "panel": "url", "squad": "sub.example"}
        old = i18n.language()
        i18n.set_language("en")
        try:
            self.assertTrue(storage.run_label(run).startswith("Subscription URL/sub.example · "))
            self.assertTrue(storage.run_label(dict(run, panel="подписка")).startswith("subscription/"))
            self.assertTrue(storage.run_label(dict(run, panel="mypanel")).startswith("mypanel/"))
        finally:
            i18n.set_language(old)


SMS_DUMP = """Row: 0 address=MegaFon, date=1790148508956, sub_id=1, body=Остатки по тарифу:
Интернет - доступно 40 ГБ до 08.10.2026 19:37, Минуты - 800 мин.
Row: 1 address=Balance, date=1790148471975, sub_id=2, body=Баланс:75,05р

// Подключите МТС Premium за 99 руб/мес"""


class SmsAndUssdTest(unittest.TestCase):
    def test_body_with_commas_and_newlines_survives(self):
        messages = phone.parse_sms_rows(SMS_DUMP)
        self.assertEqual(len(messages), 2)
        self.assertEqual(messages[0]["sub_id"], 1)
        self.assertIn("40 ГБ", messages[0]["body"])
        self.assertIn("\n", messages[0]["body"])
        self.assertTrue(messages[1]["body"].startswith("Баланс:75,05р"))

    def test_garbage_rows_are_skipped(self):
        self.assertEqual(phone.parse_sms_rows(""), [])
        self.assertEqual(phone.parse_sms_rows("No result found."), [])

    def test_codes_per_operator(self):
        self.assertEqual(phone.ussd_codes_for("MegaFon")[1][1], "*558#")
        self.assertEqual(phone.ussd_codes_for("MTS RUS")[1][1], "*217#")
        self.assertEqual(phone.ussd_codes_for("beeline")[0][1], "*102#")
        self.assertEqual(len(phone.ussd_codes_for("Неизвестный")), 1)

    def test_dialer_sim_matching(self):
        self.assertTrue(phone.same_sim("Megafon1", "MegaFon"))
        self.assertTrue(phone.same_sim("MTS2", "MTS RUS"))
        self.assertFalse(phone.same_sim("Megafon1", "MTS RUS"))
        self.assertFalse(phone.same_sim("", "MTS"))

    def test_stub_answers_are_not_real_numbers(self):
        self.assertTrue(phone.answer_is_stub("Ваша заявка принята. Ожидайте SMS с результатом."))
        self.assertTrue(phone.answer_is_stub("Спасибо за обращение! Мы направим ответ в SMS"))
        self.assertFalse(phone.answer_is_stub("Ваш баланс: 105 руб."))

    def test_phone_number_from_any_operator_format(self):
        cases = {
            "Ваш номер: +7 926 123-45-67": "+79261234567",
            "Ваш номер 89261234567": "+79261234567",
            "Номер: 7(926)1234567": "+79261234567",
            "Ваш абонентский номер - +7-926-123-45-67.": "+79261234567",
            "Мой основной номер: 9201234567": "+79201234567",
        }
        for text, expected in cases.items():
            self.assertEqual(phone.extract_phone_number(text), expected, text)

    def test_no_number_in_text(self):
        self.assertEqual(phone.extract_phone_number("Баланс: 105 руб."), "")
        self.assertEqual(phone.extract_phone_number(""), "")
        self.assertEqual(phone.extract_phone_number("код 92012345671234"), "")

    def test_number_codes_per_operator(self):
        self.assertEqual(phone.number_code_for("MegaFon"), "*205#")
        self.assertEqual(phone.number_code_for("MTS RUS"), "*111*0887#")
        self.assertIsNone(phone.number_code_for("Неизвестный"))

    def test_sim_key_is_stable(self):
        sim = phone.Sim(sub_id=2, slot=1, name="MTS RUS")
        self.assertEqual(phone.sim_key(sim), "1:mts rus")
        self.assertEqual(phone.sim_key(sim, "R58X1234ABC"), "R58X1234ABC|1:mts rus")

    def test_saved_number_never_borrows_neighbours_number(self):
        sim = phone.Sim(sub_id=1, slot=0, name="MegaFon")
        old = {"0:megafon": "+79201234567"}
        self.assertEqual(phone.saved_number(old, sim, "AAA", only_phone=True), "+79201234567")
        self.assertEqual(phone.saved_number(old, sim, "BBB", only_phone=False), "")
        mine = {"BBB|0:megafon": "+79000000000"}
        self.assertEqual(phone.saved_number(mine, sim, "BBB", only_phone=False), "+79000000000")

    def test_balance_from_real_operator_answers(self):
        cases = {"Баланс:75,05р": 75.05, "Ваш баланс: 105 руб.": 105.0, "баланс: 910 р.": 910.0,
                 "Ваш баланс: -12,50 руб.": -12.5, "Баланс 1 020,06 р": 1020.06,
                 "Баланс:1020,06р // Кубик за 49 руб./мес": 1020.06}
        for text, amount in cases.items():
            self.assertAlmostEqual(phone.parse_balance(text), amount, msg=text)
        self.assertIsNone(phone.parse_balance("Интернет 40 ГБ до 08.10.2026"))
        self.assertIsNone(phone.parse_balance("проверено 20 раз"))

    def test_whitelist_verdict(self):
        self.assertIn("кончились деньги", phone.whitelist_verdict("Ваш баланс: -12,50 руб."))
        self.assertIn("деньги есть", phone.whitelist_verdict("баланс: 910 р."))
        self.assertIn("не удалось", phone.whitelist_verdict(""))

    def test_ussd_answer_skips_buttons_and_progress(self):
        nodes = [{"text": "OK"}, {"text": "Выполнение кода USSD…"}, {"text": "Ваш баланс: 105 руб."}]
        self.assertEqual(phone.ussd_answer(nodes), "Ваш баланс: 105 руб.")
        self.assertEqual(phone.ussd_answer([{"text": "OK"}]), "")


if __name__ == "__main__":
    unittest.main()
