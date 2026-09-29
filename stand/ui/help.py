"""Справка внутри программы: как подготовить и подключить новый телефон."""
from PySide6.QtWidgets import QDialog, QDialogButtonBox, QTextBrowser, QVBoxLayout

from .. import i18n
from ..i18n import t

NEW_PHONE_HTML = """
<h2>Как подключить новый телефон</h2>
<p>Стенд работает с любым телефоном на Android 11 и новее (процессор arm64 - это почти все
телефоны последних лет). Телефонов можно подключить сколько угодно: они проверяются
одновременно, результат сводится в одну таблицу.</p>

<h3>1. Что понадобится</h3>
<ul>
  <li><b>Кабель с передачей данных.</b> Дешёвые «только для зарядки» не подойдут: телефон будет
      заряжаться, а программа его не увидит. Родной кабель от телефона подходит.</li>
  <li><b>Для двух и больше телефонов - USB-хаб с внешним питанием</b> (с блоком питания от 4 А).
      Без него телефонам не хватает тока, и они отваливаются посреди проверки.</li>
</ul>

<h3>2. Подготовка телефона (один раз)</h3>
<ol>
  <li><b>Режим разработчика:</b> Настройки → Сведения о телефоне → Сведения о ПО →
      7 раз нажать «Номер сборки».</li>
  <li><b>Отладка по USB:</b> Настройки → Параметры разработчика → «Отладка по USB» - включить.</li>
  <li>Там же - <b>«Не выключать экран»</b> (при зарядке). Стенд переключает SIM-карты и
      узнаёт баланс нажатиями по экрану, на погасшем экране они не работают.</li>
  <li><b>Блокировка экрана - «Нет».</b> Настройки → Экран блокировки → Тип блокировки.
      С PIN-кодом или графическим ключом стенд не сможет нажимать кнопки.</li>
  <li><b>Samsung: выключить «Автоблокировку».</b> Настройки → Безопасность и
      конфиденциальность → Автоблокировка. Иначе телефон видно, но команды по кабелю не проходят.</li>
  <li><b>Xiaomi, POCO, Redmi:</b> в Параметрах разработчика включить ещё <b>«Отладка по USB (настройки
      безопасности)»</b> и <b>«Установка через USB»</b> - без них стенд не сможет нажимать на экран
      и ставить приложения (нужен вход в Mi-аккаунт и SIM в телефоне).</li>
</ol>

<h3>3. Подключение</h3>
<ol>
  <li>Воткните кабель. На телефоне появится «Разрешить отладку по USB?» - поставьте галочку
      <b>«Всегда разрешать с этого компьютера»</b> и нажмите «Разрешить».</li>
  <li>Телефон сам появится в карточке «Телефон». Если телефонов несколько, в карточке есть
      переключатель - кнопки карточки и экран работают с выбранным.</li>
  <li>Нажмите <b>«Проверить IP»</b>. При первом запуске стенд сам зальёт на телефон xray
      (около 40 МБ), это займёт полминуты.</li>
  <li>Нажмите <b>«узнать баланс, трафик и номера»</b> - программа спросит у операторов номера
      SIM-карт и запомнит их.</li>
</ol>

<h3>4. SIM-карты</h3>
<ul>
  <li>Новая SIM подхватывается сама и появляется отдельной галочкой в «Что проверять».
      <b>Не вставляйте SIM во время проверки</b> - телефон перезапустит связь, замер собьётся.</li>
  <li>При новой SIM Samsung спрашивает, какую карту использовать для звонков и интернета.
      Закройте это окно руками - оно мешает стенду нажимать кнопки.</li>
  <li>Если в телефоне две SIM, стенд сам переключает между ними мобильный интернет.</li>
  <li><b>«Белые списки».</b> Если колонка оператора показывает «белые списки», наружу пускает только
      на разрешённые российские сайты, и VPN-узлы в ней мёртвы не по своей вине. Так бывает
      у новых SIM и при ограничениях мобильного интернета в регионе (чаще ночью). Проверьте баланс;
      для новой SIM помогает меню «Телефон» → «Открыть капчу оператора».</li>
</ul>

<h3>5. Несколько телефонов</h3>
<ul>
  <li>Все отмеченные телефоны проверяются одновременно, проверка из ДЦ идёт отдельно и
      телефоны не занимает.</li>
  <li>Если телефоны подключены к одной точке Wi-Fi, колонка Wi-Fi общая: узлы делятся между
      телефонами поровну, и проверка идёт быстрее.</li>
  <li>Одинаковые модели различаются по концу серийного номера в подписи колонки.</li>
</ul>

<h3>Если телефона не видно</h3>
<ul>
  <li>Поменяйте кабель или порт - чаще всего дело в них.</li>
  <li>Опустите шторку уведомлений на телефоне и выберите режим USB «Передача файлов».</li>
  <li>Запрос «Разрешить отладку» не появился или нажали «Отмена»: Параметры разработчика →
      «Отозвать авторизацию отладки по USB», переподключите кабель и разрешите снова.</li>
  <li>Если телефон периодически отваливается сам - не хватает питания хаба.</li>
</ul>
"""

NEW_PHONE_HTML_EN = """
<h2>How to connect a new phone</h2>
<p>The stand works with any phone on Android 11 or newer (arm64 processor - almost every
phone from recent years). You can connect as many phones as you like: they are checked
at the same time and the results go into one table.</p>

<h3>1. What you need</h3>
<ul>
  <li><b>A data cable.</b> Cheap "charge only" cables will not work: the phone will charge,
      but the program will not see it. The phone's original cable is fine.</li>
  <li><b>For two or more phones - a USB hub with its own power supply</b> (4 A or more).
      Without it the phones do not get enough current and drop off in the middle of a check.</li>
</ul>

<h3>2. Preparing the phone (once)</h3>
<ol>
  <li><b>Developer mode:</b> Settings → About phone → Software information →
      tap "Build number" 7 times.</li>
  <li><b>USB debugging:</b> Settings → Developer options → "USB debugging" - turn on.</li>
  <li>In the same place - <b>"Stay awake"</b> (while charging). The stand switches SIM cards and
      checks the balance by tapping the screen, and taps do not work on a dark screen.</li>
  <li><b>Screen lock - "None".</b> Settings → Lock screen → Screen lock type.
      With a PIN or pattern the stand cannot press buttons.</li>
  <li><b>Samsung: turn off "Auto Blocker".</b> Settings → Security and
      privacy → Auto Blocker. Otherwise the phone is visible, but commands over the cable do not go through.</li>
  <li><b>Xiaomi, POCO, Redmi:</b> in Developer options also turn on <b>"USB debugging (Security
      settings)"</b> and <b>"Install via USB"</b> - without them the stand cannot tap the screen
      or install apps (requires a Mi account sign-in and a SIM in the phone).</li>
</ol>

<h3>3. Connecting</h3>
<ol>
  <li>Plug in the cable. The phone will show "Allow USB debugging?" - tick
      <b>"Always allow from this computer"</b> and tap "Allow".</li>
  <li>The phone will appear in the "Phone" card by itself. If there are several phones, the card has
      a switcher - the card buttons and the screen work with the selected one.</li>
  <li>Press <b>"Check IP"</b>. On the first run the stand uploads xray to the phone
      (about 40 MB), this takes half a minute.</li>
  <li>Press <b>"get balance, data and numbers"</b> - the program will ask the carriers for the
      SIM card numbers and remember them.</li>
</ol>

<h3>4. SIM cards</h3>
<ul>
  <li>A new SIM is picked up automatically and appears as a separate checkbox in "What to check".
      <b>Do not insert a SIM during a check</b> - the phone will restart its connection and the measurement will be off.</li>
  <li>With a new SIM, Samsung asks which card to use for calls and internet.
      Close that window by hand - it keeps the stand from pressing buttons.</li>
  <li>If the phone has two SIMs, the stand switches mobile data between them by itself.</li>
  <li><b>"Whitelist mode".</b> If a carrier column shows "whitelist mode", only approved Russian sites
      are reachable, and the VPN nodes in it are dead through no fault of their own. This happens
      with new SIMs and when mobile internet is restricted in the region (more often at night). Check the balance;
      for a new SIM the "Phone" → "Open carrier captcha" menu helps.</li>
</ul>

<h3>5. Several phones</h3>
<ul>
  <li>All ticked phones are checked at the same time; the check from the DC runs separately and
      does not occupy the phones.</li>
  <li>If the phones are on the same Wi-Fi access point, the Wi-Fi column is shared: nodes are split
      evenly between the phones, and the check goes faster.</li>
  <li>Identical models are told apart by the end of the serial number in the column title.</li>
</ul>

<h3>If the phone is not visible</h3>
<ul>
  <li>Change the cable or the port - that is the most common cause.</li>
  <li>Pull down the notification shade on the phone and choose the "File transfer" USB mode.</li>
  <li>The "Allow debugging" prompt did not appear or you tapped "Cancel": Developer options →
      "Revoke USB debugging authorizations", reconnect the cable and allow again.</li>
  <li>If the phone keeps dropping off by itself - the hub does not have enough power.</li>
</ul>
"""


def new_phone_html():
    """Справка «новый телефон» на языке интерфейса."""
    return NEW_PHONE_HTML_EN if i18n.language() == "en" else NEW_PHONE_HTML


class HelpDialog(QDialog):
    """Окно справки с оформленным текстом (заголовки, списки)."""

    def __init__(self, title, html, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(760, 720)
        layout = QVBoxLayout(self)
        view = QTextBrowser()
        view.setOpenExternalLinks(True)
        view.setStyleSheet("font-family: 'Segoe UI', sans-serif; font-size: 10pt;")
        view.setHtml(html)
        layout.addWidget(view)
        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.button(QDialogButtonBox.Close).setText(t("Закрыть"))
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
