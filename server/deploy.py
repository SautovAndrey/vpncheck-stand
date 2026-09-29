"""Выкатить сервер агентов на свой Linux-сервер по SSH: залить server/ и запустить там server/install.sh.

Доступ по SSH берётся из «Подключений» стенда (раздел probe): сервер агентов и пробник ДЦ
могут жить на одной машине. Токен, Telegram, язык и порт прежней установки сохраняются;
админ-токен и Telegram из agent.json стенда передаются установщику, если заданы, - файлом 0600
во временной папке (ENV_FILE), не в командной строке.

    python server/deploy.py                   # поставить или обновить
    python server/deploy.py --behind-proxy    # слушать только 127.0.0.1 (TLS-прокси рядом), порт не открывать
    python server/deploy.py --lang en --port 9000

TLS: install.sh печатает порт и отпечаток сертификата, deploy сверяет отпечаток с cert.pem, прочитанным по SSH,
проверяет, что TLS-порт отвечает отсюда, сохраняет tls_host/tls_port/tls_pin в agent.json и перевыкладывает
подписанный манифест с полем tls - агенты 0.12.9+ переходят на https с проверкой отпечатка.
TLS не поднялся (сбой сети стенда, порт, отпечаток) - манифест НЕ трогается: громкое предупреждение и код выхода 3,
агенты остаются на TLS. Выключить TLS можно только явно: --disable-tls (без TLS-порта, в манифест - "tls": null,
по нему агенты 0.12.11+ возвращаются на http). Ключ сменился - громкое предупреждение (агенты 0.12.11+ перейдут
на новый по манифесту, 0.12.9-0.12.10 - только после переустановки).

    python server/deploy.py --new-tls-key     # новый ключ TLS вместо прежнего (VPNAGENT_TLS_REGENERATE=1)
    python server/deploy.py --disable-tls     # выключить TLS (VPNAGENT_TLS_PORT=0, "tls": null в манифесте)
"""
import argparse
import glob
import json
import os
import re
import sys
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
from stand import agentapi, dcprobe, storage  # noqa: E402

REMOTE_DIR = "/opt/vpnagent"
TLS_PORT_RE = re.compile(r"^TLS port: (\d{1,5})$", re.M)
TLS_PIN_RE = re.compile(r"^TLS pin: (sha256/[A-Za-z0-9+/]{43}=)$", re.M)


class DeployError(Exception):
    pass


def say(ru, en):
    print("* %s / %s" % (ru, en), flush=True)


def payload():
    files = [(os.path.join(HERE, "install.sh"), "server/install.sh"),
             (os.path.join(HERE, "restore.sh"), "server/restore.sh"),
             (os.path.join(HERE, "requirements.txt"), "server/requirements.txt")]
    for path in sorted(glob.glob(os.path.join(HERE, "*.py"))):
        if os.path.basename(path) != "deploy.py":
            files.append((path, "server/" + os.path.basename(path)))
    for path in sorted(glob.glob(os.path.join(HERE, "static", "*"))):
        if os.path.isfile(path):
            files.append((path, "server/static/" + os.path.basename(path)))
    account = os.path.join(HERE, "service-account.json")
    if os.path.exists(account):
        files.append((account, "server/service-account.json"))
    regions = os.path.join(ROOT, "stand", "ui", "assets", "ru_regions.geojson")
    if os.path.exists(regions):
        files.append((regions, "stand/ui/assets/ru_regions.geojson"))
    table = os.path.join(ROOT, "stand", "regions.json")
    if os.path.exists(table):
        files.append((table, "stand/regions.json"))
    files.append((os.path.join(ROOT, "stand", "node_fields.json"), "stand/node_fields.json"))
    return files


def installer_env(current, args):
    env = {}
    if current.get("token"):
        env["ADMIN_TOKEN"] = str(current["token"]).strip()
    for key, name in (("tg_bot_token", "TG_BOT_TOKEN"), ("tg_admin", "TG_ADMIN")):
        if current.get(key):
            env[name] = str(current[key]).strip()
    if args.lang:
        env["VPNCHECK_LANG"] = args.lang
    if args.port:
        env["PORT"] = str(args.port)
    if args.behind_proxy:
        env["BEHIND_PROXY"] = "1"
    if getattr(args, "new_tls_key", False):
        env["VPNAGENT_TLS_REGENERATE"] = "1"
    if getattr(args, "disable_tls", False):
        env["VPNAGENT_TLS_PORT"] = "0"
    return env


def shout(ru, en):
    bar = "!" * 78
    print("%s\n! %s\n! %s\n%s" % (bar, ru, en, bar), flush=True)


def run(client, command, timeout=180):
    out, err, code = dcprobe.run(client, command, timeout=timeout)
    if code != 0:
        text = (err.strip() or out.strip())[-1500:]
        raise DeployError("команда завершилась с кодом %d / command failed with code %d:\n%s" % (code, code, text))
    return out


def env_file_text(env):
    for key, value in env.items():
        if "\n" in value or "\r" in value:
            raise DeployError("перевод строки в %s / line break in %s" % (key, key))
    return "".join("%s=%s\n" % item for item in env.items())


def installer_command(sudo, stage):
    return "%senv ENV_FILE=%s bash %s" % (sudo, dcprobe.shell_quote(stage + "/installer.env"),
                                         dcprobe.shell_quote(stage + "/server/install.sh"))


def upload(client, stage, env):
    files = []
    for local, remote in payload():
        with open(local, "rb") as handle:
            data = handle.read()
        if remote.endswith(".sh"):
            data = data.replace(b"\r\n", b"\n")
        files.append((remote, data))
    files.append(("installer.env", env_file_text(env).encode("utf-8")))
    sftp = client.open_sftp()
    try:
        for sub in ("server", "server/static", "stand", "stand/ui", "stand/ui/assets"):
            sftp.mkdir(stage + "/" + sub, 0o700)
        for remote, data in files:
            target = stage + "/" + remote
            with sftp.open(target, "wb") as handle:
                sftp.chmod(target, 0o600)
                handle.write(data)
    finally:
        sftp.close()


def server_address(current, spec, out):
    if current.get("server"):
        return current["server"], False
    match = re.search(r"OK\. Server: http://(\[[^\]\s]+\]|[^\s:]+):(\d+)", out)
    if not match:
        return "", False
    if match.group(1).startswith("127.") or match.group(1) in ("[::1]", "localhost"):
        return "", True
    return "http://%s:%s" % (spec["host"], match.group(2)), False


def installer_tls(out):
    port, pin = TLS_PORT_RE.search(out), TLS_PIN_RE.search(out)
    if not port or not pin or not 0 < int(port.group(1)) < 65536:
        return None
    return {"port": int(port.group(1)), "pin": pin.group(1)}


def tls_host(server, spec):
    parts = urllib.parse.urlsplit(server)
    if parts.scheme == "http" and parts.hostname:
        return parts.hostname
    return spec["host"]


def setup_tls(server, token, tls, cert_pem, spec):
    """Проверенный TLS - в agent.json и в подписанный манифест. Отпечаток не сошёлся - agent.json не трогаем;
    TLS-порт не отвечает отсюда - стенд всё равно остаётся на TLS: молча уйти на http с админ-токеном хуже,
    чем не подключиться."""
    if not tls or not server or urllib.parse.urlsplit(server).scheme != "http":
        agentapi.save_tls()
        return False
    try:
        pin = agentapi.spki_pin(cert_pem)
    except ValueError:
        pin = ""
    if pin != tls["pin"]:
        say("отпечаток из install.sh не совпал с cert.pem на сервере - TLS в agent.json не меняю",
            "the pin printed by install.sh does not match cert.pem on the server - TLS in agent.json is left as it was")
        return False
    api = agentapi.AgentServer(server, token, tls=tls)
    try:
        api.health()
    except Exception as exc:
        agentapi.save_tls(tls_host(server, spec), tls["port"], tls["pin"])
        shout("TLS-порт %d не отвечает отсюда (%s). Стенд остаётся на TLS (отпечаток %s в agent.json) и не подключится "
              "к центру, пока порт не заработает: откройте его в фаерволе хостера и перевыкатите"
              % (tls["port"], exc, tls["pin"]),
              "TLS port %d is not reachable from here (%s). The stand stays on TLS (pin %s in agent.json) and will not "
              "connect to the center until the port works: open it in the hoster's firewall and redeploy"
              % (tls["port"], exc, tls["pin"]))
        return False
    agentapi.save_tls(tls_host(server, spec), tls["port"], tls["pin"])
    say("TLS: порт %d, отпечаток %s сохранён в agent.json" % (tls["port"], tls["pin"]),
        "TLS: port %d, pin %s saved to agent.json" % (tls["port"], tls["pin"]))
    publish_tls(api)
    return True


def publish_tls(api):
    if not os.path.exists(agentapi.KEY_PATH):
        say("ключа подписи манифеста нет - tls попадёт к агентам с первой выкладкой APK из стенда",
            "no manifest signing key - agents get tls with the first APK published from the stand")
        return
    try:
        manifest = api.state().get("manifest") or {}
        if not manifest:
            say("манифеста ещё нет - tls попадёт к агентам с первой выкладкой APK",
                "no manifest yet - agents get tls with the first APK published")
            return
        if manifest.get("tls") == api.tls:
            return
        api.publish_manifest()
    except Exception as exc:
        say("манифест с tls не выложен: %s - выложите APK из стенда ещё раз" % exc,
            "manifest with tls not published: %s - publish the APK from the stand again" % exc)
        return
    say("манифест перевыложен с tls - агенты 0.12.9+ перейдут на https",
        "manifest republished with tls - agents 0.12.9+ switch to https")


def server_manifest_tls(server, token):
    """tls из текущего манифеста на сервере (None - нет или сервер не ответил)."""
    if not server:
        return None
    try:
        return (agentapi.AgentServer(server, token).state().get("manifest") or {}).get("tls") or None
    except Exception:
        return None


def disable_tls(server, token):
    """Явное выключение (--disable-tls): подписанный манифест с "tls": null - агенты 0.12.11+ по нему возвращаются
    на http. True - перевыложен, False - не нужно, None - нужно, но не вышло (агенты остались на старом манифесте)."""
    agentapi.save_tls()
    if not server:
        return False
    api = agentapi.AgentServer(server, token)
    try:
        manifest = api.state().get("manifest") or {}
        if not manifest or ("tls" in manifest and manifest["tls"] is None):
            return False
        if not os.path.exists(agentapi.KEY_PATH):
            shout("нет ключа подписи манифеста - \"tls\": null не выложен, агенты остаются на старом манифесте",
                  "no manifest signing key - \"tls\": null not published, agents stay on the old manifest")
            return None
        api.publish_manifest(disable_tls=True)
    except Exception as exc:
        shout("манифест с \"tls\": null не выложен: %s - запустите deploy.py --disable-tls ещё раз" % exc,
              "manifest with \"tls\": null not published: %s - run deploy.py --disable-tls again" % exc)
        return None
    say("манифест перевыложен с \"tls\": null - агенты 0.12.11+ вернутся на http",
        "manifest republished with \"tls\": null - agents 0.12.11+ go back to http")
    return True


def tls_failed(previous, tls, server, token):
    """TLS не поднят, хотя был или ожидался: манифест не трогаем (агенты остаются на TLS), громко сообщаем."""
    expected = tls or previous or server_manifest_tls(server, token)
    if not expected:
        return False
    shout("TLS не поднят - манифест на сервере НЕ тронут, агенты с TLS остаются на нём. Исправьте причину выше и "
          "перевыкатите; выключить TLS сознательно - python server/deploy.py --disable-tls",
          "TLS did not come up - the manifest on the server was NOT touched, agents on TLS stay on it. Fix the "
          "cause above and redeploy; to turn TLS off on purpose - python server/deploy.py --disable-tls")
    return True


def warn_tls(previous, tls_on, tls, health):
    """Громкие предупреждения: агенты с закреплённым отпечатком теряют связь или ключ сменился."""
    if previous and not tls_on:
        shout("TLS-порт %d больше не работает (отпечаток %s был в agent.json): агенты 0.12.9-0.12.10 замолчат, пока "
              "TLS не вернут; 0.12.11+ вернутся на http только по манифесту с \"tls\": null (--disable-tls)"
              % (previous["port"], previous["pin"]),
              "TLS port %d is gone (pin %s was in agent.json): agents 0.12.9-0.12.10 go silent until TLS is back; "
              "0.12.11+ go back to http only via a manifest with \"tls\": null (--disable-tls)"
              % (previous["port"], previous["pin"]))
    elif previous and tls and previous["pin"] != tls["pin"]:
        shout("ключ TLS сервера сменился (%s -> %s): агенты 0.12.11+ перейдут на новый по подписанному манифесту, "
              "0.12.9-0.12.10 замолчат до переустановки приложения" % (previous["pin"], tls["pin"]),
              "the server TLS key changed (%s -> %s): agents 0.12.11+ move to it via the signed manifest, "
              "0.12.9-0.12.10 go silent until the app is reinstalled" % (previous["pin"], tls["pin"]))
    if previous and isinstance(health, dict) and health.get("tls") is False:
        shout("сервер говорит tls: false - TLS-порт не поднялся: journalctl -u vpnagent -n 50",
              "the server says tls: false - the TLS port did not start: journalctl -u vpnagent -n 50")


def check_health(server):
    """Ответ /health (словарь) или None, если сервер не отвечает."""
    try:
        with urllib.request.urlopen(server.rstrip("/") + "/health", timeout=15) as response:
            if response.status != 200:
                return None
            answer = json.loads(response.read(65536) or b"{}")
            return answer if isinstance(answer, dict) else {}
    except Exception:
        return None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--behind-proxy", action="store_true",
                        help="listen on 127.0.0.1 only, do not open the port (TLS proxy on the same machine)")
    parser.add_argument("--lang", choices=("ru", "en"), help="server texts language (default: keep, new install - ru)")
    parser.add_argument("--port", type=int, help="listening port (default: keep, new install - 8787)")
    tls_mode = parser.add_mutually_exclusive_group()
    tls_mode.add_argument("--new-tls-key", action="store_true",
                          help="replace the TLS key (agents 0.12.9-0.12.10 pinned to the old one go silent)")
    tls_mode.add_argument("--disable-tls", action="store_true",
                          help='turn TLS off: no TLS port, the manifest gets "tls": null '
                               '(agents 0.12.11+ go back to http)')
    args = parser.parse_args(argv)

    spec = storage.load_connections().get("probe") or {}
    if not spec.get("host"):
        sys.exit("SSH-доступ к серверу не настроен: в стенде Файл → Подключения → сервер-пробник\n"
                 "SSH access is not set up: in the stand File → Connections → probe server")
    current = agentapi.load_agent_config()
    previous = agentapi.tls_for(current.get("server") or "", current)
    env = installer_env(current, args)
    sudo = "" if (spec.get("user") or "root") == "root" else "sudo -n "

    say("подключаюсь к %s" % spec["host"], "connecting to %s" % spec["host"])
    try:
        client = dcprobe.connect(spec)
    except dcprobe.ProbeError as exc:
        sys.exit(str(exc))
    try:
        stage = run(client, "umask 077 && mktemp -d /tmp/vpnagent-src.XXXXXX").strip()
        if not stage.startswith("/tmp/vpnagent-src."):
            raise DeployError("не удалось создать временную папку / could not create a temporary folder: %r" % stage)
        try:
            say("заливаю файлы сервера", "uploading server files")
            upload(client, stage, env)
            say("запускаю install.sh (пакеты, venv, сервис - до нескольких минут)",
                "running install.sh (packages, venv, service - may take a few minutes)")
            out = run(client, installer_command(sudo, stage), timeout=1800)
        finally:
            dcprobe.run(client, "rm -rf " + dcprobe.shell_quote(stage))
        token = run(client, sudo + "cat %s/admin_token" % REMOTE_DIR).strip()
        tls = installer_tls(out)
        cert_pem = dcprobe.run(client, sudo + "cat %s/tls/cert.pem" % REMOTE_DIR)[0] if tls else ""
    except DeployError as exc:
        sys.exit("%s\nустановка не завершена / installation did not finish" % exc)
    finally:
        client.close()

    lines = [line for line in out.splitlines() if line.strip() and not line.startswith(("Admin token", "Токен админа"))]
    print("\n".join(lines[-11:]))
    if not token:
        sys.exit("на сервере нет админ-токена / no admin token on the server: %s/admin_token" % REMOTE_DIR)

    server, local_only = server_address(current, spec, out)
    agentapi.save_agent_config(server, token)
    say("токен сохранён в agent.json стенда", "token saved to the stand's agent.json")
    if local_only or args.behind_proxy or args.disable_tls:
        tls = None
    tls_on = failed = False
    if args.disable_tls:
        failed = disable_tls(server, token) is None
    else:
        tls_on = setup_tls(server, token, tls, cert_pem, spec)
        failed = not tls_on and tls_failed(previous, tls, server, token)
    health = check_health(server) if server and not (local_only or args.behind_proxy) else None
    warn_tls(previous, tls_on, tls, health)
    code = 3 if failed else 0
    if local_only or args.behind_proxy:
        say("сервер слушает только 127.0.0.1 - укажите HTTPS-адрес прокси в Центре управления агентами",
            "the server listens on 127.0.0.1 only - enter the proxy's HTTPS address in the Agent control center")
        return code
    if not server:
        return code
    if health is not None:
        say("сервер отвечает: %s" % server, "server is up: %s" % server)
    else:
        say("%s/health не отвечает отсюда - проверьте фаервол хостера и адрес в Центре управления агентами"
            % server.rstrip("/"),
            "%s/health is not reachable from here - check the hoster's firewall and the address in the "
            "Agent control center" % server.rstrip("/"))
    return code


if __name__ == "__main__":
    sys.exit(main())
