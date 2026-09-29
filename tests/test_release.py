import argparse
import hashlib
import io
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
import zipfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "server"))
sys.path.insert(0, ROOT)

import deploy  # noqa: E402
from tools import fetch_binaries, i18n_check, make_public  # noqa: E402

FAKES = {
    "id": '#!/bin/bash\nif [ "$1" = "-u" ] && [ -n "$2" ]; then\n'
          '  [ -f "$SBX/user_$2" ] && echo 999 && exit 0; exit 1\nfi\necho 0\n',
    "useradd": '#!/bin/bash\ntouch "$SBX/user_${@: -1}"\n',
    "systemctl": '#!/bin/bash\necho "systemctl $*" >> "$SBX/log"\n'
                 'if [ "$1" = "is-active" ]; then [ -f "$SBX/active" ]; exit $?; fi\n'
                 '[ "$1" = "restart" ] && touch "$SBX/active"\n[ "$1" = "stop" ] && rm -f "$SBX/active"\nexit 0\n',
    "apt-get": "#!/bin/bash\nexit 0\n",
    "curl": '#!/bin/bash\necho "curl $*" >> "$SBX/log"\ncase "$*" in *ipify*) echo 203.0.113.10;; esac\nexit 0\n',
    "ufw": '#!/bin/bash\necho "ufw $*" >> "$SBX/log"\n[ "$1" = "status" ] && echo "Status: active"\nexit 0\n',
    "chown": '#!/bin/bash\necho "chown $*" >> "$SBX/log"\n'
             '[ "$1" = "-h" ] && [ "$3" = "$VPNAGENT_DIR" ] && rm -f "$SBX/foreign_owner"\nexit 0\n',
    "stat": '#!/bin/bash\nflag=foreign_data; [ "${@: -1}" = "$VPNAGENT_DIR" ] && flag=foreign_owner\n'
            'if [ -f "$SBX/$flag" ]; then echo 999; else echo 0; fi\n',
    "python3": '#!/bin/bash\nif [ "$1" = "-c" ]; then [ ! -f "$SBX/old_python" ]; exit $?; fi\n'
               'if [ "$1" = "-V" ]; then echo "Python 3.8.10"; exit 0; fi\n'
               'if [ "$1" = "-m" ] && [ "$2" = "venv" ]; then mkdir -p "$3/bin"; '
               'printf \'#!/bin/bash\\nexit 0\\n\' > "$3/bin/pip"; chmod +x "$3/bin/pip"; fi\n',
}
SETTINGS = ("ADMIN_TOKEN", "VPNCHECK_LANG", "TG_BOT_TOKEN", "TG_ADMIN", "PORT", "HOST", "BEHIND_PROXY", "ENV_FILE",
            "VPNAGENT_TLS_PORT", "TLS_NAME", "VPNAGENT_TLS_REGENERATE")


def find_bash():
    path = shutil.which("bash")
    if not path or "system32" in path.lower():
        git = shutil.which("git")
        candidate = os.path.join(os.path.dirname(os.path.dirname(git)), "bin", "bash.exe") if git else ""
        return candidate if candidate and os.path.exists(candidate) else None
    return path


def posix(path):
    return str(path).replace("\\", "/")


@pytest.fixture
def sandbox(tmp_path):
    bash = find_bash()
    if not bash:
        pytest.skip("bash is not available")
    fake = tmp_path / "bin"
    fake.mkdir()
    for name, body in FAKES.items():
        path = fake / name
        path.write_bytes(body.encode())
        path.chmod(0o755)
    source = tmp_path / "src" / "server"
    (source / "static").mkdir(parents=True)
    for name in ("install.sh", "restore.sh", "app.py", "fcm.py", "run.py", "requirements.txt"):
        data = open(os.path.join(ROOT, "server", name), "rb").read().replace(b"\r\n", b"\n")
        (source / name).write_bytes(data)
    (source / "static" / "admin.html").write_text("x")
    (tmp_path / "src" / "stand").mkdir()
    shutil.copy(os.path.join(ROOT, "stand", "node_fields.json"), tmp_path / "src" / "stand" / "node_fields.json")
    target, unit = tmp_path / "opt" / "vpnagent", tmp_path / "vpnagent.service"
    (tmp_path / "sysctl.d").mkdir()

    def run(ok=True, **extra):
        env = dict(os.environ, SBX=posix(tmp_path), VPNAGENT_DIR=posix(target), VPNAGENT_UNIT=posix(unit),
                   VPNAGENT_SYSCTL=posix(tmp_path / "sysctl.d" / "90-vpnagent.conf"),
                   PATH=str(fake) + os.pathsep + os.environ["PATH"])
        for key in SETTINGS:
            env.pop(key, None)
        env.update(extra)
        result = subprocess.run([bash, str(source / "install.sh")], env=env, capture_output=True, text=True,
                                encoding="utf-8")
        if not ok:
            return result
        assert result.returncode == 0, result.stderr + result.stdout
        values = dict(line.split("=", 1) for line in (target / "env").read_text().splitlines() if "=" in line)
        return values, unit.read_text(), result.stdout + result.stderr

    return tmp_path, target, unit, run


def log_of(tmp_path):
    path = tmp_path / "log"
    return path.read_text() if path.exists() else ""


def test_install_keeps_old_deploy_env(sandbox):
    tmp_path, target, unit, run = sandbox
    target.mkdir(parents=True)
    (target / "env").write_text("ADMIN_TOKEN=livetoken\nTG_BOT_TOKEN=1:AAA\nTG_ADMIN=42\n")
    (target / "agents.db").write_text("db")
    unit.write_text("[Service]\nExecStart=/x/uvicorn app:app --host 0.0.0.0 --port 8787 --proxy-headers\n")
    (tmp_path / "active").write_text("")
    env, unit_text, out = run()
    assert env["ADMIN_TOKEN"] == "livetoken" and env["TG_BOT_TOKEN"] == "1:AAA" and env["TG_ADMIN"] == "42"
    assert env["VPNCHECK_LANG"] == "ru"
    assert (target / "admin_token").read_text().strip() == "livetoken"
    assert (target / "data" / "agents.db").read_text() == "db" and not (target / "agents.db").exists()
    assert "User=vpnagent" in unit_text and "--host 0.0.0.0 --port 8787" in unit_text
    assert "/venv/bin/python %s/run.py --host" % posix(target) in unit_text and "uvicorn" not in unit_text
    assert "MemoryMax=1500M" in unit_text and (target / "run.py").exists()
    log = log_of(tmp_path)
    assert log.index("systemctl stop") < log.index("chown -R -h vpnagent:vpnagent") < log.index("systemctl restart")
    assert "livetoken" in out


def test_install_rerun_keeps_settings(sandbox):
    tmp_path, target, _unit, run = sandbox
    first, _, _ = run(VPNCHECK_LANG="en", PORT="9000", TG_BOT_TOKEN="1:AAA", TG_ADMIN="42")
    with open(target / "env", "a") as handle:
        handle.write("VPNAGENT_MAX_DB_MB=500\nLD_PRELOAD=/tmp/x.so\nPYTHONPATH=/opt/vpnagent/data\n")
    again, unit_text, out = run()
    assert again["ADMIN_TOKEN"] == first["ADMIN_TOKEN"] and len(first["ADMIN_TOKEN"]) == 48
    assert again["VPNCHECK_LANG"] == "en" and again["TG_BOT_TOKEN"] == "1:AAA"
    assert again["VPNAGENT_MAX_DB_MB"] == "500"
    assert "LD_PRELOAD" not in again and "PYTHONPATH" not in again and "LD_PRELOAD PYTHONPATH" in out
    assert "--port 9000" in unit_text
    proxied, unit_text, out = run(BEHIND_PROXY="1")
    assert "--host 127.0.0.1 --port 9000" in unit_text and "local only" in out
    _, unit_text, _ = run()
    assert "--host 127.0.0.1" in unit_text
    rotated, _, _ = run(ADMIN_TOKEN="rotated", TG_BOT_TOKEN="")
    assert rotated["ADMIN_TOKEN"] == "rotated" and rotated["TG_BOT_TOKEN"] == "" and rotated["TG_ADMIN"] == "42"
    _, unit_text, _ = run(BEHIND_PROXY="0")
    assert "--host 0.0.0.0 --port 9000" in unit_text
    assert "chown -R" not in log_of(tmp_path)


def test_install_unit_layout_and_hardening(sandbox):
    tmp_path, target, _unit, run = sandbox
    _, unit_text, out = run()
    data = posix(target / "data")
    assert "Environment=VPNAGENT_DATA=%s\n" % data in unit_text
    assert "ReadWritePaths=%s\n" % data in unit_text
    for line in ("ProtectSystem=strict", "ProtectHome=yes", "PrivateDevices=yes", "ProtectKernelTunables=yes",
                 "ProtectKernelModules=yes", "ProtectControlGroups=yes", "CapabilityBoundingSet=\n",
                 "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX", "LockPersonality=yes", "NoNewPrivileges=yes"):
        assert line in unit_text
    assert (target / "data" / "files").is_dir() and (target / "app.py").exists()
    assert not [name for name in os.listdir(target) if name.startswith(".")]
    log = log_of(tmp_path)
    assert "chown -h root:vpnagent %s" % posix(target) in log
    assert "curl -fs http://127.0.0.1:8787/health" in log


def test_install_health_check_follows_host(sandbox):
    tmp_path, _target, _unit, run = sandbox
    _, _, out = run(HOST="::1")
    assert "curl -fs http://[::1]:8787/health" in log_of(tmp_path) and "local only" in out
    _, _, out = run(HOST="192.0.2.5")
    assert "curl -fs http://192.0.2.5:8787/health" in log_of(tmp_path)


def test_install_migrates_round2_layout(sandbox):
    tmp_path, target, unit, run = sandbox
    target.mkdir(parents=True)
    db = sqlite3.connect(str(target / "agents.db"))
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA wal_autocheckpoint=0")
    db.execute("CREATE TABLE agents (agent_id TEXT)")
    db.executemany("INSERT INTO agents VALUES (?)", [("a1",), ("a2",), ("a3",)])
    db.commit()
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    for name in ("agents.db", "agents.db-wal", "agents.db-shm"):
        shutil.copyfile(target / name, snapshot / name)
    db.close()
    for name in ("agents.db", "agents.db-wal", "agents.db-shm"):
        shutil.copyfile(snapshot / name, target / name)
    assert (target / "agents.db-wal").stat().st_size > 0
    (target / "state.json").write_text('{"nodes": {"n1": 1}}')
    (target / "backups").mkdir()
    (target / "backups" / "agents-1.db").write_text("backup")
    (target / "files").mkdir()
    (target / "files" / "agent.apk").write_text("apk")
    (target / "service-account.json").write_text("{}")
    (target / "static").mkdir()
    (target / "static" / "old.js").write_text("old")
    (target / "venv" / "bin").mkdir(parents=True)
    (target / "venv" / "bin" / "planted").write_text("x")
    (target / "__pycache__").mkdir()
    (target / "fastapi").mkdir()
    (target / "fastapi" / "__init__.py").write_text("planted")
    (target / "sitecustomize.py").write_text("planted")
    (target / "notes.txt").write_text("keep me")
    (target / "env.new").write_text("stale")
    (target / "app.py").write_text("old app")
    (target / "admin_token").write_text("livetoken\n")
    (target / "env").write_text("ADMIN_TOKEN=livetoken\nVPNCHECK_LANG=en\nTG_BOT_TOKEN=1:AAA\nTG_ADMIN=42\n"
                                "HTTPS_PROXY=http://proxy\n")
    unit.write_text("[Service]\nUser=vpnagent\nWorkingDirectory=/opt/vpnagent\nEnvironmentFile=/opt/vpnagent/env\n"
                    "ExecStart=/opt/vpnagent/venv/bin/uvicorn app:app --host 0.0.0.0 --port 9000 --proxy-headers\n"
                    "ProtectSystem=strict\nReadWritePaths=/opt/vpnagent\n")
    (tmp_path / "user_vpnagent").write_text("")
    (tmp_path / "foreign_owner").write_text("")
    (tmp_path / "active").write_text("")

    env, unit_text, out = run()

    data = target / "data"
    assert env["ADMIN_TOKEN"] == "livetoken" and env["VPNCHECK_LANG"] == "en"
    assert env["TG_BOT_TOKEN"] == "1:AAA" and env["TG_ADMIN"] == "42" and env["HTTPS_PROXY"] == "http://proxy"
    assert "VPNAGENT_DATA" not in env
    assert (target / "admin_token").read_text().strip() == "livetoken"
    assert "--host 0.0.0.0 --port 9000" in unit_text and "ReadWritePaths=%s\n" % posix(data) in unit_text
    moved = sqlite3.connect(str(data / "agents.db"))
    assert moved.execute("SELECT COUNT(*) FROM agents").fetchone()[0] == 3
    moved.close()
    assert (data / "state.json").read_text() == '{"nodes": {"n1": 1}}'
    assert (data / "backups" / "agents-1.db").read_text() == "backup"
    assert (data / "files" / "agent.apk").read_text() == "apk"
    assert (data / "service-account.json").read_text() == "{}"
    assert (data / "old-install" / "notes.txt").read_text() == "keep me"
    assert (data / "old-install" / "fastapi").is_dir() and (data / "old-install" / "env.new").exists()
    assert sorted(os.listdir(target)) == ["admin_token", "app.py", "data", "env", "fcm.py", "node_fields.json",
                                          "requirements.txt", "restore.sh", "run.py", "static", "tls", "venv"]
    assert (target / "app.py").read_text() != "old app"
    assert os.listdir(target / "static") == ["admin.html"]
    assert not (target / "venv" / "bin" / "planted").exists()
    log = log_of(tmp_path)
    assert log.index("systemctl stop vpnagent") < log.index("chown -R -h vpnagent:vpnagent")
    assert log.index("chown -R -h vpnagent:vpnagent") < log.index("systemctl restart vpnagent")
    assert "old layout" in out and not (tmp_path / "foreign_owner").exists()

    again, unit_again, out = run()
    assert again == env and unit_again == unit_text and "old layout" not in out
    assert (data / "state.json").exists() and (data / "agents.db").exists()


def test_install_token_env_wins_over_file(sandbox):
    _tmp, target, unit, run = sandbox
    (target / "data").mkdir(parents=True)
    (target / "admin_token").write_text("tokenX\n")
    (target / "env").write_text("ADMIN_TOKEN=tokenY\nTG_BOT_TOKEN=1:AAA\nTG_ADMIN=42\n")
    env, _, out = run()
    assert env["ADMIN_TOKEN"] == "tokenY" and (target / "admin_token").read_text().strip() == "tokenY"
    assert "differs" in out


def test_install_reads_env_file(sandbox):
    tmp_path, _target, _unit, run = sandbox
    settings = tmp_path / "installer.env"
    settings.write_bytes(b"ADMIN_TOKEN=fromfile\r\nTG_BOT_TOKEN=1:BBB\nPORT=9100\nEVIL=1\nPATH=/nowhere\n")
    env, unit_text, _ = run(ENV_FILE=posix(settings))
    assert env["ADMIN_TOKEN"] == "fromfile" and env["TG_BOT_TOKEN"] == "1:BBB" and "EVIL" not in env
    assert "--port 9100" in unit_text and not settings.exists()


def test_install_refuses_old_python_and_bad_values(sandbox):
    tmp_path, target, _unit, run = sandbox
    (tmp_path / "old_python").write_text("")
    result = run(ok=False)
    assert result.returncode != 0 and "Python 3.10+" in result.stderr and not target.exists()
    (tmp_path / "old_python").unlink()
    assert run(ok=False, PORT="80a").returncode != 0 and not target.exists()
    assert run(ok=False, ADMIN_TOKEN="a b").returncode != 0 and not target.exists()
    assert run(ok=False, HOST="1.2.3.4;id").returncode != 0 and not target.exists()


def test_install_refuses_symlinked_env(sandbox):
    _tmp, target, _unit, run = sandbox
    target.mkdir(parents=True)
    try:
        os.symlink(str(target / "elsewhere"), str(target / "env"))
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available")
    result = run(ok=False)
    assert result.returncode != 0 and "symbolic link" in result.stderr


@pytest.mark.parametrize("name", ["env", "admin_token"])
def test_install_refuses_env_or_token_folder(sandbox, name):
    tmp_path, target, _unit, run = sandbox
    (target / name).mkdir(parents=True)
    (target / name / "a").write_text("LD_PRELOAD=/x")
    (target / "agents.db").write_text("old db")
    (tmp_path / "active").write_text("")
    result = run(ok=False)
    assert result.returncode != 0 and "not a regular file" in result.stderr
    assert (target / name / "a").exists() and (target / "agents.db").read_text() == "old db"
    assert "systemctl start vpnagent" in log_of(tmp_path)


def new_layout(tmp_path, target, unit):
    data = target / "data"
    (data / "files").mkdir(parents=True)
    (data / "backups").mkdir()
    (data / "agents.db").write_text("live db")
    (data / "state.json").write_text('{"nodes": {"n1": 1}}')
    (data / "files" / "agent.apk").write_text("apk")
    (data / "service-account.json").write_text("{}")
    (target / "app.py").write_text("old app")
    (target / "admin_token").write_text("livetoken\n")
    (target / "env").write_text("ADMIN_TOKEN=livetoken\nVPNCHECK_LANG=ru\nTG_BOT_TOKEN=1:AAA\nTG_ADMIN=42\n"
                                "VPNAGENT_MAX_DB_MB=3000\n")
    unit.write_text("[Service]\nUser=vpnagent\nGroup=vpnagent\nWorkingDirectory=/opt/vpnagent\n"
                    "Environment=VPNAGENT_DATA=/opt/vpnagent/data\nEnvironmentFile=/opt/vpnagent/env\n"
                    "ExecStart=/opt/vpnagent/venv/bin/uvicorn app:app --host 0.0.0.0 --port 8787 --proxy-headers\n")
    (tmp_path / "user_vpnagent").write_text("")
    (tmp_path / "active").write_text("")
    return data


def test_install_rerun_on_new_layout_keeps_data(sandbox):
    tmp_path, target, unit, run = sandbox
    data = new_layout(tmp_path, target, unit)
    env, unit_text, out = run()
    assert "old layout" not in out and "dropped" not in out
    assert env == {"ADMIN_TOKEN": "livetoken", "VPNCHECK_LANG": "ru", "TG_BOT_TOKEN": "1:AAA", "TG_ADMIN": "42",
                   "VPNAGENT_MAX_DB_MB": "3000"}
    assert (data / "agents.db").read_text() == "live db" and (data / "state.json").exists()
    assert (data / "files" / "agent.apk").read_text() == "apk" and (data / "service-account.json").exists()
    assert not (data / "old-install").exists() and (target / "app.py").read_text() != "old app"
    assert "/run.py --host 0.0.0.0 --port 8787 --tls-port 8788 --tls-cert " in unit_text
    assert "/tls/key.pem --limit-concurrency 5000" in unit_text
    log = log_of(tmp_path)
    assert "chown -R" not in log and log.index("systemctl stop vpnagent") < log.index("systemctl restart vpnagent")
    sysctl = tmp_path / "sysctl.d" / "90-vpnagent.conf"
    assert "net.ipv4.tcp_keepalive_time=180" in sysctl.read_text()
    sysctl.write_text("own\n")
    run()
    assert sysctl.read_text() == "own\n"


def test_install_finishes_interrupted_migration(sandbox):
    tmp_path, target, unit, run = sandbox
    data = new_layout(tmp_path, target, unit)
    (tmp_path / "foreign_data").write_text("")
    (target / "agents.db").write_text("stale db")
    (target / "agents.db-wal").write_text("wal")
    _env, _unit_text, out = run()
    assert "old layout" in out
    assert (data / "agents.db").read_text() == "live db" and (data / "agents.db-wal").read_text() == "wal"
    assert (data / "old-install" / "agents.db").read_text() == "stale db"
    assert not (target / "agents.db").exists() and not (target / "agents.db-wal").exists()
    assert (data / "files" / "agent.apk").read_text() == "apk" and not (data / "old-install" / "data").exists()


def test_install_sets_aside_foreign_data_folder(sandbox):
    tmp_path, target, _unit, run = sandbox
    (target / "data").mkdir(parents=True)
    (target / "data" / "agents.db").write_text("planted")
    (target / "data" / "old-install").mkdir()
    (target / "data" / "old-install" / "x").write_text("planted")
    (target / "agents.db").write_text("real db")
    (target / "evil.sh").write_text("echo")
    (tmp_path / "user_vpnagent").write_text("")
    (tmp_path / "foreign_owner").write_text("")
    (tmp_path / "foreign_data").write_text("")
    run()
    data = target / "data"
    assert (data / "agents.db").read_text() == "real db"
    assert (data / "old-install" / "data" / "agents.db").read_text() == "planted"
    assert (data / "old-install" / "evil.sh").exists() and not (target / "evil.sh").exists()
    assert not [name for name in os.listdir(target) if name.startswith(".")]


def test_install_restarts_service_after_late_failure(sandbox):
    tmp_path, target, unit, run = sandbox
    new_layout(tmp_path, target, unit)
    unit.write_text("[Service]\nExecStart=/x/uvicorn app:app --host 0.0.0.0 --port 80a\n")
    result = run(ok=False)
    assert result.returncode != 0 and "bad PORT" in result.stderr
    log = log_of(tmp_path)
    assert log.index("systemctl stop vpnagent") < log.index("systemctl start vpnagent")
    assert (target / "data" / "agents.db").read_text() == "live db"


def test_install_telegram_line_and_test_message(sandbox):
    tmp_path, target, _unit, run = sandbox
    _, _, out = run()
    assert "Telegram alerts: off - set TG_BOT_TOKEN and TG_ADMIN" in out
    assert "sendMessage" not in log_of(tmp_path)
    assert (target / "restore.sh").read_bytes() == (tmp_path / "src" / "server" / "restore.sh").read_bytes()
    fake = tmp_path / "bin" / "curl"
    fake.write_bytes(b'#!/bin/bash\necho "curl $*" >> "$SBX/log"\n'
                     b'case "$*" in *"-K -"*) cat > "$SBX/tgcfg"; echo "{\\"ok\\":true}";; esac\nexit 0\n')
    _, _, out = run(TG_BOT_TOKEN="123:SECRET", TG_ADMIN="-100500", VPNCHECK_LANG="en")
    assert "Telegram alerts: on (a test message was sent)" in out
    assert "bot123:SECRET/sendMessage" in (tmp_path / "tgcfg").read_text()
    log = log_of(tmp_path)
    assert "SECRET" not in log and "chat_id=-100500" in log and "test message from the installer" in log
    fake.write_bytes(b'#!/bin/bash\ncase "$*" in *"-K -"*) cat >/dev/null; '
                     b'echo "{\\"ok\\":false,\\"description\\":\\"Bad Request: chat not found\\"}";; esac\n'
                     b'exit 0\n')
    _, _, out = run()
    assert "test message failed - Bad Request: chat not found" in out
    assert "\u043f\u0440\u043e\u0431\u043d\u043e\u0435" in out


@pytest.fixture
def restore_box(sandbox):
    tmp_path, _target, _unit, _run = sandbox
    data = tmp_path / "opt" / "vpnagent" / "data"
    (data / "backups").mkdir(parents=True)
    (data / "agents.db").write_text("live db")
    (data / "agents.db-wal").write_text("live wal")
    (tmp_path / "active").write_text("")
    bash = find_bash()

    def run(*args):
        env = dict(os.environ, SBX=posix(tmp_path), VPNAGENT_DIR=posix(tmp_path / "opt" / "vpnagent"),
                   VPNAGENT_UNIT=posix(tmp_path / "vpnagent.service"),
                   PATH=str(tmp_path / "bin") + os.pathsep + os.environ["PATH"])
        return subprocess.run([bash, str(tmp_path / "src" / "server" / "restore.sh"), *args], env=env,
                              capture_output=True, text=True, encoding="utf-8")

    return tmp_path, data, run


def test_restore_lists_backups_without_argument(restore_box):
    tmp_path, data, run = restore_box
    (data / "backups" / "agents-20260927.db.gz").write_bytes(b"")
    result = run()
    assert result.returncode != 0 and "agents-20260927.db.gz" in result.stdout
    assert "systemctl" not in log_of(tmp_path)


@pytest.mark.parametrize("name", ["20260926", "agents-20260925.db.gz"])
def test_restore_refuses_bad_backup_without_stopping(restore_box, name):
    tmp_path, data, run = restore_box
    (data / "backups" / "agents-20260926.db.gz").write_bytes(b"\x1f\x8b\x08\x00broken")
    result = run(name)
    assert result.returncode != 0
    assert "systemctl" not in log_of(tmp_path)
    assert (data / "agents.db").read_text() == "live db" and (data / "agents.db-wal").read_text() == "live wal"
    assert not [path for path in os.listdir(data) + os.listdir(data.parent) if path.startswith(".restore")]


def test_deploy_passes_only_known_settings():
    args = argparse.Namespace(lang=None, port=None, behind_proxy=False)
    assert deploy.installer_env({"server": "", "token": ""}, args) == {}
    env = deploy.installer_env({"token": "t", "tg_bot_token": "1:A", "tg_admin": 42},
                               argparse.Namespace(lang="en", port=9000, behind_proxy=True))
    assert env == {"ADMIN_TOKEN": "t", "TG_BOT_TOKEN": "1:A", "TG_ADMIN": "42", "VPNCHECK_LANG": "en",
                   "PORT": "9000", "BEHIND_PROXY": "1"}


def test_deploy_keeps_secrets_out_of_command_line():
    env = {"ADMIN_TOKEN": "secret-token", "TG_BOT_TOKEN": "1:A"}
    assert deploy.env_file_text(env) == "ADMIN_TOKEN=secret-token\nTG_BOT_TOKEN=1:A\n"
    command = deploy.installer_command("sudo -n ", "/tmp/vpnagent-src.abc")
    assert command == "sudo -n env ENV_FILE='/tmp/vpnagent-src.abc/installer.env' " \
                      "bash '/tmp/vpnagent-src.abc/server/install.sh'"
    assert "secret" not in command
    with pytest.raises(deploy.DeployError):
        deploy.env_file_text({"ADMIN_TOKEN": "a\nPATH=/x"})


def test_deploy_keeps_existing_server_address():
    out = "OK. Server: http://198.51.100.7:9000\n"
    spec = {"host": "203.0.113.10"}
    assert deploy.server_address({"server": "https://agents.example.com"}, spec, out) == \
        ("https://agents.example.com", False)
    assert deploy.server_address({}, spec, out) == ("http://203.0.113.10:9000", False)
    assert deploy.server_address({}, spec, "OK. Server: http://127.0.0.1:8787 (local only)") == ("", True)
    assert deploy.server_address({}, spec, "OK. Server: http://[::1]:8787 (local only)") == ("", True)


def test_install_creates_tls_certificate_once(sandbox):
    from stand import agentapi
    tmp_path, target, _unit, run = sandbox
    _, unit_text, out = run()
    cert = target / "tls" / "cert.pem"
    if not cert.exists():
        pytest.skip("openssl is not available to bash: " + out[-300:])
    assert "--tls-port 8788 --tls-cert %s/tls/cert.pem --tls-key %s/tls/key.pem" % (posix(target), posix(target)) \
        in unit_text
    pin = agentapi.spki_pin(cert.read_bytes())
    assert "TLS port: 8788\n" in out and "TLS pin: %s\n" % pin in out
    assert deploy.installer_tls(out) == {"port": 8788, "pin": pin}
    assert "ufw allow 8788/tcp" in log_of(tmp_path)
    assert "BEGIN PRIVATE KEY" in (target / "tls" / "key.pem").read_text()
    assert "chown -h root:vpnagent %s/tls/key.pem" % posix(target) in log_of(tmp_path)
    before = cert.read_bytes(), (target / "tls" / "key.pem").read_bytes()
    _, unit_text, out = run()
    assert (cert.read_bytes(), (target / "tls" / "key.pem").read_bytes()) == before
    assert "TLS pin: %s\n" % pin in out
    _, unit_text, out = run(VPNAGENT_TLS_PORT="9443")
    assert "--tls-port 9443 " in unit_text and "TLS port: 9443\n" in out and cert.read_bytes() == before[0]
    _, unit_text, out = run()
    assert "--tls-port 9443 " in unit_text
    _, unit_text, out = run(VPNAGENT_TLS_PORT="0")
    assert "--tls-port 0 " in unit_text and "--tls-cert" not in unit_text and "TLS pin" not in out
    _, unit_text, out = run()
    assert "--tls-port 0 " in unit_text and cert.read_bytes() == before[0]
    _, unit_text, out = run(VPNAGENT_TLS_PORT="8788", BEHIND_PROXY="1")
    assert "--tls" not in unit_text and "TLS pin" not in out and cert.read_bytes() == before[0]
    result = run(ok=False, VPNAGENT_TLS_PORT="8787", BEHIND_PROXY="0")
    assert result.returncode != 0 and "must differ" in result.stderr


def test_install_refuses_broken_tls_key_and_regenerates_only_on_request(sandbox):
    tmp_path, target, _unit, run = sandbox
    run()
    cert = target / "tls" / "cert.pem"
    if not cert.exists():
        pytest.skip("openssl is not available to bash")
    old = cert.read_bytes()
    pin = deploy.installer_tls(run()[2])["pin"]
    key = (target / "tls" / "key.pem").read_bytes()
    (tmp_path / "foreign_data").write_text("")
    _, _, out = run()
    (tmp_path / "foreign_data").unlink()
    assert deploy.installer_tls(out)["pin"] == pin and cert.read_bytes() == old
    (target / "tls" / "key.pem").write_text("broken")
    result = run(ok=False)
    assert result.returncode != 0 and "VPNAGENT_TLS_REGENERATE=1" in result.stderr
    assert "restore.sh tls" in result.stderr
    assert cert.read_bytes() == old and (target / "tls" / "key.pem").read_text() == "broken"
    assert "systemctl restart" not in log_of(tmp_path).split("systemctl stop vpnagent")[-1]
    (target / "tls" / "key.pem").write_bytes(key)
    (target / "tls" / "cert.pem").unlink()
    result = run(ok=False)
    assert result.returncode != 0 and (target / "tls" / "key.pem").read_bytes() == key
    (target / "tls" / "cert.pem").write_bytes(old)
    _, _, out = run(VPNAGENT_TLS_REGENERATE="1")
    assert "VPNAGENT_TLS_REGENERATE=1" in out and cert.read_bytes() != old
    assert deploy.installer_tls(out)["pin"] != pin
    assert any(name.startswith("key.pem.old.") for name in os.listdir(target / "tls"))
    assert any(name.startswith("cert.pem.old.") for name in os.listdir(target / "tls"))
    assert "New TLS key" in out
    result = run(ok=False, VPNAGENT_TLS_REGENERATE="yes")
    assert result.returncode != 0


def test_install_warns_when_tls_is_turned_off_with_a_key_in_place(sandbox):
    _tmp_path, target, _unit, run = sandbox
    run()
    if not (target / "tls" / "cert.pem").exists():
        pytest.skip("openssl is not available to bash")
    _, _, out = run(VPNAGENT_TLS_PORT="0")
    assert "TLS port is being turned off" in out
    _, _, out = run(VPNAGENT_TLS_PORT="8788", BEHIND_PROXY="1")
    assert "TLS port is being turned off" in out


def test_restore_tls_refuses_a_foreign_archive_and_lists_tls_backups(restore_box):
    tmp_path, data, run = restore_box
    (data / "backups" / "tls-20260927.tar").write_bytes(b"not a tar")
    result = run("tls")
    assert result.returncode != 0 and "tls-20260927.tar" in result.stdout
    result = run("tls", "20260927")
    assert result.returncode != 0
    assert "systemctl" not in log_of(tmp_path)


def test_deploy_tls_from_installer_output():
    pin = "sha256/" + "B" * 43 + "="
    assert deploy.installer_tls("Data: /d\nTLS port: 8788\nTLS pin: %s\n" % pin) == {"port": 8788, "pin": pin}
    assert deploy.installer_tls("TLS port: 8788\n") is None
    assert deploy.installer_tls("TLS port: 0\nTLS pin: %s\n" % pin) is None
    assert deploy.installer_tls("TLS port: 8788\nTLS pin: sha256/short\n") is None
    assert deploy.tls_host("http://203.0.113.10:8787", {"host": "srv"}) == "203.0.113.10"
    assert deploy.tls_host("https://agents.example.com", {"host": "srv"}) == "srv"


def test_deploy_setup_tls_checks_pin_and_reachability(monkeypatch):
    from stand import agentapi
    sys.path.insert(0, os.path.join(ROOT, "tests"))
    from test_server_run import make_cert
    folder = os.path.join(os.environ["APPDATA"], "cert")
    os.makedirs(folder)
    cert_path, _key = make_cert(folder)
    pem = open(cert_path, encoding="ascii").read()
    pin = agentapi.spki_pin(pem)
    saved, published = [], []
    monkeypatch.setattr(agentapi, "save_tls", lambda *args: saved.append(args))
    monkeypatch.setattr(deploy, "publish_tls", lambda api: published.append(api.tls))
    monkeypatch.setattr(agentapi.AgentServer, "health", lambda self: {"ok": True})
    tls = {"port": 8788, "pin": pin}
    assert deploy.setup_tls("http://203.0.113.10:8787", "t", tls, pem, {"host": "h"}) is True
    assert saved[-1] == ("203.0.113.10", 8788, pin) and published == [tls]
    wrong = {"port": 8788, "pin": "sha256/" + "C" * 43 + "="}
    kept = len(saved)
    assert deploy.setup_tls("http://203.0.113.10:8787", "t", wrong, pem, {"host": "h"}) is False
    assert len(saved) == kept
    assert deploy.setup_tls("https://agents.example.com", "t", tls, pem, {"host": "h"}) is False
    assert deploy.setup_tls("http://203.0.113.10:8787", "t", None, "", {"host": "h"}) is False

    def down(self):
        raise OSError("timed out")
    monkeypatch.setattr(agentapi.AgentServer, "health", down)
    assert deploy.setup_tls("http://203.0.113.10:8787", "t", tls, pem, {"host": "h"}) is False
    assert saved[-1] == ("203.0.113.10", 8788, pin) and published == [tls]


def test_deploy_publishes_tls_manifest_once(monkeypatch, tmp_path):
    from stand import agentapi
    key = tmp_path / "manifest.key"
    key.write_bytes(b"k")
    monkeypatch.setattr(agentapi, "KEY_PATH", str(key))
    pin = "sha256/" + "D" * 43 + "="
    api = agentapi.AgentServer("http://203.0.113.10:8787", "t", tls={"port": 8788, "pin": pin})
    calls = []
    monkeypatch.setattr(api, "publish_manifest", lambda: calls.append("publish"))
    monkeypatch.setattr(api, "state", lambda: {"manifest": {"app": {}, "signature": "s"}})
    deploy.publish_tls(api)
    monkeypatch.setattr(api, "state", lambda: {"manifest": {"tls": {"port": 8788, "pin": pin}}})
    deploy.publish_tls(api)
    monkeypatch.setattr(api, "state", lambda: {"manifest": None})
    deploy.publish_tls(api)
    assert calls == ["publish"]


def test_deploy_new_tls_key_flag_reaches_the_installer():
    env = deploy.installer_env({}, argparse.Namespace(lang=None, port=None, behind_proxy=False, new_tls_key=True))
    assert env == {"VPNAGENT_TLS_REGENERATE": "1"}
    env = deploy.installer_env({}, argparse.Namespace(lang=None, port=None, behind_proxy=False, new_tls_key=False,
                                                      disable_tls=True))
    assert env == {"VPNAGENT_TLS_PORT": "0"}
    with pytest.raises(SystemExit):
        deploy.main(["--new-tls-key", "--disable-tls"])


def test_deploy_disable_tls_publishes_explicit_null_only_when_needed(monkeypatch, tmp_path):
    from stand import agentapi
    monkeypatch.setattr(agentapi, "AGENT_CONFIG", str(tmp_path / "agent.json"))
    agentapi.save_tls("203.0.113.10", 8788, "sha256/" + "D" * 43 + "=")
    key = tmp_path / "manifest.key"
    monkeypatch.setattr(agentapi, "KEY_PATH", str(key))
    manifests, published = [{"tls": {"port": 8788, "pin": "sha256/" + "D" * 43 + "="}, "issued": 5}], []
    monkeypatch.setattr(agentapi.AgentServer, "state", lambda self: {"manifest": manifests[-1]})
    monkeypatch.setattr(agentapi.AgentServer, "publish_manifest",
                        lambda self, app=None, disable_tls=False: published.append((self.tls, disable_tls)))
    assert deploy.disable_tls("http://203.0.113.10:8787", "t") is None
    assert agentapi.tls_for("http://203.0.113.10:8787") is None
    key.write_bytes(b"k")
    assert deploy.disable_tls("", "t") is False
    assert deploy.disable_tls("http://203.0.113.10:8787", "t") is True
    assert published == [(None, True)]
    manifests.append({"app": {}, "issued": 6})
    assert deploy.disable_tls("http://203.0.113.10:8787", "t") is True
    manifests.append({"app": {}, "tls": None, "issued": 7})
    assert deploy.disable_tls("http://203.0.113.10:8787", "t") is False
    assert published == [(None, True), (None, True)]


def deploy_box(monkeypatch, tmp_path, install_out, health, manifest=None, stand_tls=True):
    from stand import agentapi, dcprobe, storage
    monkeypatch.setattr(agentapi, "AGENT_CONFIG", str(tmp_path / "agent.json"))
    key = tmp_path / "manifest.key"
    key.write_bytes(b"k")
    monkeypatch.setattr(agentapi, "KEY_PATH", str(key))
    monkeypatch.setattr(storage, "load_connections", lambda: {"probe": {"host": "203.0.113.10", "user": "root"}})
    agentapi.save_agent_config("http://203.0.113.10:8787", "tok")
    if stand_tls:
        agentapi.save_tls("203.0.113.10", 8788, "sha256/" + "E" * 43 + "=")
    if manifest is None:
        manifest = {"app": {}, "tls": {"port": 8788, "pin": "sha256/" + "E" * 43 + "="}, "issued": 5}

    def remote(_client, command, timeout=0):
        if "mktemp" in command:
            return "/tmp/vpnagent-src.x\n", "", 0
        if "install.sh" in command:
            return install_out, "", 0
        if "admin_token" in command:
            return "tok\n", "", 0
        return "", "", 0
    monkeypatch.setattr(dcprobe, "connect", lambda spec: mock_client())
    monkeypatch.setattr(dcprobe, "run", remote)
    monkeypatch.setattr(deploy, "upload", lambda *args: None)
    monkeypatch.setattr(deploy, "check_health", lambda server: health)
    monkeypatch.setattr(agentapi.AgentServer, "state", lambda self: {"manifest": manifest})
    published = []
    monkeypatch.setattr(agentapi.AgentServer, "publish_manifest",
                        lambda self, app=None, disable_tls=False: published.append(disable_tls))
    return agentapi, published


def mock_client():
    return argparse.Namespace(close=lambda: None)


def test_deploy_shouts_and_republishes_nothing_when_tls_is_gone(monkeypatch, tmp_path, capsys):
    _agentapi, published = deploy_box(monkeypatch, tmp_path, "OK. Server: http://203.0.113.10:8787\n",
                                      {"ok": True, "tls": False})
    assert deploy.main([]) != 0
    out = capsys.readouterr().out
    assert "TLS-порт 8788 больше не работает" in out and "tls: false" in out and "!!!!" in out
    assert "НЕ тронут" in out and "--disable-tls" in out
    assert published == []


def test_deploy_republishes_nothing_when_the_tls_check_fails(monkeypatch, tmp_path, capsys):
    pin = "sha256/" + "E" * 43 + "="
    _agentapi, published = deploy_box(monkeypatch, tmp_path, "OK. Server: http://203.0.113.10:8787\n"
                                      "TLS port: 8788\nTLS pin: %s\n" % pin, {"ok": True, "tls": True},
                                      stand_tls=False)
    assert deploy.main([]) != 0
    out = capsys.readouterr().out
    assert "НЕ тронут" in out
    assert published == []


def test_deploy_without_tls_anywhere_is_not_a_failure(monkeypatch, tmp_path, capsys):
    _agentapi, published = deploy_box(monkeypatch, tmp_path, "OK. Server: http://203.0.113.10:8787\n",
                                      {"ok": True}, manifest={"app": {}, "issued": 5}, stand_tls=False)
    assert deploy.main([]) == 0
    assert "!!!!" not in capsys.readouterr().out and published == []


def test_deploy_disable_tls_flag_publishes_explicit_null(monkeypatch, tmp_path, capsys):
    agentapi, published = deploy_box(monkeypatch, tmp_path, "OK. Server: http://203.0.113.10:8787\n",
                                     {"ok": True})
    assert deploy.main(["--disable-tls"]) == 0
    assert "tls\": null" in capsys.readouterr().out
    assert published == [True]
    assert agentapi.tls_for("http://203.0.113.10:8787") is None


def test_deploy_disable_tls_fails_when_the_manifest_is_not_published(monkeypatch, tmp_path, capsys):
    _agentapi, _published = deploy_box(monkeypatch, tmp_path, "OK. Server: http://203.0.113.10:8787\n",
                                       {"ok": True})

    def broken(self, app=None, disable_tls=False):
        raise OSError("connection reset")
    monkeypatch.setattr(_agentapi.AgentServer, "publish_manifest", broken)
    assert deploy.main(["--disable-tls"]) != 0
    assert "не выложен" in capsys.readouterr().out


def test_deploy_disable_tls_without_signing_key_fails(monkeypatch, tmp_path, capsys):
    agentapi, published = deploy_box(monkeypatch, tmp_path, "OK. Server: http://203.0.113.10:8787\n",
                                     {"ok": True})
    os.remove(agentapi.KEY_PATH)
    assert deploy.main(["--disable-tls"]) != 0
    assert published == [] and "нет ключа подписи" in capsys.readouterr().out


def test_deploy_keeps_stand_on_tls_when_the_tls_port_is_unreachable(monkeypatch, tmp_path, capsys):
    from test_server_run import make_cert
    pem = open(make_cert(str(tmp_path))[0], encoding="ascii").read()
    agentapi, published = deploy_box(monkeypatch, tmp_path, "", {"ok": True, "tls": True})
    pin = agentapi.spki_pin(pem)
    previous = agentapi.load_agent_config()

    def down(self):
        raise OSError("timed out")
    monkeypatch.setattr(agentapi.AgentServer, "health", down)
    assert deploy.setup_tls("http://203.0.113.10:8787", "tok", {"port": 8788, "pin": pin}, pem,
                            {"host": "203.0.113.10"}) is False
    assert agentapi.tls_for("http://203.0.113.10:8787") == {"port": 8788, "pin": pin}
    assert previous["tls_pin"] != pin
    out = capsys.readouterr().out
    assert "остаётся на TLS" in out and "!!!!" in out
    assert published == []


def test_deploy_shouts_when_the_tls_key_changed(monkeypatch, tmp_path, capsys):
    new = "sha256/" + "F" * 43 + "="
    _agentapi, published = deploy_box(monkeypatch, tmp_path, "OK. Server: http://203.0.113.10:8787\n"
                                      "TLS port: 8788\nTLS pin: %s\n" % new, {"ok": True, "tls": True})
    monkeypatch.setattr(deploy, "setup_tls", lambda *args: True)
    assert deploy.main([]) == 0
    out = capsys.readouterr().out
    assert "ключ TLS сервера сменился" in out and new in out
    assert published == []


def test_deploy_is_quiet_when_the_tls_key_is_kept(monkeypatch, tmp_path, capsys):
    same = "sha256/" + "E" * 43 + "="
    _agentapi, published = deploy_box(monkeypatch, tmp_path, "OK. Server: http://203.0.113.10:8787\n"
                                      "TLS port: 8788\nTLS pin: %s\n" % same, {"ok": True, "tls": True})
    monkeypatch.setattr(deploy, "setup_tls", lambda *args: True)
    assert deploy.main([]) == 0
    assert "!!!!" not in capsys.readouterr().out and published == []


def test_deploy_payload_skips_itself():
    remote = [name for _local, name in deploy.payload()]
    assert "server/install.sh" in remote and "server/app.py" in remote and "server/restore.sh" in remote
    assert "server/run.py" in remote
    assert "server/deploy.py" not in remote
    assert "stand/regions.json" in remote and "stand/node_fields.json" in remote


def test_install_copies_region_table(sandbox):
    tmp_path, target, _unit, run = sandbox
    run()
    assert not (target / "regions.json").exists()
    stand = tmp_path / "src" / "stand"
    assert (target / "node_fields.json").read_bytes() == (stand / "node_fields.json").read_bytes()
    shutil.copy(os.path.join(ROOT, "stand", "regions.json"), stand / "regions.json")
    run()
    assert (target / "regions.json").read_bytes() == (stand / "regions.json").read_bytes()
    (stand / "regions.json").write_text('{"changed": 1}')
    run()
    assert (target / "regions.json").read_text() == '{"changed": 1}'



def test_install_refuses_without_node_fields(sandbox):
    tmp_path, target, _unit, run = sandbox
    os.remove(tmp_path / "src" / "stand" / "node_fields.json")
    result = run(ok=False)
    assert result.returncode != 0 and "node_fields.json" in result.stderr
    assert not target.exists()


def test_install_refuses_without_run_py(sandbox):
    tmp_path, target, _unit, run = sandbox
    os.remove(tmp_path / "src" / "server" / "run.py")
    result = run(ok=False)
    assert result.returncode != 0 and "run.py" in result.stderr
    assert not target.exists()

def test_make_public_author(tmp_path, monkeypatch):
    monkeypatch.delenv("VPNCHECK_PUBLIC_AUTHOR", raising=False)
    assert make_public.commit_author(str(tmp_path)) is None
    monkeypatch.setenv("VPNCHECK_PUBLIC_AUTHOR", "Some One <someone@example.com>")
    assert make_public.commit_author(str(tmp_path)) == ("Some One", "someone@example.com")
    monkeypatch.setenv("VPNCHECK_PUBLIC_AUTHOR", "no email")
    assert make_public.commit_author(str(tmp_path)) is None


def test_make_public_removes_read_only_tree(tmp_path):
    folder = tmp_path / "copy" / ".git" / "objects" / "ab"
    folder.mkdir(parents=True)
    blob = folder / "cdef"
    blob.write_text("x")
    os.chmod(blob, stat.S_IREAD)
    make_public.remove_tree(str(tmp_path / "copy"))
    assert not (tmp_path / "copy").exists()


def test_make_public_knows_sim_numbers_and_serials(monkeypatch):
    monkeypatch.setattr(make_public.storage, "load_connections", lambda: {})
    monkeypatch.setattr(make_public.storage, "APP_DIR", os.path.join(ROOT, "no-such-dir"))
    monkeypatch.setattr(make_public.storage, "load_settings", lambda: {
        "sim_numbers": {"R83L602ABCD|0:megafon": "+7 920 123-45-67"}, "phone_serial": "RFGL63XYZ12"})
    found = make_public.own_secrets()
    assert found["R83L602ABCD"] == "phone serial" and found["RFGL63XYZ12"] == "phone serial"
    assert found["79201234567"] == "SIM number" and found["9201234567"] == "SIM number"


def test_make_public_learns_addresses_and_squads_from_stand_data(monkeypatch, tmp_path):
    runs = tmp_path / "runs"
    runs.mkdir()
    run = {"squad": "TEAM-Q", "modes": [{"id": "wifi", "ip": "5.6.7.8", "results": {
        "n1.shop-demo.net:443": {"exit_ip": "5.6.7.9"}, "198.51.100.7:443": {"exit_ip": "1.1.1.1"},
        "api.ipify.org:443": {}, "[2a01:4f8::7]:443": {}}}]}
    (runs / "one.json").write_text(json.dumps(run), encoding="utf-8")
    (runs / "two.json").write_text(json.dumps({"squad": "https://subs.demo-sub.org/abc"}), encoding="utf-8")
    (tmp_path / "geo_cache.json").write_text(json.dumps({"6.7.8.9": {"org": "X"}}), encoding="utf-8")
    (tmp_path / "agent.json").write_text(json.dumps({"server": "http://agents.demo-box.com:8787"}),
                                         encoding="utf-8")
    monkeypatch.setattr(make_public.storage, "APP_DIR", str(tmp_path))
    found = make_public.stand_markers()
    for value in ("5.6.7.8", "5.6.7.9", "6.7.8.9", "2a01:4f8::7", "n1.shop-demo.net", "shop-demo.net",
                  "subs.demo-sub.org", "agents.demo-box.com", "demo-box.com", "TEAM-Q"):
        assert value in found, value
    for value in ("198.51.100.7", "1.1.1.1", "127.0.0.1", "api.ipify.org", "ipify.org"):
        assert value not in found, value

    pattern = make_public.markers_regex(found)
    leak = tmp_path / "leak.py"
    leak.write_text('A = "5.6.7.8"\nB = "15.6.7.88"\nC = "x.shop-demo.net"\nD = "squad TEAM-Q"\n', encoding="utf-8")
    hits = make_public.scan(str(leak), "tests/leak.py", {}, pattern)
    assert hits == ["tests/leak.py:1  stand data: 5.6.7.8", "tests/leak.py:3  stand data: shop-demo.net",
                    "tests/leak.py:4  stand data: TEAM-Q"]
    named = make_public.scan(str(leak), "docs/n1.shop-demo.net.txt", {}, pattern)
    assert "docs/n1.shop-demo.net.txt  n1.shop-demo.net (file name)" in named


def test_i18n_dynamic_keys_are_listed():
    keys = i18n_check.dynamic_keys()
    assert keys and all(isinstance(key, str) and key for key in keys)


def test_install_prints_admin_page(sandbox):
    _tmp_path, _target, _unit, run = sandbox
    _, _, out = run()
    assert "Admin page (phone/browser): http://203.0.113.10:8787/admin" in out
    assert deploy.server_address({}, {"host": "203.0.113.10"}, out) == ("http://203.0.113.10:8787", False)
    _, _, out = run(BEHIND_PROXY="1")
    assert "/admin" in out and "http://127.0.0.1:8787/admin" not in out


def fake_release(version):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name in ("xray", "geoip.dat", "geosite.dat"):
            archive.writestr(name, name + version)
    blob = buffer.getvalue()
    return blob, ("SHA2-256= %s\n" % hashlib.sha256(blob).hexdigest()).encode()


def point_fetch_at(tmp_path, monkeypatch, blob, digest):
    targets = {name: [str(tmp_path / "bin" / name)] for name in ("xray", "geoip.dat", "geosite.dat")}
    monkeypatch.setattr(fetch_binaries, "ROOT", str(tmp_path))
    monkeypatch.setattr(fetch_binaries, "TARGETS", targets)
    monkeypatch.setattr(fetch_binaries, "VERSION_FILE", str(tmp_path / "bin" / "xray.version"))
    monkeypatch.setattr(fetch_binaries, "download", lambda url: digest if url.endswith(".dgst") else blob)


def test_fetch_binaries_writes_version(tmp_path, monkeypatch):
    blob, digest = fake_release("1.2.3")
    point_fetch_at(tmp_path, monkeypatch, blob, digest)
    monkeypatch.setattr(sys, "argv", ["fetch_binaries.py", "1.2.3"])
    fetch_binaries.main()
    assert (tmp_path / "bin" / "xray.version").read_text() == "1.2.3\n"
    assert (tmp_path / "bin" / "xray").read_text() == "xray1.2.3"


def test_fetch_binaries_bad_hash_keeps_old_version(tmp_path, monkeypatch):
    blob, _digest = fake_release("2.0.0")
    point_fetch_at(tmp_path, monkeypatch, blob, b"SHA2-256= 00\n")
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "xray.version").write_text("1.0.0\n")
    monkeypatch.setattr(sys, "argv", ["fetch_binaries.py", "2.0.0"])
    with pytest.raises(SystemExit):
        fetch_binaries.main()
    assert (tmp_path / "bin" / "xray.version").read_text() == "1.0.0\n"
    assert not (tmp_path / "bin" / "xray").exists()


def test_version_file_is_ignored_and_private():
    ignored = open(os.path.join(ROOT, ".gitignore"), encoding="utf-8").read().splitlines()
    assert "bin/xray.version" in ignored and "venv/" in ignored and ".venv/" in ignored
    assert "bin/*" in make_public.EXCLUDE


def xray_step():
    text = open(os.path.join(ROOT, "install.ps1"), encoding="utf-8-sig").read()
    return text.split("# 4.", 1)[1].split("\n", 1)[1].split("# 5.", 1)[0]


@pytest.mark.parametrize("have, fetched", [(None, True), ("1.0.0", True), ("9.9.9", False)])
def test_install_ps1_refetches_xray_on_version_change(tmp_path, have, fetched):
    shell = shutil.which("powershell") or shutil.which("pwsh")
    if not shell:
        pytest.skip("PowerShell is not available")
    (tmp_path / "stand").mkdir()
    (tmp_path / "stand" / "__init__.py").write_text("")
    (tmp_path / "stand" / "dcprobe.py").write_text('XRAY_VERSION = "9.9.9"\n')
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "fetch_binaries.py").write_text("open('fetched', 'w').write('1')\n")
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "xray").write_text("old")
    if have:
        (tmp_path / "bin" / "xray.version").write_text(have + "\n")
    script = tmp_path / "step.ps1"
    head = ('$ErrorActionPreference = "Stop"\nSet-Location -Path $PSScriptRoot\n'
            'function Say($ru, $en) { Write-Host $ru }\n$pyExe = "%s"\n$pyArgs = @()\n' % sys.executable)
    script.write_text(head + xray_step(), encoding="utf-8-sig")
    result = subprocess.run([shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script)],
                            capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
    assert (tmp_path / "fetched").exists() == fetched
