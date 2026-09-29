"""Тонкая обёртка над adb.exe: поиск бинарника, shell, push, проброс портов."""
import glob
import os
import shutil
import subprocess
import sys

from .i18n import t

CREATE_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0


class AdbError(Exception):
    pass


def find_adb():
    env = os.environ.get("ADB_PATH")
    if env and os.path.exists(env):
        return env
    found = shutil.which("adb")
    if found:
        return found
    local = os.environ.get("LOCALAPPDATA", "")
    patterns = [
        os.path.join(local, "Microsoft", "WinGet", "Packages", "Google.PlatformTools*", "platform-tools", "adb.exe"),
        os.path.join(local, "Microsoft", "WinGet", "Links", "adb.exe"),
        os.path.join(local, "Android", "Sdk", "platform-tools", "adb.exe"),
    ]
    for pattern in patterns:
        hits = glob.glob(pattern)
        if hits:
            return hits[0]
    return None


class Adb:
    def __init__(self, path=None, serial=None):
        self.path = path or find_adb()
        self.serial = serial or os.environ.get("ANDROID_SERIAL") or None
        if not self.path:
            raise AdbError(t("adb не найден: winget install Google.PlatformTools"))

    def _base(self):
        cmd = [self.path]
        if self.serial:
            cmd += ["-s", self.serial]
        return cmd

    def run(self, *args, timeout=25, input_text=None):
        try:
            proc = subprocess.run(self._base() + list(args), capture_output=True, timeout=timeout,
                                  input=input_text.encode() if input_text else None,
                                  creationflags=CREATE_NO_WINDOW)
        except subprocess.TimeoutExpired as exc:
            raise AdbError(t("adb %s: таймаут %ds") % (" ".join(args[:2]), timeout)) from exc
        except OSError as exc:
            raise AdbError("adb: %s" % exc) from exc
        out = proc.stdout.decode("utf-8", errors="replace")
        err = proc.stderr.decode("utf-8", errors="replace")
        if proc.returncode != 0 and "more than one device" in err:
            raise AdbError(t("подключено несколько телефонов - нужно указать, с каким работать"))
        return proc.returncode, out, err

    def serials(self):
        """Серийники телефонов, готовых к работе (state=device), в стабильном порядке."""
        return sorted(d["serial"] for d in self.devices() if d["state"] == "device")

    def devices(self):
        _, out, _ = self.run("devices", "-l", timeout=15)
        result = []
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 2 and parts[0] != "*":
                result.append({"serial": parts[0], "state": parts[1],
                               "desc": " ".join(parts[2:])})
        return result

    def shell(self, command, timeout=25):
        code, out, err = self.run("shell", command, timeout=timeout)
        if code != 0 and ("device" in err and "not found" in err or "no devices" in err):
            raise AdbError(t("телефон не подключён"))
        return out

    def push(self, local, remote, timeout=180):
        code, out, err = self.run("push", local, remote, timeout=timeout)
        if code != 0:
            raise AdbError("push %s: %s" % (os.path.basename(local), (err or out).strip()[-200:]))
        return out

    def forward(self, local_port, remote_port):
        code, out, err = self.run("forward", "tcp:%d" % local_port, "tcp:%d" % remote_port)
        if code != 0:
            raise AdbError("forward %d: %s" % (local_port, (err or out).strip()[-200:]))

    def forward_remove_ports(self, low, high):
        """Снять только свои пробросы (диапазон портов), чужие - scrcpy и прочие - не трогать."""
        _, out, _ = self.run("forward", "--list")
        for line in out.splitlines():
            parts = line.split()
            if self.serial and parts and parts[0] != self.serial:
                continue
            if len(parts) >= 2 and parts[1].startswith("tcp:"):
                try:
                    port = int(parts[1][4:])
                except ValueError:
                    continue
                if low <= port <= high:
                    self.run("forward", "--remove", parts[1])
