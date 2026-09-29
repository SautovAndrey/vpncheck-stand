#!/usr/bin/env python3
"""Скачать ядро xray для телефонов - в репозиторий бинарники не кладём.

    python tools/fetch_binaries.py            # версия из stand/dcprobe.py (та же, что на пробнике ДЦ)
    python tools/fetch_binaries.py 26.6.27    # другая версия

Берёт официальный релиз XTLS/Xray-core для Android arm64, сверяет SHA-256 с файлом .dgst из того же
релиза и раскладывает:
    bin/xray, bin/geoip.dat, bin/geosite.dat                    - стенд заливает их на телефон по ADB;
    agent/app/src/main/jniLibs/arm64-v8a/libxray.so             - ядро внутри приложения агента;
    bin/xray.version                                            - версия ядра: другая - install.ps1 качает заново.
"""
import hashlib
import io
import os
import sys
import urllib.request
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from stand.dcprobe import XRAY_VERSION  # noqa: E402

URL = "https://github.com/XTLS/Xray-core/releases/download/v%s/Xray-android-arm64-v8a.zip"
TARGETS = {
    "xray": [os.path.join(ROOT, "bin", "xray"),
             os.path.join(ROOT, "agent", "app", "src", "main", "jniLibs", "arm64-v8a", "libxray.so")],
    "geoip.dat": [os.path.join(ROOT, "bin", "geoip.dat")],
    "geosite.dat": [os.path.join(ROOT, "bin", "geosite.dat")],
}
VERSION_FILE = os.path.join(ROOT, "bin", "xray.version")


def download(url):
    request = urllib.request.Request(url, headers={"User-Agent": "vpncheck-stand"})
    with urllib.request.urlopen(request, timeout=180) as response:
        return response.read()


def main():
    version = sys.argv[1] if len(sys.argv) > 1 else XRAY_VERSION
    url = URL % version
    print("downloading", url)
    blob = download(url)
    digest = download(url + ".dgst").decode()
    want = [line.split("=")[-1].strip().lower() for line in digest.splitlines() if line.upper().startswith("SHA2-256")]
    got = hashlib.sha256(blob).hexdigest()
    if not want or got != want[0]:
        sys.exit("SHA-256 mismatch (%s != %s) - nothing installed" % (got, want[0] if want else "?"))
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        names = set(archive.namelist())
        for name, paths in TARGETS.items():
            if name not in names:
                sys.exit("%s is missing in the release archive" % name)
            data = archive.read(name)
            for path in paths:
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "wb") as handle:
                    handle.write(data)
                print("  %-60s %6.1f MB" % (os.path.relpath(path, ROOT), len(data) / 1e6))
    with open(VERSION_FILE, "w", encoding="ascii", newline="\n") as handle:
        handle.write(version + "\n")
    print("xray %s ready (sha256 ok)" % version)


if __name__ == "__main__":
    main()
