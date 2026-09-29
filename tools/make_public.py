#!/usr/bin/env python3
"""Собрать чистую копию проекта для публикации: без истории git, без личных файлов, с проверкой на утечки.

    python tools/make_public.py ../VPNCheck-public          # собрать и проверить
    python tools/make_public.py ../VPNCheck-public --force  # пересобрать поверх прошлой сборки
    python tools/make_public.py ../VPNCheck-public --update "что изменилось"  # новый коммит поверх

Берутся только файлы в индексе git (git ls-files --cached) минус EXCLUDE; неотслеживаемые файлы печатаются
списком и попадают в копию только с --include-untracked. Потом каждый файл проверяется на:
  - секреты из своих настроек стенда (%APPDATA%/VPNCheckStand: токены панелей и сервера агентов, адреса
    панелей, SSH-хост и пароль пробника, номера SIM и серийники телефонов) - их программа знает сама,
    список вести не нужно;
  - адреса и имена из данных стенда (runs/*.json, geo_cache.json, connections.json, agent.json): все IPv4/IPv6,
    имена узлов и их базовые домены, названия сквадов. Не считаются: документационные и служебные адреса
    (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32, частные, 127.0.0.1) и публичные сервисы,
    которые код использует намеренно (ALLOWED_IPS, ALLOWED_DOMAINS);
  - слова из личного списка %APPDATA%/VPNCheckStand/public_blocklist.txt (по строке: IP своих серверов,
    серийники телефонов, названия своих сервисов) - в репозиторий этот список не попадает;
  - типовые признаки ключей (PRIVATE KEY, пароли в keystore.properties и т.п.).
Проверяется и содержимое файлов, и их имена.
Нашлось хоть что-то - копия не публикуется (код выхода 1), список находок печатается.
В конце в папке делается `git init` и один коммит. Никуда не отправляет - push делается руками.
Автор коммита - user.name/user.email из настроек git самой копии, иначе VPNCHECK_PUBLIC_AUTHOR="Name <email>"
(запоминается в копии); глобальный git-пользователь не используется.
"""
import argparse
import fnmatch
import glob
import ipaddress
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from urllib.parse import urlparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from stand import storage  # noqa: E402

MARKER = ".vpncheck-public"
EXCLUDE = [
    "CHANGELOG.md",
    "canary*", "cf_*", "sbcheck.py",
    "bin/*",
    "agent/app/src/main/jniLibs/*",
    "*.log", "*.csv",
]
GENERIC = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private key"),
    (re.compile(r"(?im)^\s*(storePassword|keyPassword)\s*=\s*[^\s(.][^\s(]*\s*$"), "keystore password"),
    (re.compile(r"(?i)\b(?:ghp|github_pat|glpat|xox[bap])_[A-Za-z0-9_]{20,}"), "access token"),
    (re.compile(r"\b\d{9,10}:[A-Za-z0-9_-]{35}\b"), "telegram bot token"),
    (re.compile(r"(?i)\"private_key\"\s*:"), "service account key"),
]


def git_list(*args):
    out = subprocess.run(["git", "ls-files", "-z", *args], cwd=ROOT, capture_output=True, check=True).stdout
    return [f for f in out.decode("utf-8").split("\0") if f]


def tracked_files():
    return git_list("--cached")


def untracked_files():
    return git_list("--others", "--exclude-standard")


def executable_files():
    found = set()
    for entry in git_list("--stage"):
        if entry.startswith("100755 "):
            found.add(entry.split("\t", 1)[1])
    return found


def remove_tree(path):
    def retry(func, target, _info):
        os.chmod(target, stat.S_IWRITE)
        func(target)
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=retry)
    else:
        shutil.rmtree(path, onerror=retry)


AUTHOR_RE = re.compile(r"^\s*(.+?)\s*<([^<>\s]+@[^<>\s]+)>\s*$")


def local_config(target, key):
    if not os.path.isdir(os.path.join(target, ".git")):
        return ""
    result = subprocess.run(["git", "config", "--local", "--get", key], cwd=target, capture_output=True, text=True)
    return result.stdout.strip() if result.returncode == 0 else ""


def commit_author(target):
    name, email = local_config(target, "user.name"), local_config(target, "user.email")
    if name and email:
        return name, email
    match = AUTHOR_RE.match(os.environ.get("VPNCHECK_PUBLIC_AUTHOR", ""))
    if match:
        return match.group(1), match.group(2)
    return None


def excluded(path):
    return any(fnmatch.fnmatch(path, pattern) for pattern in EXCLUDE)


def own_secrets():
    """Значения из своих настроек стенда, которых не должно быть в публичной копии."""
    found = {}

    def add(value, why):
        value = (value or "").strip()
        if len(value) >= 6 and value not in ("http://", "https://"):
            found[value] = why

    connections = storage.load_connections()
    for name, panel in (connections.get("panels") or {}).items():
        add(panel.get("token"), "panel %s token" % name)
        add(urlparse(panel.get("url") or "").hostname, "panel %s host" % name)
        for header in (panel.get("headers") or {}).values():
            add(str(header), "panel %s header" % name)
    probe = connections.get("probe") or {}
    for key in ("host", "password", "key"):
        add(probe.get(key), "probe %s" % key)
    agent_json = os.path.join(storage.APP_DIR, "agent.json")
    if os.path.exists(agent_json):
        with open(agent_json, encoding="utf-8") as handle:
            cfg = json.load(handle)
        add(cfg.get("token"), "agent server token")
        add(urlparse(cfg.get("server") or "").hostname, "agent server host")
        for key in ("yandex_key", "tg_bot_token", "tg_admin"):
            add(cfg.get(key), key)
    settings = storage.load_settings()
    for key, number in (settings.get("sim_numbers") or {}).items():
        add(str(key).split("|")[0], "phone serial")
        digits = re.sub(r"\D", "", str(number or ""))
        add(str(number or ""), "SIM number")
        add(digits, "SIM number")
        add(digits[-10:], "SIM number")
    add(settings.get("phone_serial"), "phone serial")
    blocklist = os.path.join(storage.APP_DIR, "public_blocklist.txt")
    if os.path.exists(blocklist):
        with open(blocklist, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line and not line.startswith("#"):
                    found[line] = "blocklist"
    return found


ALLOWED_IPS = {
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
    "2606:4700:4700::1111", "2606:4700:4700::1001", "2001:4860:4860::8888", "2001:4860:4860::8844",
}
ALLOWED_DOMAINS = (
    "localhost", "example.com", "example.org", "example.net", "ipify.org", "ifconfig.me", "amazonaws.com",
    "ipinfo.io", "google.com", "googleapis.com", "gstatic.com", "cloudflare.com", "telegram.org", "t.me",
    "openstreetmap.org", "arcgisonline.com", "yandex.ru", "yandex.net", "yandex.cloud", "yastatic.net", "ya.ru",
    "github.com", "githubusercontent.com", "neverssl.com", "gosuslugi.ru", "nalog.ru", "mts.ru", "dom.ru",
    "youtube.com", "apple.com", "icloud.com", "microsoft.com", "samsung.com", "android.com", "gradle.org",
    "python.org", "w3.org", "leafletjs.com", "naturalearthdata.com", "chromium.org", "mozilla.org",
    "apache.org", "vk.ru", "vk.com", "avito.ru", "rutube.ru", "x5.ru", "magnit.ru", "max.ru", "cloud.ru",
    "philips.com",
)
NOT_TLD = {"exe", "dll", "py", "json", "log", "txt", "apk", "png", "jpg", "kt", "kts", "xml", "md", "html", "js",
           "css", "so", "jar", "cmd", "bat", "ps1", "lock", "db", "sh", "toml", "cfg", "ini", "zip", "gz", "csv"}
SECOND_LEVEL = {"com", "net", "org", "co", "gov", "edu", "ac", "msk", "spb"}
IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.]*\d)")
IPV6_RE = re.compile(r"(?<![\w:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![\w:])", re.I)
HOST_RE = re.compile(r"(?<![\w@.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62})(?![\w-])", re.I)


def public_ip(text):
    """Адрес, который выдаёт настоящий узел: глобальный и не из списка намеренно используемых."""
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return None
    if not ip.is_global or ip.is_multicast or str(ip) in ALLOWED_IPS:
        return None
    return str(ip)


def allowed_host(host):
    return any(host == domain or host.endswith("." + domain) for domain in ALLOWED_DOMAINS)


def base_domain(host):
    labels = host.split(".")
    keep = 3 if len(labels) >= 3 and labels[-2] in SECOND_LEVEL else 2
    return ".".join(labels[-keep:])


def stand_markers():
    """Адреса, имена узлов и сквадов из данных самого стенда: реальные узлы, панели, сервер агентов, свой IP."""
    app = storage.APP_DIR
    paths = sorted(glob.glob(os.path.join(app, "runs", "*.json")))
    paths += [os.path.join(app, name) for name in ("geo_cache.json", "connections.json", "agent.json")]
    found = {}
    squads = set()

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "squad" and isinstance(value, str):
                    squads.add(value.strip())
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    for path in paths:
        try:
            with open(path, encoding="utf-8") as handle:
                text = handle.read()
            walk(json.loads(text))
        except (OSError, ValueError):
            continue
        for candidate in IPV4_RE.findall(text) + IPV6_RE.findall(text):
            ip = public_ip(candidate)
            if ip:
                found[ip] = "stand IP %s" % ip
        for host in HOST_RE.findall(text):
            host = host.lower()
            if host.rsplit(".", 1)[1] in NOT_TLD or allowed_host(host):
                continue
            found[host] = "stand host %s" % host
            base = base_domain(host)
            if not allowed_host(base):
                found[base] = "stand domain %s" % base
    for squad in squads:
        host = (urlparse(squad).hostname or "") if "://" in squad else ""
        if host:
            if not allowed_host(host):
                found[host] = "stand host %s" % host
        elif len(squad) >= 4:
            found[squad] = "squad name %s" % squad
    return found


def markers_regex(markers):
    """Одно выражение на все метки: слово целиком, чтобы 1.2.3.4 не срабатывал внутри 11.2.3.45."""
    if not markers:
        return None
    body = "|".join(re.escape(value) for value in sorted(markers, key=len, reverse=True))
    return re.compile(r"(?<![\w-])(?:%s)(?![\w-])" % body, re.I)


BINARY = (".png", ".jpg", ".jpeg", ".ico", ".jar", ".so", ".apk", ".zip")


def scan(path, rel, secrets, markers=None):
    hits = []
    lower_rel = rel.lower()
    for value, why in secrets.items():
        if value.lower() in lower_rel:
            hits.append("%s  %s (file name)" % (rel, why))
    pattern = markers_regex(markers) if isinstance(markers, dict) else markers
    if pattern is not None:
        found = pattern.search(rel)
        if found:
            hits.append("%s  %s (file name)" % (rel, found.group(0)))
    if lower_rel.endswith(BINARY):
        return hits
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError:
        return hits
    text = data.decode("utf-8", errors="ignore")
    lower = text.lower()
    if pattern is not None:
        for found in pattern.finditer(text):
            hits.append("%s:%d  stand data: %s" % (rel, text[:found.start()].count("\n") + 1, found.group(0)))
    for value, why in secrets.items():
        if value.lower() in lower:
            line = lower[:lower.index(value.lower())].count("\n") + 1
            hits.append("%s:%d  %s" % (rel, line, why))
    for pattern, why in GENERIC:
        match = pattern.search(text)
        if match:
            hits.append("%s:%d  %s" % (rel, text[:match.start()].count("\n") + 1, why))
    return hits


def git(target, *args):
    return subprocess.run(["git", *args], cwd=target, check=True, capture_output=True, text=True).stdout


def exclude_marker(target):
    path = os.path.join(target, ".git", "info", "exclude")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    lines = []
    if os.path.exists(path):
        with open(path, encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    if "/" + MARKER not in lines:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write("/%s\n" % MARKER)


def main():
    parser = argparse.ArgumentParser(
        description="Build a clean public copy of the project: files from the git index only, no history, "
                    "checked for leaks of your own secrets (see the module docstring for details).")
    parser.add_argument("target", help="folder for the copy, outside the project")
    parser.add_argument("--force", action="store_true", help="remove an earlier build made by this script there")
    parser.add_argument("--update", metavar="MESSAGE", help="update an earlier copy with one new commit")
    parser.add_argument("--include-untracked", action="store_true",
                        help="also take new files not yet added to git (except .gitignore'd ones)")
    args = parser.parse_args()
    target = os.path.abspath(args.target)
    if os.path.normcase(target + os.sep).startswith(os.path.normcase(ROOT + os.sep)):
        sys.exit("target must be outside the project folder")
    made_here = os.path.exists(os.path.join(target, MARKER))
    if args.update and not (made_here and os.path.isdir(os.path.join(target, ".git"))):
        sys.exit("--update needs a folder made by this script earlier")
    if not args.update and os.path.exists(target) and os.listdir(target):
        if not (args.force and made_here):
            sys.exit("%s is not empty (use --force only for a folder made by this script)" % target)
    author = commit_author(target)
    if author is None:
        sys.exit('commit author is not set: VPNCHECK_PUBLIC_AUTHOR="Name <email>" '
                 "(or git config --local user.name / user.email in %s)" % target)

    untracked = [f for f in untracked_files() if not excluded(f)]
    candidates = tracked_files() + (untracked if args.include_untracked else [])
    if untracked and not args.include_untracked:
        print("not in git, skipped (git add them or use --include-untracked):")
        for rel in untracked:
            print("  " + rel)
    secrets = own_secrets()
    markers = stand_markers()
    print("checking against %d own values, %d addresses and names from stand data + generic patterns"
          % (len(secrets), len(markers)))
    pattern = markers_regex(markers)
    files = [f for f in dict.fromkeys(candidates) if not excluded(f) and os.path.isfile(os.path.join(ROOT, f))]
    hits = [hit for rel in files for hit in scan(os.path.join(ROOT, rel), rel, secrets, pattern)]
    if hits:
        print("LEAKS FOUND - do not publish:")
        for hit in hits:
            print("  " + hit)
        return 1

    if args.update:
        for rel in git(target, "ls-files", "-z").split("\0"):
            if rel and rel not in files:
                os.remove(os.path.join(target, rel))
    elif os.path.exists(target):
        remove_tree(target)
    for rel in files:
        dst = os.path.join(target, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(os.path.join(ROOT, rel), dst)
    with open(os.path.join(target, MARKER), "w") as handle:
        handle.write("made by tools/make_public.py\n")

    if not args.update:
        git(target, "init", "-q", "-b", "main")
    git(target, "config", "--local", "user.name", author[0])
    git(target, "config", "--local", "user.email", author[1])
    exclude_marker(target)
    git(target, "add", "-A")
    executable = sorted(executable_files().intersection(files))
    if executable:
        git(target, "update-index", "--chmod=+x", "--", *executable)
    if not git(target, "status", "--porcelain").strip():
        print("no changes")
        return 0
    git(target, "-c", "user.name=" + author[0], "-c", "user.email=" + author[1],
        "commit", "-q", "-m", args.update or "VPNCheck Stand: initial public release")
    print("author: %s <%s>" % author)
    print("%d files -> %s (committed, nothing pushed)" % (len(files), target))
    return 0


if __name__ == "__main__":
    sys.exit(main())
