#!/usr/bin/env bash
# VPNCheck agent server - восстановление базы или ключа TLS из бэкапа / restore the database or the TLS key.
#
#   sudo bash /opt/vpnagent/restore.sh                 # список бэкапов / list backups
#   sudo bash /opt/vpnagent/restore.sh 20260927        # бэкап за дату / backup of that day
#   sudo bash /opt/vpnagent/restore.sh /path/agents-20260927.db.gz
#   sudo bash /opt/vpnagent/restore.sh tls 20260927    # сертификат и ключ TLS-порта / TLS certificate and key
#   sudo bash /opt/vpnagent/restore.sh tls /path/tls-20260927.tar
#
# База: распаковывает бэкап во временную папку root рядом с сервером (не в папке данных), проверяет его
# (PRAGMA integrity_check), останавливает сервис, откладывает текущую базу вместе с -wal/-shm
# в agents.db.broken-<время>, кладёт бэкап на место, запускает сервис и ждёт /health.
# Отложенную базу можно удалить, когда всё в порядке.
# TLS: из tls-ГГГГММДД.tar берутся только cert.pem и key.pem, пара проверяется (ключ подходит к сертификату),
# прежние файлы откладываются в tls/*.pem.replaced-<время>, права - как у установщика (cert 644 root:root,
# key 640 root:vpnagent). Агенты 0.12.9+ снова узнают сервер по прежнему отпечатку.
set -euo pipefail

DIR="${VPNAGENT_DIR:-/opt/vpnagent}"
DATA="${VPNAGENT_DATA:-$DIR/data}"
UNIT="${VPNAGENT_UNIT:-/etc/systemd/system/vpnagent.service}"
SVC_USER=vpnagent
DB="$DATA/agents.db"
BACKUPS="$DATA/backups"
TLS_DIR="$DIR/tls"

die() { echo "$*" >&2; exit 1; }

if [ "$(id -u)" -ne 0 ]; then die "run as root: sudo bash $0
запустите от root: sudo bash $0"; fi

list_backups() {
  echo "Backups in $BACKUPS / бэкапы в $BACKUPS:"
  ls -1 "$BACKUPS" 2>/dev/null | grep -E "^$1-[0-9]{8}\\.$2\$" | sort -r | sed 's/^/  /' || echo "  -"
}

old_unit_arg() {
  [ -f "$UNIT" ] || return 0
  grep -oE -- "--$1 [^ ]+" "$UNIT" | tail -n 1 | cut -d' ' -f2 || true
}

TMP_DIR=""
STOPPED=0
on_exit() {
  local rc=$?
  if [ -n "$TMP_DIR" ]; then rm -rf "$TMP_DIR"; fi
  if [ "$rc" -ne 0 ] && [ "$STOPPED" = 1 ]; then
    systemctl start vpnagent >/dev/null 2>&1 || true
  fi
}
trap on_exit EXIT

check_host() {
  case "${1:-0.0.0.0}" in
    0.0.0.0) echo 127.0.0.1 ;;
    ::) echo "[::1]" ;;
    *:*) echo "[$1]" ;;
    *) echo "$1" ;;
  esac
}

stop_service() {
  echo "* stopping vpnagent"
  if command -v systemctl >/dev/null; then
    systemctl stop vpnagent
    STOPPED=1
  fi
}

start_service() {
  echo "* starting vpnagent"
  [ "$STOPPED" = 1 ] || return 0
  systemctl start vpnagent
  STOPPED=0
  local port
  port="$(old_unit_arg port)"
  HEALTH="http://$(check_host "$(old_unit_arg host)"):${port:-8787}/health"
  for _ in $(seq 60); do
    curl -fs "$HEALTH" >/dev/null && break
    sleep 1
  done
  curl -fs "$HEALTH" >/dev/null || die "service did not start: journalctl -u vpnagent -n 50
$1
сервис не запустился - смотрите: journalctl -u vpnagent -n 50
$2"
}

restore_tls() {
  if [ $# -ne 1 ]; then
    list_backups tls tar
    die "usage: sudo bash $0 tls YYYYMMDD | <tls-YYYYMMDD.tar>
запуск: sudo bash $0 tls ГГГГММДД | <tls-ГГГГММДД.tar>"
  fi
  case "$1" in
    [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]) SOURCE="$BACKUPS/tls-$1.tar" ;;
    */*) SOURCE="$1" ;;
    *) SOURCE="$BACKUPS/$1" ;;
  esac
  if [ ! -f "$SOURCE" ]; then
    list_backups tls tar
    die "no such backup: $SOURCE
нет такого бэкапа: $SOURCE"
  fi
  command -v openssl >/dev/null || die "openssl not found / нет openssl"
  if [ -L "$TLS_DIR" ] || { [ -e "$TLS_DIR" ] && [ ! -d "$TLS_DIR" ]; }; then die "$TLS_DIR is not a folder - move it away
$TLS_DIR - не папка: уберите это"; fi

  echo "* unpacking $SOURCE"
  umask 077
  TMP_DIR="$(mktemp -d "$DIR/.restore.XXXXXX")"
  python3 - "$SOURCE" "$TMP_DIR" <<'EOF' || die "not a TLS backup (needs exactly cert.pem and key.pem), nothing changed
это не бэкап TLS (нужны ровно cert.pem и key.pem), ничего не изменено"
import os, sys, tarfile
source, target = sys.argv[1], sys.argv[2]
with tarfile.open(source) as archive:
    members = archive.getmembers()
    names = sorted(member.name for member in members)
    if names != ["cert.pem", "key.pem"] or not all(m.isfile() and 0 < m.size <= 65536 for m in members):
        sys.exit("unexpected members: %s" % names)
    for member in members:
        data = archive.extractfile(member).read()
        fd = os.open(os.path.join(target, member.name), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
EOF
  local cert_key key_key pin
  cert_key="$(openssl x509 -in "$TMP_DIR/cert.pem" -pubkey -noout 2>/dev/null)" || cert_key=""
  key_key="$(openssl pkey -in "$TMP_DIR/key.pem" -passin pass: -pubout 2>/dev/null </dev/null)" || key_key=""
  if [ -z "$cert_key" ] || [ "$cert_key" != "$key_key" ]; then die "the key in $SOURCE does not match its certificate, nothing changed
ключ в $SOURCE не подходит к сертификату, ничего не изменено"; fi
  pin="$(openssl x509 -in "$TMP_DIR/cert.pem" -pubkey -noout | openssl pkey -pubin -outform der \
    | openssl dgst -sha256 -binary | base64)"

  stop_service
  mkdir -p "$TLS_DIR"
  chown -h root:"$SVC_USER" "$TLS_DIR"
  chmod 750 "$TLS_DIR"
  STAMP="$(date +%Y%m%d-%H%M%S)"
  for f in cert.pem key.pem; do
    if [ -e "$TLS_DIR/$f" ] || [ -L "$TLS_DIR/$f" ]; then mv -T "$TLS_DIR/$f" "$TLS_DIR/$f.replaced-$STAMP"; fi
  done
  chown -h root:root "$TMP_DIR/cert.pem"
  chmod 644 "$TMP_DIR/cert.pem"
  chown -h root:"$SVC_USER" "$TMP_DIR/key.pem"
  chmod 640 "$TMP_DIR/key.pem"
  mv -T "$TMP_DIR/key.pem" "$TLS_DIR/key.pem"
  mv -T "$TMP_DIR/cert.pem" "$TLS_DIR/cert.pem"
  start_service "the previous pair is kept as $TLS_DIR/*.pem.replaced-$STAMP" \
    "прежняя пара сохранена как $TLS_DIR/*.pem.replaced-$STAMP"

  echo
  echo "OK. TLS certificate and key restored from $SOURCE"
  echo "Готово. Сертификат и ключ TLS восстановлены из $SOURCE"
  echo "TLS pin: sha256/$pin"
  if [ -z "$(old_unit_arg tls-cert)" ]; then
    echo "The TLS port is off in the service - turn it on: python server/deploy.py (or sudo bash server/install.sh)"
    echo "TLS-порт в сервисе выключен - включите: python server/deploy.py (или sudo bash server/install.sh)"
  fi
}

if [ "${1:-}" = tls ]; then
  shift
  restore_tls "$@"
  exit 0
fi

if [ $# -ne 1 ]; then
  list_backups agents 'db\.gz'
  die "usage: sudo bash $0 YYYYMMDD | <file.db.gz> | tls YYYYMMDD
запуск: sudo bash $0 ГГГГММДД | <файл.db.gz> | tls ГГГГММДД"
fi

case "$1" in
  [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]) SOURCE="$BACKUPS/agents-$1.db.gz" ;;
  */*) SOURCE="$1" ;;
  *) SOURCE="$BACKUPS/$1" ;;
esac
if [ ! -f "$SOURCE" ]; then
  list_backups agents 'db\.gz'
  die "no such backup: $SOURCE
нет такого бэкапа: $SOURCE"
fi
[ -d "$DATA" ] || die "no data folder: $DATA
нет папки данных: $DATA"

echo "* unpacking $SOURCE"
umask 077
TMP_DIR="$(mktemp -d "$DIR/.restore.XXXXXX")"
TMP_DB="$TMP_DIR/agents.db"
gunzip -c "$SOURCE" > "$TMP_DB" || die "cannot unpack $SOURCE (damaged or no free space)
не удалось распаковать $SOURCE (повреждён или нет места)"

echo "* integrity check"
CHECK="$(python3 - "$TMP_DB" <<'EOF' 2>&1 || true
import sqlite3, sys, urllib.parse
uri = "file:%s?mode=ro&immutable=1" % urllib.parse.quote(sys.argv[1])
try:
    conn = sqlite3.connect(uri, uri=True)
    rows = conn.execute("PRAGMA integrity_check").fetchall()
    count = conn.execute("SELECT COUNT(*) FROM sqlite_master").fetchone()[0]
except sqlite3.Error as exc:
    sys.exit(str(exc))
print(rows[0][0] if len(rows) == 1 else "; ".join(str(row[0]) for row in rows[:5]))
print("tables=%d" % count)
EOF
)"
case "$CHECK" in
  ok$'\n'tables=*) ;;
  *) die "backup failed the integrity check, nothing changed: $CHECK
бэкап не прошёл проверку целостности, ничего не изменено: $CHECK" ;;
esac

stop_service

STAMP="$(date +%Y%m%d-%H%M%S)"
ASIDE="$DB.broken-$STAMP"
if [ -e "$DB" ]; then
  echo "* current database -> $ASIDE"
  mv -T "$DB" "$ASIDE"
fi
for suffix in -wal -shm -journal; do
  if [ -e "$DB$suffix" ]; then
    if [ -e "$ASIDE" ]; then mv -T "$DB$suffix" "$ASIDE$suffix"; else rm -f "$DB$suffix"; fi
  fi
done

chown -h "$SVC_USER:$SVC_USER" "$TMP_DB"
mv -T "$TMP_DB" "$DB"

start_service "the previous database is kept as $ASIDE" "прежняя база сохранена как $ASIDE"

echo
echo "OK. Restored from $SOURCE"
echo "Готово. База восстановлена из $SOURCE"
if [ -e "$ASIDE" ]; then
  echo "Previous database: $ASIDE (with -wal/-shm if there were any) - delete it when everything looks right"
  echo "Прежняя база: $ASIDE (вместе с -wal/-shm, если были) - удалите, когда убедитесь, что всё в порядке"
fi
