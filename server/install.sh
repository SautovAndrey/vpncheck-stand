#!/usr/bin/env bash
# VPNCheck agent server - установка на свой Linux-сервер (Debian 12 / Ubuntu 22.04+, Python 3.10+) / Linux installer.
#
#   sudo bash server/install.sh                  # из папки проекта, скопированной на сервер
#   sudo VPNCHECK_LANG=en bash server/install.sh # тексты сервера по-английски
#   sudo BEHIND_PROXY=1 bash server/install.sh   # только 127.0.0.1, порт наружу не открывать (TLS-прокси рядом)
#   sudo ENV_FILE=/path/to/file bash server/install.sh  # переменные из файла KEY=VALUE (файл удаляется)
#   sudo VPNAGENT_TLS_PORT=0 bash server/install.sh      # без TLS-порта (только http)
#
# Кладёт код сервера в /opt/vpnagent (владелец root), данные - в /opt/vpnagent/data (владелец vpnagent),
# ставит зависимости в venv, заводит systemd-сервис vpnagent (пользователь vpnagent, порт 8787)
# и печатает админ-токен для стенда (Агенты → Центр управления агентами).
# Второй порт (8788) - TLS с самоподписанным сертификатом в /opt/vpnagent/tls (10 лет): агенты сверяют отпечаток
# ключа (строка «TLS pin: sha256/...»). Сертификат создаётся один раз: если cert.pem и key.pem на месте и подходят
# друг к другу, повторная установка только чинит владельца и права (даже после копирования не от root).
# Битые или чужие друг другу файлы - установка останавливается; новый ключ - только при
# VPNAGENT_TLS_REGENERATE=1. Сохраните /opt/vpnagent/tls вместе с базой: без этого ключа агенты 0.12.9+
# после переустановки сервера замолчат. Копия ключа - в data/backups/tls-ГГГГММДД.tar, вернуть: restore.sh tls.
# Повторный запуск обновляет код и сохраняет токен, настройки Telegram, язык, порт и базу:
# не заданные переменные берутся из прежней установки. Старая раскладка (всё в /opt/vpnagent)
# переносится в data/ автоматически.
# Переменные: ADMIN_TOKEN, VPNCHECK_LANG, TG_BOT_TOKEN, TG_ADMIN, PORT, HOST, BEHIND_PROXY, ENV_FILE,
# VPNAGENT_TLS_PORT (0 - без TLS), TLS_NAME (имя в новом сертификате, по умолчанию внешний IP),
# VPNAGENT_TLS_REGENERATE=1 (новый ключ TLS вместо прежнего - прежний отложен рядом как *.old.<pid>).
# Альтернатива с Windows без входа на сервер: python server/deploy.py (по SSH, запускает этот же скрипт).
set -euo pipefail

DIR="${VPNAGENT_DIR:-/opt/vpnagent}"
DATA="$DIR/data"
UNIT="${VPNAGENT_UNIT:-/etc/systemd/system/vpnagent.service}"
SYSCTL_FILE="${VPNAGENT_SYSCTL:-/etc/sysctl.d/90-vpnagent.conf}"
SVC_USER=vpnagent
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_ITEMS="agents.db agents.db-wal agents.db-shm agents.db-journal state.json backups files service-account.json"
CODE_ITEMS="venv static __pycache__ requirements.txt"
ENV_KEEP='^(VPNAGENT_[A-Z0-9_]+|HTTPS?_PROXY|https?_proxy|NO_PROXY|no_proxy|ALL_PROXY|all_proxy)='
ENV_OWN='^(ADMIN_TOKEN|VPNCHECK_LANG|TG_BOT_TOKEN|TG_ADMIN|VPNAGENT_DATA)='

die() { echo "$*" >&2; exit 1; }

if [ "$(id -u)" -ne 0 ]; then die "run as root: sudo bash $0
запустите от root: sudo bash $0"; fi
if [ ! -f "$HERE/run.py" ] || [ ! -f "$HERE/app.py" ]; then die "server/run.py or server/app.py not found: copy the whole server folder or use server/deploy.py
нет server/run.py или server/app.py: скопируйте папку server целиком или выкатывайте через server/deploy.py"; fi
if [ ! -f "$HERE/../stand/node_fields.json" ]; then die "stand/node_fields.json not found: copy the whole project folder or use server/deploy.py
нет stand/node_fields.json: скопируйте папку проекта целиком или выкатывайте через server/deploy.py"; fi

if [ -n "${ENV_FILE:-}" ]; then
  if [ -L "$ENV_FILE" ] || [ ! -f "$ENV_FILE" ]; then die "ENV_FILE is not a regular file: $ENV_FILE"; fi
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%$'\r'}"
    case "$line" in
      ADMIN_TOKEN=*|VPNCHECK_LANG=*|TG_BOT_TOKEN=*|TG_ADMIN=*|PORT=*|HOST=*|BEHIND_PROXY=*|VPNAGENT_TLS_PORT=*|TLS_NAME=*|VPNAGENT_TLS_REGENERATE=*)
        printf -v "${line%%=*}" '%s' "${line#*=}" ;;
    esac
  done < "$ENV_FILE"
  rm -f "$ENV_FILE"
fi

check_token() { case "$1" in *[!A-Za-z0-9._~+/=-]*) die "bad ADMIN_TOKEN: use letters, digits and ._~+/=-" ;; esac; }
check_port() { case "$1" in ''|*[!0-9]*) die "bad PORT: $1" ;; esac; }
check_host() { case "$1" in *[!0-9A-Za-z.:-]*) die "bad HOST: $1" ;; esac; }
check_token "${ADMIN_TOKEN:-}"
if [ -n "${PORT:-}" ]; then check_port "$PORT"; fi
check_host "${HOST:-}"
if [ -n "${VPNAGENT_TLS_PORT:-}" ]; then check_port "$VPNAGENT_TLS_PORT"; fi
check_host "${TLS_NAME:-}"
TLS_REGENERATE="${VPNAGENT_TLS_REGENERATE:-0}"
case "$TLS_REGENERATE" in 0|1) ;; *) die "bad VPNAGENT_TLS_REGENERATE: use 0 or 1" ;; esac

echo "* packages"
if command -v apt-get >/dev/null; then
  apt-get update -q >/dev/null
  apt-get install -y -q python3 python3-venv curl openssl >/dev/null
fi
if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'; then
  die "Python 3.10+ is required (Debian 12 / Ubuntu 22.04+), found: $(python3 -V 2>&1 || echo none)
Нужен Python 3.10+ (Debian 12 / Ubuntu 22.04+), найден: $(python3 -V 2>&1 || echo нет)"
fi

echo "* user $SVC_USER"
if ! id -u "$SVC_USER" >/dev/null 2>&1; then
  NOLOGIN="$(command -v nologin || echo /bin/false)"
  useradd --system --no-create-home --home-dir "$DIR" --shell "$NOLOGIN" "$SVC_USER"
fi

TMP_TOKEN=""
TMP_ENV=""
WAS_ACTIVE=0
MIGRATING=0
on_exit() {
  local rc=$?
  rm -f "$TMP_TOKEN" "$TMP_ENV"
  if [ "$rc" -ne 0 ] && [ "$WAS_ACTIVE" = 1 ] && [ "$MIGRATING" = 0 ]; then
    systemctl start vpnagent >/dev/null 2>&1 || true
  fi
}
trap on_exit EXIT
if command -v systemctl >/dev/null; then
  if systemctl is-active --quiet vpnagent; then WAS_ACTIVE=1; fi
  systemctl stop vpnagent >/dev/null 2>&1 || true
fi

TLS_DIR="$DIR/tls"
for path in "$DIR" "$DATA" "$DIR/env" "$DIR/admin_token" "$TLS_DIR" "$TLS_DIR/cert.pem" "$TLS_DIR/key.pem"; do
  if [ -L "$path" ]; then die "$path is a symbolic link - remove it and run the installer again
$path - символическая ссылка: уберите её и запустите установку ещё раз"; fi
done
for path in "$DIR/env" "$DIR/admin_token" "$TLS_DIR/cert.pem" "$TLS_DIR/key.pem"; do
  if [ -e "$path" ] && [ ! -f "$path" ]; then die "$path is not a regular file - move it away and run the installer again
$path - не обычный файл: уберите его и запустите установку ещё раз"; fi
done

old_env() {
  [ -f "$DIR/env" ] || return 0
  grep -E "^$1=" "$DIR/env" | tail -n 1 | cut -d= -f2- | tr -d '\r' || true
}

old_unit_arg() {
  [ -f "$UNIT" ] || return 0
  grep -oE -- "--$1 [^ ]+" "$UNIT" | tail -n 1 | cut -d' ' -f2 || true
}

new_token() {
  head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n'
}

TOKEN_FILE="$DIR/admin_token"
FILE_TOKEN=""
if [ -f "$TOKEN_FILE" ] && [ -s "$TOKEN_FILE" ]; then FILE_TOKEN="$(head -c 512 "$TOKEN_FILE" | tr -d ' \r\n')"; fi
ENV_TOKEN="$(old_env ADMIN_TOKEN)"
TOKEN="${ADMIN_TOKEN:-}"
if [ -z "$TOKEN" ] && [ -n "$ENV_TOKEN" ]; then
  TOKEN="$ENV_TOKEN"
  if [ -n "$FILE_TOKEN" ] && [ "$FILE_TOKEN" != "$ENV_TOKEN" ]; then
    echo "warning: $TOKEN_FILE differs from ADMIN_TOKEN in $DIR/env - keeping the one the service uses (env)" >&2
    echo "внимание: $TOKEN_FILE не совпадает с ADMIN_TOKEN в $DIR/env - оставлен токен сервиса (env)" >&2
  fi
fi
if [ -z "$TOKEN" ]; then TOKEN="$FILE_TOKEN"; fi
if [ -z "$TOKEN" ]; then TOKEN="$(new_token)"; fi
check_token "$TOKEN"

LANG_VALUE="${VPNCHECK_LANG:-$(old_env VPNCHECK_LANG)}"
LANG_VALUE="${LANG_VALUE:-ru}"
TG_TOKEN_VALUE="${TG_BOT_TOKEN-$(old_env TG_BOT_TOKEN)}"
TG_ADMIN_VALUE="${TG_ADMIN-$(old_env TG_ADMIN)}"

PORT="${PORT:-$(old_unit_arg port)}"
PORT="${PORT:-8787}"
check_port "$PORT"
case "${BEHIND_PROXY:-}" in
  1) HOST="${HOST:-127.0.0.1}" ;;
  0) HOST="${HOST:-0.0.0.0}" ;;
esac
HOST="${HOST:-$(old_unit_arg host)}"
HOST="${HOST:-0.0.0.0}"
check_host "$HOST"
LOCAL_ONLY=0
case "$HOST" in 127.*|::1|localhost) LOCAL_ONLY=1 ;; esac
TLS_PORT="${VPNAGENT_TLS_PORT:-$(old_unit_arg tls-port)}"
TLS_PORT="${TLS_PORT:-8788}"
check_port "$TLS_PORT"
if [ "$TLS_PORT" != 0 ] && [ "$TLS_PORT" = "$PORT" ]; then die "VPNAGENT_TLS_PORT must differ from PORT ($PORT)
VPNAGENT_TLS_PORT должен отличаться от PORT ($PORT)"; fi

tls_pin() {
  openssl x509 -in "$1" -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64
}

tls_match() {
  [ -f "$TLS_DIR/cert.pem" ] && [ -f "$TLS_DIR/key.pem" ] || return 1
  local cert_key key_key
  cert_key="$(openssl x509 -in "$TLS_DIR/cert.pem" -pubkey -noout 2>/dev/null)" || return 1
  key_key="$(openssl pkey -in "$TLS_DIR/key.pem" -passin pass: -pubout 2>/dev/null </dev/null)" || return 1
  [ -n "$cert_key" ] && [ "$cert_key" = "$key_key" ]
}

TLS_HAVE=0
if [ -e "$TLS_DIR/cert.pem" ] || [ -e "$TLS_DIR/key.pem" ]; then TLS_HAVE=1; fi
TLS_WANTED=0
if [ "$TLS_PORT" != 0 ] && [ "$LOCAL_ONLY" = 0 ]; then TLS_WANTED=1; fi
if [ -e "$TLS_DIR" ] && [ ! -d "$TLS_DIR" ]; then die "$TLS_DIR is not a folder - move it away and run the installer again
$TLS_DIR - не папка: уберите это и запустите установку ещё раз"; fi
if [ "$TLS_WANTED" = 1 ] && [ "$TLS_HAVE" = 1 ] && [ "$TLS_REGENERATE" != 1 ]; then
  if ! command -v openssl >/dev/null; then die "openssl not found, and $TLS_DIR holds the TLS key agents are pinned to - install openssl and run the installer again
нет openssl, а в $TLS_DIR лежит ключ TLS, к которому привязаны агенты: поставьте openssl и запустите установку ещё раз"; fi
  if ! tls_match; then die "$TLS_DIR: cert.pem and key.pem are missing, damaged or do not belong together - nothing changed.
Put back the pair from a backup (sudo bash $DIR/restore.sh tls) or, to make a NEW key that agents 0.12.9+ are not pinned to,
run again with VPNAGENT_TLS_REGENERATE=1 (agents 0.12.11+ then move to it after python server/deploy.py; 0.12.9-0.12.10 only after reinstalling the app)
$TLS_DIR: cert.pem и key.pem отсутствуют, повреждены или не подходят друг к другу - ничего не изменено.
Верните пару из бэкапа (sudo bash $DIR/restore.sh tls) или, чтобы создать НОВЫЙ ключ, к которому агенты 0.12.9+ не привязаны,
запустите ещё раз с VPNAGENT_TLS_REGENERATE=1 (агенты 0.12.11+ перейдут на него после python server/deploy.py; 0.12.9-0.12.10 - только после переустановки приложения)"; fi
fi
if [ "$TLS_WANTED" = 0 ] && [ -f "$TLS_DIR/cert.pem" ]; then
  echo "WARNING: the TLS port is being turned off (VPNAGENT_TLS_PORT=0 or BEHIND_PROXY), but $TLS_DIR/cert.pem exists:" >&2
  echo "agents 0.12.9+ pinned to it go silent until TLS is back or a signed manifest without tls is published (python server/deploy.py does it)" >&2
  echo "ВНИМАНИЕ: TLS-порт выключается (VPNAGENT_TLS_PORT=0 или BEHIND_PROXY), а $TLS_DIR/cert.pem есть:" >&2
  echo "агенты 0.12.9+ с этим отпечатком замолчат, пока TLS не вернут или не выложат подписанный манифест без tls (это делает python server/deploy.py)" >&2
fi

EXTRA_ENV=""
if [ -f "$DIR/env" ]; then
  EXTRA_ENV="$(tr -d '\r' < "$DIR/env" | grep -E "$ENV_KEEP" | grep -vE "$ENV_OWN" || true)"
  DROPPED="$(tr -d '\r' < "$DIR/env" | grep -E '^[^#[:space:]]' | grep -vE "$ENV_KEEP" | grep -vE "$ENV_OWN" \
    | cut -d= -f1 | tr '\n' ' ' || true)"
  if [ -n "$DROPPED" ]; then
    echo "warning: dropped unknown settings from $DIR/env: $DROPPED" >&2
    echo "внимание: из $DIR/env убраны неизвестные настройки: $DROPPED" >&2
  fi
fi

move_aside() {
  local target="$OLD/$2"
  if [ -e "$target" ] || [ -L "$target" ]; then target="$target.$$"; fi
  mv -T "$1" "$target"
}

umask 022
if [ -d "$DIR" ]; then
  MIGRATE=0
  DATA_TRUSTED=0
  DIR_OWNER="$(stat -c %u "$DIR")"
  if [ "$DIR_OWNER" != 0 ] || [ ! -d "$DATA" ]; then MIGRATE=1; fi
  if [ -d "$DATA" ] && [ ! -L "$DATA" ] && { [ "$DIR_OWNER" = 0 ] || [ "$(stat -c %u "$DATA")" = 0 ]; }; then
    DATA_TRUSTED=1
  fi
  for item in $DATA_ITEMS; do
    if [ -e "$DIR/$item" ] || [ -L "$DIR/$item" ]; then MIGRATE=1; fi
  done
  if [ "$MIGRATE" = 1 ]; then
    echo "* old layout: moving data to $DATA (service stopped)"
    MIGRATING=1
    chown -h root:root "$DIR"
    chmod 700 "$DIR"
    UNTRUSTED=""
    if [ -e "$DATA" ] || [ -L "$DATA" ]; then
      if [ "$DATA_TRUSTED" != 1 ]; then
        UNTRUSTED="$DIR/.untrusted-data.$$"
        mv -T "$DATA" "$UNTRUSTED"
        mkdir "$DATA" && chmod 700 "$DATA"
      fi
    else
      mkdir "$DATA" && chmod 700 "$DATA"
    fi
    chown -h root:root "$DATA"
    chmod 700 "$DATA"
    OLD="$DATA/old-install"
    if [ -L "$OLD" ] || { [ -e "$OLD" ] && [ ! -d "$OLD" ]; }; then
      die "$OLD is not a folder - move it away and run the installer again
$OLD - не папка: уберите это и запустите установку ещё раз"
    fi
    [ -d "$OLD" ] || { mkdir "$OLD" && chmod 700 "$OLD"; }
    for item in $DATA_ITEMS; do
      [ -e "$DIR/$item" ] || [ -L "$DIR/$item" ] || continue
      if [ -e "$DATA/$item" ] || [ -L "$DATA/$item" ]; then
        move_aside "$DIR/$item" "$item"
      else
        mv -T "$DIR/$item" "$DATA/$item"
      fi
    done
    if [ -n "$UNTRUSTED" ]; then move_aside "$UNTRUSTED" data; fi
    for item in $CODE_ITEMS; do rm -rf "${DIR:?}/$item"; done
    for path in "$DIR"/* "$DIR"/.[!.]*; do
      [ -e "$path" ] || [ -L "$path" ] || continue
      name="$(basename "$path")"
      case "$name" in
        data|env|admin_token|tls) ;;
        *.py) rm -f "$path" ;;
        *) move_aside "$path" "$name" ;;
      esac
    done
    find "$DATA" -xdev -type l -delete
    rmdir "$OLD" 2>/dev/null || true
    chown -R -h "$SVC_USER:$SVC_USER" "$DATA"
  fi
fi

echo "* files -> $DIR"
mkdir -p "$DIR"
chown -h root:"$SVC_USER" "$DIR"
chmod 750 "$DIR"
if [ ! -d "$DATA" ]; then mkdir "$DATA" && chmod 700 "$DATA"; fi
if [ -L "$DATA/files" ] || { [ -e "$DATA/files" ] && [ ! -d "$DATA/files" ]; }; then rm -f "$DATA/files"; fi
if [ ! -d "$DATA/files" ]; then mkdir "$DATA/files" && chmod 700 "$DATA/files"; fi
mkdir -p "$DIR/static"
for f in "$HERE"/*.py; do
  [ "$(basename "$f")" = "deploy.py" ] || install -m 644 "$f" "$DIR/"
done
install -m 644 "$HERE/requirements.txt" "$DIR/"
if [ -f "$HERE/restore.sh" ]; then install -m 755 "$HERE/restore.sh" "$DIR/"; fi
for f in "$HERE"/static/*; do
  if [ -f "$f" ]; then install -m 644 "$f" "$DIR/static/"; fi
done
REGIONS="$HERE/../stand/ui/assets/ru_regions.geojson"
if [ -f "$REGIONS" ]; then install -m 644 "$REGIONS" "$DIR/static/"; fi
if [ -f "$HERE/../stand/regions.json" ]; then install -m 644 "$HERE/../stand/regions.json" "$DIR/regions.json"; fi
install -m 644 "$HERE/../stand/node_fields.json" "$DIR/node_fields.json"
if [ -f "$HERE/service-account.json" ]; then
  rm -f "$DATA/service-account.json"
  install -o "$SVC_USER" -g "$SVC_USER" -m 600 "$HERE/service-account.json" "$DATA/service-account.json"
fi

tls_own() {
  chown -h root:"$SVC_USER" "$TLS_DIR/key.pem"
  chmod 640 "$TLS_DIR/key.pem"
  chown -h root:root "$TLS_DIR/cert.pem"
  chmod 644 "$TLS_DIR/cert.pem"
}

tls_create() {
  local name="${TLS_NAME:-}" san conf tmp_key tmp_cert
  if [ -z "$name" ]; then
    name="$(curl -fs --max-time 5 https://api.ipify.org || hostname -I 2>/dev/null | awk '{print $1}' || true)"
    case "$name" in ''|*[!0-9A-Fa-f.:]*) name=vpnagent ;; esac
  fi
  case "$name" in
    *:*) san="IP:$name" ;;
    *[!0-9.]*) san="DNS:$name" ;;
    *) san="IP:$name" ;;
  esac
  conf="$(mktemp "$TLS_DIR/.openssl.XXXXXX")"
  tmp_key="$(mktemp "$TLS_DIR/.key.XXXXXX")"
  tmp_cert="$(mktemp "$TLS_DIR/.cert.XXXXXX")"
  printf '%s\n' "[req]" "prompt = no" "distinguished_name = dn" "x509_extensions = ext" "[dn]" "CN = $name" \
    "[ext]" "subjectAltName = $san" "basicConstraints = critical, CA:FALSE" \
    "keyUsage = critical, digitalSignature" "extendedKeyUsage = serverAuth" > "$conf"
  if ( umask 077; openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
        -config "$conf" -keyout "$tmp_key" -out "$tmp_cert" >/dev/null 2>&1 ); then
    rm -f "$conf"
    chown -h root:"$SVC_USER" "$tmp_key"
    chmod 640 "$tmp_key"
    chown -h root:root "$tmp_cert"
    chmod 644 "$tmp_cert"
    mv -f "$tmp_key" "$TLS_DIR/key.pem"
    mv -f "$tmp_cert" "$TLS_DIR/cert.pem"
    return 0
  fi
  rm -f "$conf" "$tmp_key" "$tmp_cert"
  return 1
}

TLS_ON=0
TLS_NEW=0
if [ "$TLS_WANTED" = 1 ]; then
  echo "* TLS certificate $TLS_DIR"
  if ! command -v openssl >/dev/null; then
    echo "warning: openssl not found - TLS port $TLS_PORT is off, install openssl and run the installer again" >&2
    echo "внимание: нет openssl - TLS-порт $TLS_PORT выключен, поставьте openssl и запустите установку ещё раз" >&2
  else
    mkdir -p "$TLS_DIR"
    chown -h root:"$SVC_USER" "$TLS_DIR"
    chmod 750 "$TLS_DIR"
    if [ "$TLS_REGENERATE" = 1 ] && { [ -e "$TLS_DIR/cert.pem" ] || [ -e "$TLS_DIR/key.pem" ]; }; then
      echo "WARNING: VPNAGENT_TLS_REGENERATE=1 - making a NEW TLS key, the old pair is kept as $TLS_DIR/*.pem.old.$$" >&2
      echo "agents 0.12.9-0.12.10 pinned to the old key go silent until the app is reinstalled;" >&2
      echo "agents 0.12.11+ switch to the new key via the signed manifest after python server/deploy.py" >&2
      echo "ВНИМАНИЕ: VPNAGENT_TLS_REGENERATE=1 - создаю НОВЫЙ ключ TLS, прежняя пара отложена как $TLS_DIR/*.pem.old.$$" >&2
      echo "агенты 0.12.9-0.12.10 со старым отпечатком замолчат до переустановки приложения;" >&2
      echo "агенты 0.12.11+ перейдут на новый ключ через подписанный манифест после python server/deploy.py" >&2
      for f in cert.pem key.pem; do
        if [ -e "$TLS_DIR/$f" ]; then mv -f "$TLS_DIR/$f" "$TLS_DIR/$f.old.$$"; fi
      done
    fi
    if [ -f "$TLS_DIR/cert.pem" ] && [ -f "$TLS_DIR/key.pem" ]; then
      tls_own
      if ! tls_match; then die "$TLS_DIR: cert.pem and key.pem do not belong together - nothing changed in TLS, see the message above
$TLS_DIR: cert.pem и key.pem не подходят друг к другу - TLS не тронут, см. сообщение выше"; fi
      TLS_ON=1
    elif [ -e "$TLS_DIR/cert.pem" ] || [ -e "$TLS_DIR/key.pem" ]; then
      die "$TLS_DIR: only one of cert.pem / key.pem is there - put back the pair from a backup (sudo bash $DIR/restore.sh tls)
$TLS_DIR: есть только один из cert.pem / key.pem - верните пару из бэкапа (sudo bash $DIR/restore.sh tls)"
    elif tls_create && tls_match; then
      tls_own
      TLS_ON=1
      TLS_NEW=1
    else
      echo "warning: could not create a TLS certificate - TLS port $TLS_PORT is off" >&2
      echo "внимание: не удалось создать TLS-сертификат - TLS-порт $TLS_PORT выключен" >&2
    fi
  fi
fi
if [ "$TLS_ON" = 1 ]; then
  TLS_ARGS=" --tls-port $TLS_PORT --tls-cert $TLS_DIR/cert.pem --tls-key $TLS_DIR/key.pem"
elif [ "$TLS_PORT" = 0 ]; then
  TLS_ARGS=" --tls-port 0"
else
  TLS_ARGS=""
fi

echo "* python venv"
[ -d "$DIR/venv" ] || python3 -m venv "$DIR/venv"
"$DIR/venv/bin/pip" install -q --upgrade pip
"$DIR/venv/bin/pip" install -q -r "$DIR/requirements.txt"

echo "* systemd service vpnagent ($HOST:$PORT)"
TMP_TOKEN="$(mktemp "$DIR/.admin_token.XXXXXX")"
TMP_ENV="$(mktemp "$DIR/.env.XXXXXX")"
printf '%s\n' "$TOKEN" > "$TMP_TOKEN"
{
  echo "ADMIN_TOKEN=$TOKEN"
  echo "VPNCHECK_LANG=$LANG_VALUE"
  echo "TG_BOT_TOKEN=$TG_TOKEN_VALUE"
  echo "TG_ADMIN=$TG_ADMIN_VALUE"
  if [ -n "$EXTRA_ENV" ]; then printf '%s\n' "$EXTRA_ENV"; fi
} > "$TMP_ENV"

chown -h root:root "$TMP_TOKEN" "$TMP_ENV"
chmod 600 "$TMP_TOKEN" "$TMP_ENV"
mv -f "$TMP_TOKEN" "$TOKEN_FILE"
mv -f "$TMP_ENV" "$DIR/env"
chown -h "$SVC_USER:$SVC_USER" "$DATA" "$DATA/files"
chmod 700 "$DATA"

if [ ! -e "$SYSCTL_FILE" ] && [ -d "$(dirname "$SYSCTL_FILE")" ]; then
  printf '%s\n' net.ipv4.tcp_keepalive_time=180 net.ipv4.tcp_keepalive_intvl=30 net.ipv4.tcp_keepalive_probes=3 \
    > "$SYSCTL_FILE"
  chmod 644 "$SYSCTL_FILE"
  if command -v sysctl >/dev/null; then sysctl -q -p "$SYSCTL_FILE" >/dev/null 2>&1 || true; fi
fi

cat > "$UNIT" <<EOF
[Unit]
Description=VPNCheck agent server
After=network.target

[Service]
User=$SVC_USER
Group=$SVC_USER
WorkingDirectory=$DIR
Environment=VPNAGENT_DATA=$DATA
EnvironmentFile=$DIR/env
ExecStart=$DIR/venv/bin/python $DIR/run.py --host $HOST --port $PORT$TLS_ARGS --limit-concurrency 5000
Restart=always
RestartSec=3
LimitNOFILE=65536
MemoryMax=1500M
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
LockPersonality=yes
ReadWritePaths=$DATA

[Install]
WantedBy=multi-user.target
EOF
chmod 644 "$UNIT"
systemctl daemon-reload
systemctl enable vpnagent >/dev/null 2>&1
systemctl restart vpnagent

if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
  if [ "$LOCAL_ONLY" = "1" ]; then
    ufw delete allow "$PORT/tcp" >/dev/null 2>&1 || true
    if [ "$TLS_PORT" != 0 ]; then ufw delete allow "$TLS_PORT/tcp" >/dev/null 2>&1 || true; fi
  else
    ufw allow "$PORT/tcp" >/dev/null
  fi
  if [ "$TLS_ON" = 1 ]; then ufw allow "$TLS_PORT/tcp" >/dev/null; fi
fi

case "$HOST" in
  0.0.0.0) CHECK_HOST=127.0.0.1 ;;
  ::) CHECK_HOST="[::1]" ;;
  *:*) CHECK_HOST="[$HOST]" ;;
  *) CHECK_HOST="$HOST" ;;
esac
HEALTH="http://$CHECK_HOST:$PORT/health"
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
  curl -fs "$HEALTH" >/dev/null && break
  sleep 1
done
curl -fs "$HEALTH" >/dev/null || die "service did not start: journalctl -u vpnagent -n 50
сервис не запустился - смотрите: journalctl -u vpnagent -n 50"
TLS_PIN=""
if [ "$TLS_ON" = 1 ]; then
  TLS_HEALTH="https://$CHECK_HOST:$TLS_PORT/health"
  for _ in 1 2 3 4 5; do
    curl -fsk --max-time 5 "$TLS_HEALTH" >/dev/null && break
    sleep 1
  done
  if curl -fsk --max-time 5 "$TLS_HEALTH" >/dev/null; then
    TLS_PIN="$(tls_pin "$TLS_DIR/cert.pem")"
  else
    echo "WARNING: TLS port $TLS_PORT does not answer - agents 0.12.9+ already pinned to it go silent: journalctl -u vpnagent -n 50" >&2
    echo "ВНИМАНИЕ: TLS-порт $TLS_PORT не отвечает - агенты 0.12.9+, уже привязанные к нему, замолчат: journalctl -u vpnagent -n 50" >&2
  fi
fi

echo
if [ "$LOCAL_ONLY" = "1" ]; then
  echo "OK. Server: http://$CHECK_HOST:$PORT (local only - put a TLS proxy in front, see SECURITY.md)"
  echo "Сервер слушает только $CHECK_HOST:$PORT - снаружи через TLS-прокси (SECURITY.md)"
  echo "Admin page (phone/browser): https://<your proxy domain>/admin"
  echo "Страница центра с телефона или в браузере: https://<домен прокси>/admin"
else
  IP="$(curl -fs --max-time 5 https://api.ipify.org || hostname -I | awk '{print $1}')"
  echo "OK. Server: http://$IP:$PORT"
  echo "Готово. Сервер: http://$IP:$PORT"
  echo "Admin page (phone/browser): http://$IP:$PORT/admin"
  echo "Страница центра с телефона или в браузере: http://$IP:$PORT/admin"
fi
echo "Data: $DATA"
if [ -n "$TLS_PIN" ]; then
  echo "TLS port: $TLS_PORT"
  echo "TLS pin: sha256/$TLS_PIN"
  if [ "$TLS_NEW" = 1 ]; then
    echo "New TLS key: keep a copy of $TLS_DIR (cert.pem + key.pem) off this server together with the database"
    echo "Новый ключ TLS: сохраните копию $TLS_DIR (cert.pem + key.pem) вне этого сервера вместе с базой"
  fi
fi
if [ -n "$TG_TOKEN_VALUE" ] && [ -n "$TG_ADMIN_VALUE" ]; then
  if [ "$LANG_VALUE" = en ]; then TG_TEXT="VPNCheck: test message from the installer - alerts will come to this chat."
  else TG_TEXT="VPNCheck: пробное сообщение от установщика - тревоги будут приходить в этот чат."; fi
  TG_PROXY="$(printf '%s
' "$EXTRA_ENV" | grep -iE '^https_proxy=' | tail -n 1 | cut -d= -f2- || true)"
  TG_REPLY="$( {
    printf 'url = "https://api.telegram.org/bot%s/sendMessage"
' "$TG_TOKEN_VALUE"
    if [ -n "$TG_PROXY" ]; then printf 'proxy = "%s"
' "$TG_PROXY"; fi
  } | curl -s --max-time 15 -K - --data-urlencode "chat_id=$TG_ADMIN_VALUE" --data-urlencode "text=$TG_TEXT" 2>&1 || true)"
  case "$TG_REPLY" in
    *'"ok":true'*)
      echo "Telegram alerts: on (a test message was sent)"
      echo "Тревоги в Telegram: включены (отправлено пробное сообщение)" ;;
    *)
      TG_ERROR="$(printf '%s' "$TG_REPLY" | grep -oE '"description":"[^"]*"' | cut -d'"' -f4 || true)"
      TG_ERROR="${TG_ERROR:-${TG_REPLY:-no answer from api.telegram.org}}"
      echo "Telegram alerts: test message failed - $TG_ERROR (check TG_BOT_TOKEN and TG_ADMIN, README, Telegram alerts)"
      echo "Тревоги в Telegram: пробное сообщение не ушло - $TG_ERROR (проверьте TG_BOT_TOKEN и TG_ADMIN, README, «Тревоги в Telegram»)" ;;
  esac
else
  echo "Telegram alerts: off - set TG_BOT_TOKEN and TG_ADMIN (README, Telegram alerts)"
  echo "Тревоги в Telegram: выключены - задайте TG_BOT_TOKEN и TG_ADMIN (README, «Тревоги в Telegram»)"
fi
echo "Admin token (stand -> Agents -> Agent control center): $TOKEN"
echo "Токен админа (стенд -> Агенты -> Центр управления агентами): $TOKEN"
