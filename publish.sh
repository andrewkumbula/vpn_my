#!/usr/bin/env bash
# Переносит привилегированную часть в root-владение и выдаёт NOPASSWD sudo РОВНО
# на один файл (privileged/vpn-run). Запускать от обычного пользователя (не через
# sudo) — sudo дёргается точечно внутри, так виднее, что именно требует root.
#
# Переменные — латиницей (bash здесь не умеет кириллицу в левой части `имя=значение`,
# см. комментарий в privileged/vpn-run), команды и вывод — по-русски.
#
# Плата за bundle_bin.py: `brew upgrade sing-box` сюда не приезжает — после
# апгрейда бандл в /usr/local/libexec/vpnctl устарел молча. Перезапускай этот
# скрипт после любого `brew upgrade`, которое касается sing-box.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="/usr/local/libexec/vpnctl"
SUDOERS_FILE="/etc/sudoers.d/vpnctl"
SINGBOX_SRC="$(command -v sing-box || true)"
CURRENT_USER="$(id -un)"

if [[ -z "$SINGBOX_SRC" ]]; then
  echo "sing-box не найден в PATH — 'brew install sing-box/sing-box' сначала" >&2
  exit 1
fi

echo "Публикую vpnctl для пользователя ${CURRENT_USER}..."
echo "Понадобится sudo — попросит пароль один раз, дальше держит сессию."
sudo -v

# Держим sudo-сессию живой на время долгих шагов (bundle_bin.py может занять
# несколько секунд на подпись).
( while true; do sudo -n true; sleep 60; kill -0 "$$" 2>/dev/null || exit; done ) &
KEEPALIVE_PID=$!
trap 'kill "$KEEPALIVE_PID" 2>/dev/null || true' EXIT

echo "→ создаю ${BASE_DIR}"
sudo mkdir -p "$BASE_DIR/bin" "$BASE_DIR/rulesets" "$BASE_DIR/state"

echo "→ бандлю sing-box (копия + переподпись, без Homebrew-путей внутри)"
BUNDLE_TMP="$(mktemp -d)"
/usr/bin/python3 "$REPO_DIR/bundle_bin.py" "$SINGBOX_SRC" "$BUNDLE_TMP"
sudo rm -rf "$BASE_DIR/bin"
sudo cp -R "$BUNDLE_TMP" "$BASE_DIR/bin"
rm -rf "$BUNDLE_TMP"

echo "→ копирую vpn-run"
sudo cp "$REPO_DIR/privileged/vpn-run" "$BASE_DIR/vpn-run"

echo "→ копирую списки маршрутизации (rulesets/*.srs)"
sudo cp "$REPO_DIR"/rulesets/*.srs "$BASE_DIR/rulesets/" 2>/dev/null || {
  echo "  нет .srs файлов — сначала ./vpn обнови" >&2
  exit 1
}

echo "→ собираю клиентский конфиг (TUN) и переписываю пути на root-владение"
/usr/bin/python3 "$REPO_DIR/render_client.py" --mode tun --out "$REPO_DIR/state/client-tun.json"
# rulesets/*.srs в сгенерированном конфиге указывают на путь внутри репозитория
# (user-владение) — при публикации переписываем на то, что реально будет лежать
# в BASE_DIR. Та же грабля касается cache_file.
/usr/bin/python3 - "$REPO_DIR/state/client-tun.json" "$REPO_DIR" "$BASE_DIR" <<'PYEOF'
import json
import sys

client_path, repo_dir, base_dir = sys.argv[1:4]
with open(client_path, encoding="utf-8") as f:
    config = json.load(f)

for rs in config.get("route", {}).get("rule_set", []):
    if "path" in rs and rs["path"].startswith(repo_dir):
        rs["path"] = rs["path"].replace(repo_dir + "/rulesets", base_dir + "/rulesets", 1)

cache = config.get("experimental", {}).get("cache_file", {})
if "path" in cache and cache["path"].startswith(repo_dir):
    cache["path"] = cache["path"].replace(repo_dir + "/state", base_dir + "/state", 1)

with open(client_path, "w", encoding="utf-8") as f:
    json.dump(config, f, ensure_ascii=False, indent=2)
print("пути в client-tun.json переписаны на", base_dir)
PYEOF
sudo cp "$REPO_DIR/state/client-tun.json" "$BASE_DIR/client-tun.json"

echo "→ проверяю итоговый конфиг забандленным sing-box (грабля: не запускать демон вслепую)"
if ! sudo "$BASE_DIR/bin/sing-box" check -c "$BASE_DIR/client-tun.json"; then
  echo "sing-box check не прошёл — публикация остановлена, старая версия (если была) не тронута кроме vpn-run/бандла выше" >&2
  exit 1
fi

echo "→ выставляю root-владение на всё дерево (инвариант №3: бинарь и библиотеки тоже, не только скрипты/конфиги)"
sudo chown -R root:wheel "$BASE_DIR"
sudo chmod 755 "$BASE_DIR" "$BASE_DIR/vpn-run" "$BASE_DIR/bin" "$BASE_DIR/bin/sing-box" "$BASE_DIR/rulesets" "$BASE_DIR/state"
sudo find "$BASE_DIR/bin" -type f -exec chmod 755 {} \;
sudo find "$BASE_DIR/rulesets" -type f -exec chmod 644 {} \;
sudo chmod 644 "$BASE_DIR/client-tun.json"

echo "→ готовлю правило sudoers (NOPASSWD ровно на vpn-run, ничего сверх)"
SUDOERS_TMP="$(mktemp)"
echo "${CURRENT_USER} ALL=(root) NOPASSWD: ${BASE_DIR}/vpn-run" > "$SUDOERS_TMP"

echo "→ visudo -cf проверяет ДО установки — битый файл ломает sudo целиком (инвариант №5)"
if ! sudo visudo -cf "$SUDOERS_TMP"; then
  echo "правило sudoers не прошло проверку — НЕ устанавливаю" >&2
  rm -f "$SUDOERS_TMP"
  exit 1
fi

sudo cp "$SUDOERS_TMP" "$SUDOERS_FILE"
sudo chown root:wheel "$SUDOERS_FILE"
sudo chmod 440 "$SUDOERS_FILE"
rm -f "$SUDOERS_TMP"

echo
echo "Готово. Проверка:"
echo "  ls -l ${BASE_DIR}       — всё должно быть root:wheel"
echo "  sudo -l                 — покажет строку NOPASSWD на vpn-run"
echo "  ./vpn перехват           — теперь не должен спрашивать пароль"
