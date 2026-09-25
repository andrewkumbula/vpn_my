#!/usr/bin/env bash
# Ставит плагин в SwiftBar символьной ссылкой — так правки в репозитории
# подхватываются сразу, без переустановки.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLUGIN="${REPO_DIR}/menubar/vpn.5s.sh"

if ! command -v swiftbar >/dev/null 2>&1 && [[ ! -d "/Applications/SwiftBar.app" ]]; then
  echo "SwiftBar не установлен. Поставь: brew install --cask swiftbar" >&2
  echo "После установки запусти SwiftBar, он спросит каталог плагинов, потом повтори этот скрипт." >&2
  exit 1
fi

# Каталог плагинов SwiftBar хранит в своих настройках.
PLUGIN_DIR=$(defaults read com.ameba.SwiftBar PluginDirectory 2>/dev/null || echo "")
if [[ -z "$PLUGIN_DIR" || ! -d "$PLUGIN_DIR" ]]; then
  echo "Не нашёл каталог плагинов SwiftBar." >&2
  echo "Открой SwiftBar → Preferences → Plugin Folder, задай каталог, потом повтори." >&2
  exit 1
fi

ln -sf "$PLUGIN" "${PLUGIN_DIR}/vpn.5s.sh"
echo "Готово: ${PLUGIN_DIR}/vpn.5s.sh → ${PLUGIN}"
echo "Обнови плагины в SwiftBar (иконка → Refresh All) — в строке меню появится флаг и задержка."
