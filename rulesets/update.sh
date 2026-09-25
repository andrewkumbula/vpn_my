#!/usr/bin/env bash
# Скачивает .srs-списки (geosite/geoip), на которые ссылается render_client.py.
# Список имён — здесь и только здесь, чтобы не разъезжалось с конфигом.
# Дёргается командой `./vpn обнови`.
#
# Внимание: bash в этом окружении не понимает кириллицу в именах переменных
# (`ИМЯ=значение` тихо превращается в попытку запустить файл "ИМЯ=значение"),
# поэтому переменные здесь латиницей, а комментарии и вывод — по-русски.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

GEOSITE_BASE="https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set"
GEOIP_BASE="https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set"

GEOSITE_LISTS=(
  geosite-category-ads-all
  geosite-google
  geosite-telegram
  geosite-youtube
  geosite-twitter
  geosite-instagram
  geosite-whatsapp
  geosite-speedtest
)
GEOIP_LISTS=(
  geoip-ru
)

echo "Скачиваю списки в ${DIR}..."
for name in "${GEOSITE_LISTS[@]}"; do
  curl -fsSL --max-time 15 "${GEOSITE_BASE}/${name}.srs" -o "${DIR}/${name}.srs"
  echo "  ✓ ${name}.srs"
done
for name in "${GEOIP_LISTS[@]}"; do
  curl -fsSL --max-time 15 "${GEOIP_BASE}/${name}.srs" -o "${DIR}/${name}.srs"
  echo "  ✓ ${name}.srs"
done

# Веб-панель clash (metacubexd): графики трафика, логи, правила, переключение
# узлов — то, что sing-box отдаёт на 127.0.0.1:9090/ui. Скачиваем сюда же, а не
# в git: это готовый артефакт релиза, не исходник.
UI_DIR="$(dirname "${DIR}")/ui-panel"
if [[ ! -f "${UI_DIR}/index.html" ]]; then
  echo "Скачиваю веб-панель clash в ${UI_DIR}..."
  mkdir -p "${UI_DIR}"
  if curl -fsSL --max-time 90 \
      "https://github.com/MetaCubeX/metacubexd/releases/latest/download/compressed-dist.tgz" \
      -o "${UI_DIR}/.ui.tgz"; then
    tar xzf "${UI_DIR}/.ui.tgz" -C "${UI_DIR}" && rm -f "${UI_DIR}/.ui.tgz"
    echo "  ✓ панель на месте (откроется на http://127.0.0.1:9090/ui)"
  else
    echo "  ✗ не скачалась — не страшно, туннель работает и без неё" >&2
  fi
else
  echo "Веб-панель clash уже на месте."
fi

echo "Готово."
