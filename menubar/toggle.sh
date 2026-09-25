#!/usr/bin/env bash
# Дёргается кликом из SwiftBar (vpn.5s.sh передаёт param1/param2). Прокладка на
# `./vpn` и clash API — своей логики не держит.
set -euo pipefail

REPO_DIR="/Users/andrejkumbula/Documents/оптима/Програмки/vpn"
CLASH="http://127.0.0.1:9090"
ACTION="${1:-}"
ARG="${2:-}"

# Имена групп кириллические — в URL их надо процентно кодировать, иначе clash
# API отвечает 404 (ловилось вживую).
закодировать() {
  /usr/bin/python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$1"
}

выбрать() {
  local GROUP_ENC
  GROUP_ENC=$(закодировать "$1")
  curl -fsS --max-time 3 -X PUT -H "Content-Type: application/json" \
       -d "{\"name\": \"$2\"}" "${CLASH}/proxies/${GROUP_ENC}" >/dev/null
}

case "$ACTION" in
  режим)
    # выбор → авто | вручную | direct
    выбрать "выбор" "$ARG"
    ;;
  узел)
    # «держаться одного узла»: закрепляем узел в «вручную» и переводим режим
    # туда же — иначе закрепление ни на что не влияет, пока активен «авто».
    выбрать "вручную" "$ARG"
    выбрать "выбор" "вручную"
    ;;
  морда)
    "${REPO_DIR}/vpn" морда >/dev/null 2>&1 || open "http://127.0.0.1:7890/"
    ;;
  перехват|стоп|старт)
    "${REPO_DIR}/vpn" "$ACTION"
    ;;
  *)
    echo "toggle.sh: неизвестное действие '$ACTION'" >&2
    exit 1
    ;;
esac
