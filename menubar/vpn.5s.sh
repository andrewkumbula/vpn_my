#!/usr/bin/env bash
# SwiftBar-плагин (символьная ссылка на этот файл кладётся в каталог плагинов
# SwiftBar — см. menubar/install.sh). Суффикс .5s — обновление раз в 5 секунд.
#
# По ТЗ показывает: флаг страны активного узла, задержку, переключение режима,
# «держаться одного узла», ссылки на морду и панель узлов.
#
# Путь до репозитория захардкожен: SwiftBar запускает плагин в своём окружении,
# без профиля шелла и без гарантий про cwd. Переехал репозиторий — поправь.
# Переменные латиницей (bash не понимает кириллицу слева от `=`).
set -euo pipefail

REPO_DIR="/Users/andrejkumbula/Documents/оптима/Програмки/vpn"
CLASH="http://127.0.0.1:9090"
TOGGLE="${REPO_DIR}/menubar/toggle.sh"
PY="/usr/bin/python3"

# --- выключено ---------------------------------------------------------------
if ! pgrep -f "sing-box run" >/dev/null 2>&1; then
  echo "○ vpn"
  echo "---"
  echo "выключен"
  echo "включить локально | bash='${TOGGLE}' param1=старт terminal=false refresh=true"
  echo "включить перехват | bash='${TOGGLE}' param1=перехват terminal=false refresh=true"
  echo "---"
  echo "морда | bash='${TOGGLE}' param1=морда terminal=false"
  exit 0
fi

# --- включено: спрашиваем clash API одним запросом ----------------------------
SNAPSHOT=$(curl -fsS --max-time 2 "${CLASH}/proxies" 2>/dev/null || echo "")
if [[ -z "$SNAPSHOT" ]]; then
  echo "◐ vpn"
  echo "---"
  echo "запущен, но clash API молчит"
  echo "выключить | bash='${TOGGLE}' param1=стоп terminal=false refresh=true"
  exit 0
fi

# Разбираем ответ один раз: активный узел, его задержка, режим, список узлов.
PARSED=$(echo "$SNAPSHOT" | "$PY" -c '
import json, sys
d = json.load(sys.stdin).get("proxies", {})

def развернуть(имя, глубина=4):
    """выбор → авто → конкретный узел: показываем страну узла, не имя группы."""
    while глубина and имя in d and d[имя].get("now"):
        имя = d[имя]["now"]
        глубина -= 1
    return имя

режим = d.get("выбор", {}).get("now", "?")
узел = развернуть("выбор")
история = (d.get(узел, {}).get("history") or [])
задержка = история[-1]["delay"] if история and история[-1].get("delay") else 0
служебные = {"block", "dns-out", "GLOBAL", "direct", "авто", "вручную", "выбор"}
узлы = [и for и, з in d.items()
        if и not in служебные and з.get("type") not in ("Selector", "URLTest")]
варианты = d.get("выбор", {}).get("all", [])
закреплён = d.get("вручную", {}).get("now", "")

print(режим); print(узел); print(задержка)
print(",".join(варианты)); print(",".join(узлы)); print(закреплён)
' 2>/dev/null || echo "")

if [[ -z "$PARSED" ]]; then
  echo "◐ vpn"; echo "---"; echo "не разобрать ответ clash API"; exit 0
fi

MODE=$(echo "$PARSED" | sed -n 1p)
NODE=$(echo "$PARSED" | sed -n 2p)
DELAY=$(echo "$PARSED" | sed -n 3p)
CHOICES=$(echo "$PARSED" | sed -n 4p)
NODES=$(echo "$PARSED" | sed -n 5p)
PINNED=$(echo "$PARSED" | sed -n 6p)

# Флаг страны из servers.json. Тег узла — "<сервер>-<ремарка>", но и в имени
# сервера бывает дефис (senko-1), поэтому режем не по первому дефису, а ищем имя
# сервера как ПРЕФИКС тега — иначе флаг всегда падал в 🌐.
FLAG=$("$PY" -c "
import json
try:
    d = json.load(open('${REPO_DIR}/servers.json', encoding='utf-8'))
    тег = '${NODE}'
    подходящие = [s for s in d['servers'] if тег == s['имя'] or тег.startswith(s['имя'] + '-')]
    подходящие.sort(key=lambda s: len(s['имя']), reverse=True)
    print(подходящие[0].get('флаг', '🌐') if подходящие else '🌐')
except Exception:
    print('🌐')
" 2>/dev/null || echo "🌐")

if [[ "$DELAY" == "0" ]]; then
  echo "${FLAG} vpn"
else
  echo "${FLAG} ${DELAY}мс"
fi
echo "---"
echo "узел: ${NODE}"
echo "режим: ${MODE}"
echo "---"

# Переключение режима (выбор → авто/вручную/direct)
echo "Режим"
IFS=',' read -ra CHOICE_LIST <<< "$CHOICES"
for choice in "${CHOICE_LIST[@]}"; do
  [[ -z "$choice" ]] && continue
  MARK=" "
  [[ "$choice" == "$MODE" ]] && MARK="✓"
  echo "--${MARK} ${choice} | bash='${TOGGLE}' param1=режим param2='${choice}' terminal=false refresh=true"
done

# «Держаться одного узла» — закрепление конкретного узла в группе «вручную»
echo "Держаться узла"
IFS=',' read -ra NODE_LIST <<< "$NODES"
for node in "${NODE_LIST[@]}"; do
  [[ -z "$node" ]] && continue
  MARK=" "
  [[ "$node" == "$PINNED" && "$MODE" == "вручную" ]] && MARK="✓"
  echo "--${MARK} ${node} | bash='${TOGGLE}' param1=узел param2='${node}' terminal=false refresh=true"
done

echo "---"
echo "выключить | bash='${TOGGLE}' param1=стоп terminal=false refresh=true"
echo "морда | bash='${TOGGLE}' param1=морда terminal=false"
echo "панель узлов | href=http://127.0.0.1:9090/ui/"
