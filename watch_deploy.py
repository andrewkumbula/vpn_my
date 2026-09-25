#!/usr/bin/env python3
"""Раскатывает присмотр (server_check.py) на сервер: копирует скрипт, ставит
systemd-таймер (каждые 5 минут). По умолчанию dry-run — реально применяет
только --apply.
"""
import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

КОРЕНЬ = Path(__file__).resolve().parent
SCRIPT_НА_СЕРВЕРЕ = "/usr/local/libexec/vpnctl-watch/server_check.py"

SERVICE_UNIT = f"""[Unit]
Description=vpnctl — присмотр за x-ui (запускается таймером)

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 {SCRIPT_НА_СЕРВЕРЕ}
"""

TIMER_UNIT = """[Unit]
Description=vpnctl — присмотр каждые 5 минут

[Timer]
OnBootSec=1min
OnUnitActiveSec=5min
Unit=vpnctl-watch.service

[Install]
WantedBy=timers.target
"""


def загрузить_серверы():
    with open(КОРЕНЬ / "servers.json", encoding="utf-8") as f:
        return json.load(f)["servers"]


def ssh_команда(сервер, аргументы, таймаут=20):
    ssh = сервер["ssh"]
    ключ = Path(ssh["ключ"]).expanduser()
    return [
        "ssh", "-i", str(ключ), "-p", str(ssh.get("порт", 22)),
        "-o", f"ConnectTimeout={таймаут}", "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        f"{ssh['пользователь']}@{сервер['host']}", *аргументы,
    ]


def записать_файл_на_сервере(сервер, содержимое, путь):
    subprocess.run(
        ssh_команда(сервер, ["tee", путь]),
        input=содержимое.encode(), stdout=subprocess.DEVNULL, check=True,
    )


def main():
    парсер = argparse.ArgumentParser(description=__doc__)
    парсер.add_argument("сервер", help="имя сервера из servers.json")
    парсер.add_argument("--apply", action="store_true")
    аргс = парсер.parse_args()

    серверы = {s["имя"]: s for s in загрузить_серверы()}
    if аргс.сервер not in серверы:
        print(f"нет сервера с именем {аргс.сервер}", file=sys.stderr)
        return 1
    сервер = серверы[аргс.сервер]

    шаги = [
        f"создать /usr/local/libexec/vpnctl-watch",
        f"скопировать server_check.py → {SCRIPT_НА_СЕРВЕРЕ}",
        "положить /etc/systemd/system/vpnctl-watch.service",
        "положить /etc/systemd/system/vpnctl-watch.timer",
        "systemctl daemon-reload && systemctl enable --now vpnctl-watch.timer",
    ]
    for шаг in шаги:
        print(f"{'[apply]' if аргс.apply else '[dry-run]'} {шаг}")

    if not аргс.apply:
        print("\n(dry-run — добавь --apply, чтобы применить)")
        return 0

    # ОДНИМ ssh-подключением: этот хостер регулярно рвёт соединения (видно и по
    # обмену баннером при обычном ssh), а последовательность из шести отдельных
    # подключений почти гарантированно спотыкается на середине и оставляет
    # полуразвёрнутое состояние. Скрипт целиком уезжает на stdin и выполняется там.
    установщик = f"""set -e
mkdir -p /usr/local/libexec/vpnctl-watch
cat > {SCRIPT_НА_СЕРВЕРЕ} <<'КОНЕЦ_СКРИПТА'
{(КОРЕНЬ / "server_check.py").read_text(encoding="utf-8")}
КОНЕЦ_СКРИПТА
cat > /etc/systemd/system/vpnctl-watch.service <<'КОНЕЦ_СЕРВИСА'
{SERVICE_UNIT}
КОНЕЦ_СЕРВИСА
cat > /etc/systemd/system/vpnctl-watch.timer <<'КОНЕЦ_ТАЙМЕРА'
{TIMER_UNIT}
КОНЕЦ_ТАЙМЕРА
systemctl daemon-reload
systemctl enable --now vpnctl-watch.timer
systemctl start vpnctl-watch.service
echo "развёрнуто"
"""

    последняя_ошибка = None
    for попытка in (1, 2, 3):
        r = subprocess.run(
            ssh_команда(сервер, ["bash", "-s"]),
            input=установщик.encode(), capture_output=True, timeout=90,
        )
        if r.returncode == 0:
            print(r.stdout.decode().strip())
            break
        последняя_ошибка = r.stderr.decode().strip()
        print(f"  попытка {попытка} не удалась ({последняя_ошибка}) — повторяю", file=sys.stderr)
        time.sleep(10)
    else:
        print(f"не удалось развернуть за три попытки: {последняя_ошибка}", file=sys.stderr)
        return 1

    print("готово — первый прогон через ≤5 минут (или systemctl start vpnctl-watch.service сразу же)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
