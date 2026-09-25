#!/usr/bin/env python3
"""Раскатывает read-only морду на сервер: копирует ui_server_readonly.py + его
зависимости (remote_dump.py, links.py, ui_page.html), генерирует пароль
(PBKDF2-хэш едет на сервер, ПЛЕЙНТЕКСТ — только в вывод терминала один раз,
сохрани сам), ставит systemd-сервис, слушающий 127.0.0.1:порт (инвариант №9).
По умолчанию dry-run — реально применяет только --apply.
"""
import argparse
import hashlib
import json
import os
import secrets
import subprocess
import sys
from pathlib import Path

КОРЕНЬ = Path(__file__).resolve().parent
ФАЙЛЫ = ["ui_server_readonly.py", "remote_dump.py", "links.py", "ui_page.html"]
УСТАНОВКА_ДИР = "/usr/local/libexec/vpnctl-ui"

SERVICE_UNIT_TEMPLATE = """[Unit]
Description=vpnctl — read-only морда (localhost:{порт})
After=network.target

[Service]
Type=simple
Environment=VPNCTL_UI_PORT={порт}
ExecStart=/usr/bin/python3 {каталог}/ui_server_readonly.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
"""


def загрузить_морду():
    with open(КОРЕНЬ / "servers.json", encoding="utf-8") as f:
        данные = json.load(f)
    морда = данные.get("морда")
    if not морда:
        raise SystemExit("в servers.json нет секции 'морда' — нечего разворачивать")
    return морда, данные["servers"]


def ssh_команда(сервер, аргументы, таймаут=20):
    ssh = сервер["ssh"]
    ключ = Path(ssh["ключ"]).expanduser()
    return [
        "ssh", "-i", str(ключ), "-p", str(ssh.get("порт", 22)),
        "-o", f"ConnectTimeout={таймаут}", "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        f"{ssh['пользователь']}@{сервер['host']}", *аргументы,
    ]


def записать_на_сервере(сервер, содержимое_bytes, путь):
    subprocess.run(
        ssh_команда(сервер, ["tee", путь]),
        input=содержимое_bytes, stdout=subprocess.DEVNULL, check=True,
    )


def main():
    парсер = argparse.ArgumentParser(description=__doc__)
    парсер.add_argument("--apply", action="store_true")
    аргс = парсер.parse_args()

    морда, серверы = загрузить_морду()
    сервер = next((s for s in серверы if s["имя"] == морда["сервер"]), None)
    if сервер is None:
        raise SystemExit(f"сервер {морда['сервер']!r} из секции 'морда' не найден в servers.json")

    порт = морда["порт"]
    пароль = secrets.token_urlsafe(18)
    соль = os.urandom(16)
    хэш = hashlib.pbkdf2_hmac("sha256", пароль.encode(), соль, 200_000).hex()
    хэш_файл_содержимое = f"{соль.hex()}:{хэш}".encode()

    шаги = [
        f"создать {УСТАНОВКА_ДИР} на {сервер['имя']}",
        f"скопировать: {', '.join(ФАЙЛЫ)}",
        "сгенерировать пароль, положить password.hash (не плейнтекст)",
        f"положить systemd unit vpnctl-ui.service (слушает 127.0.0.1:{порт})",
        "systemctl daemon-reload && systemctl enable --now vpnctl-ui.service",
    ]
    for шаг in шаги:
        print(f"{'[apply]' if аргс.apply else '[dry-run]'} {шаг}")

    if not аргс.apply:
        print("\n(dry-run — добавь --apply, чтобы применить)")
        return 0

    subprocess.run(ssh_команда(сервер, ["mkdir", "-p", УСТАНОВКА_ДИР]), check=True)
    for имя_файла in ФАЙЛЫ:
        with open(КОРЕНЬ / имя_файла, "rb") as f:
            записать_на_сервере(сервер, f.read(), f"{УСТАНОВКА_ДИР}/{имя_файла}")

    записать_на_сервере(сервер, хэш_файл_содержимое, f"{УСТАНОВКА_ДИР}/password.hash")

    unit = SERVICE_UNIT_TEMPLATE.format(порт=порт, каталог=УСТАНОВКА_ДИР)
    записать_на_сервере(сервер, unit.encode(), "/etc/systemd/system/vpnctl-ui.service")

    subprocess.run(ssh_команда(сервер, ["systemctl", "daemon-reload"]), check=True)
    subprocess.run(ssh_команда(сервер, ["systemctl", "enable", "--now", "vpnctl-ui.service"]), check=True)

    print(f"\nготово. Пароль морды (сохрани, больше нигде не показан):\n\n  {пароль}\n")
    print(f"Открой через свой же туннель: http://{морда['хост']}:{порт}/  (личный туннель должен быть поднят)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
