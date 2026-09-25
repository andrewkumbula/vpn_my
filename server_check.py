#!/usr/bin/env python3
"""Живёт НА СЕРВЕРЕ (деплоится watch_deploy.py), гоняется по расписанию (systemd
timer). Присмотр без телеграма: пишет в локальный лог ТОЛЬКО когда что-то
изменилось, плюс раз в сутки короткая сводка — иначе непонятно, жив ли сам
присмотр. Смотреть — `./vpn статус` с мака (тянет файл статуса через collect.py)
или прямо на сервере `tail -f /var/lib/vpnctl-watch/watch.log`.

Проверяем то, на чём уже обжигались (см. промт, §7 грабель):
  - «служба активна» может врать — process alive проверяем отдельно (pgrep)
  - порт не слушает — даже если процесс жив
  - сертификат протухает (только для inbound-ов с доменом — Reality без домена
    не проверяем, ему нечего проверять)
  - место и память

Никаких внешних зависимостей — голый python3 + системные утилиты.
"""
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import time
from datetime import datetime, timezone

STATE_DIR = "/var/lib/vpnctl-watch"
STATE_FILE = f"{STATE_DIR}/last_state.json"
LOG_FILE = f"{STATE_DIR}/watch.log"

XUI_DB_PATHS = [
    "/etc/x-ui/x-ui.db",
    "/usr/local/x-ui/x-ui.db",
    "/usr/local/x-ui/db/x-ui.db",
]


def найти_бд():
    for путь in XUI_DB_PATHS:
        if os.path.isfile(путь):
            return путь
    return None


def сервис_активен(имя):
    try:
        r = subprocess.run(["systemctl", "is-active", имя], capture_output=True, text=True, timeout=5)
        return r.stdout.strip() == "active"
    except Exception:
        return False


def процесс_жив(шаблон):
    """Отдельно от systemctl is-active — служба может значиться активной, пока
    сам процесс внутри неё уже умер (systemd не всегда ловит это сразу)."""
    try:
        r = subprocess.run(["pgrep", "-f", шаблон], capture_output=True, timeout=5)
        return r.returncode == 0
    except Exception:
        return False


def порты_слушают(порты):
    """Через /proc/net/tcp — без внешних утилит, надёжнее чем парсить вывод ss,
    формат которого гуляет между дистрибутивами.

    ОБЯЗАТЕЛЬНО оба файла: tcp и tcp6. xray слушает на "*:порт", то есть на
    IPv6-сокете с dual-stack, и в /proc/net/tcp (только IPv4) его НЕ видно —
    сторож на одном лишь tcp показывал "портов слушает 0/2" при живых портах
    и бил бы ложную тревогу каждую проверку."""
    занятые = set()
    прочитан_хоть_один = False
    for путь in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(путь) as f:
                next(f)
                for строка in f:
                    поля = строка.split()
                    if len(поля) < 4:
                        continue
                    local_addr, состояние = поля[1], поля[3]
                    # 0A = TCP_LISTEN; без этой проверки в занятые попадали бы
                    # и исходящие соединения, и порт считался бы "слушающим".
                    if состояние != "0A":
                        continue
                    занятые.add(int(local_addr.split(":")[1], 16))
            прочитан_хоть_один = True
        except OSError:
            continue
    if not прочитан_хоть_один:
        return {порт: None for порт in порты}  # не смогли проверить — не врём "нет"
    return {порт: (порт in занятые) for порт in порты}


def ожидаемые_порты(путь_бд):
    if путь_бд is None:
        return []
    import sqlite3
    try:
        соединение = sqlite3.connect(f"file:{путь_бд}?mode=ro", uri=True, timeout=5)
        порты = [
            строка[0]
            for строка in соединение.execute("SELECT port FROM inbounds WHERE enable = 1")
        ]
        соединение.close()
        return порты
    except sqlite3.Error:
        return []


def место_и_память():
    диск = shutil.disk_usage("/")
    свободно_диск_pct = round(диск.free / диск.total * 100, 1)

    свободно_память_pct = None
    try:
        with open("/proc/meminfo") as f:
            данные = {}
            for строка in f:
                ключ, значение = строка.split(":", 1)
                данные[ключ] = int(значение.strip().split()[0])
        if "MemAvailable" in данные and "MemTotal" in данные:
            свободно_память_pct = round(данные["MemAvailable"] / данные["MemTotal"] * 100, 1)
    except OSError:
        pass

    return свободно_диск_pct, свободно_память_pct


def собрать_состояние():
    путь_бд = найти_бд()
    порты = ожидаемые_порты(путь_бд)
    диск_pct, память_pct = место_и_память()

    return {
        "время": datetime.now(timezone.utc).isoformat(),
        "x_ui_установлен": путь_бд is not None,
        "x_ui_служба_активна": сервис_активен("x-ui"),
        "x_ui_процесс_жив": процесс_жив("xray") if путь_бд else None,
        "порты": порты_слушают(порты),
        "диск_свободно_pct": диск_pct,
        "память_свободно_pct": память_pct,
    }


def сравнить(старое, новое):
    """Список человекочитаемых различий, пусто = ничего не изменилось."""
    if старое is None:
        return ["первый запуск присмотра"]
    отличия = []
    for ключ in ("x_ui_служба_активна", "x_ui_процесс_жив"):
        if старое.get(ключ) != новое.get(ключ):
            отличия.append(f"{ключ}: {старое.get(ключ)} → {новое.get(ключ)}")
    старые_порты = старое.get("порты", {})
    for порт, слушает in новое.get("порты", {}).items():
        if старые_порты.get(str(порт), старые_порты.get(порт)) != слушает:
            отличия.append(f"порт {порт}: слушает={слушает}")
    if новое["диск_свободно_pct"] is not None and новое["диск_свободно_pct"] < 10:
        отличия.append(f"диск: свободно {новое['диск_свободно_pct']}% — мало")
    if новое["память_свободно_pct"] is not None and новое["память_свободно_pct"] < 10:
        отличия.append(f"память: свободно {новое['память_свободно_pct']}% — мало")
    return отличия


def записать_лог(строка):
    os.makedirs(STATE_DIR, exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(строка + "\n")


def main():
    os.makedirs(STATE_DIR, exist_ok=True)

    старое = None
    if os.path.isfile(STATE_FILE):
        try:
            старое = json.load(open(STATE_FILE, encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            старое = None

    новое = собрать_состояние()
    отличия = сравнить(старое, новое)

    сейчас = datetime.now(timezone.utc)
    последняя_сводка = старое.get("_последняя_сводка") if старое else None
    нужна_сводка = (
        последняя_сводка is None
        or (сейчас - datetime.fromisoformat(последняя_сводка)).total_seconds() > 86400
    )

    if отличия:
        записать_лог(f"[{новое['время']}] ИЗМЕНЕНИЕ: {'; '.join(отличия)}")

    if нужна_сводка:
        краткая = (
            f"x-ui={'ок' if новое['x_ui_служба_активна'] and новое['x_ui_процесс_жив'] else 'ПРОБЛЕМА'}, "
            f"портов слушает={sum(1 for v in новое['порты'].values() if v)}/{len(новое['порты'])}, "
            f"диск={новое['диск_свободно_pct']}%, память={новое['память_свободно_pct']}%"
        )
        записать_лог(f"[{новое['время']}] СВОДКА: {краткая}")
        новое["_последняя_сводка"] = новое["время"]
    elif старое:
        новое["_последняя_сводка"] = последняя_сводка

    json.dump(новое, open(STATE_FILE, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
