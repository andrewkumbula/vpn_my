#!/usr/bin/env python3
"""Выполняется НА СЕРВЕРЕ (пайпом: `ssh хост python3 - <inbound> <dest> [--apply] <
set_reality_dest.py`). Меняет сайт-маскировку (dest + serverNames) у Reality-inbound-а.
По умолчанию dry-run, бэкап БД перед --apply.

Сайт для маскировки подбирается НЕ угадыванием — проверь его сначала локальным
check_dest.py (TLS 1.3, без редиректов), а после смены здесь проверь живым
Reality-соединением через клиента: сервер сам о плохом выборе не расскажет.
"""
import argparse
import json
import shutil
import sqlite3
import subprocess
import sys
import time


XUI_DB_ПУТИ = [
    "/etc/x-ui/x-ui.db",
    "/usr/local/x-ui/x-ui.db",
    "/usr/local/x-ui/db/x-ui.db",
]


def найти_бд():
    import os
    for путь in XUI_DB_ПУТИ:
        if os.path.isfile(путь):
            return путь
    return None


def резервная_копия(путь_бд):
    копия = f"{путь_бд}.bak.{int(time.time())}"
    shutil.copy2(путь_бд, копия)
    return копия


def перезапустить_x_ui(apply_):
    if not apply_:
        print("  [dry-run] перезапустил бы systemctl restart x-ui")
        return
    subprocess.run(["systemctl", "restart", "x-ui"], check=True)
    print("  x-ui перезапущен")


def main():
    парсер = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    парсер.add_argument("inbound", help="id или remark inbound-а")
    парсер.add_argument("dest", help="host:port сайта-маскировки, например www.example.com:443")
    парсер.add_argument("--apply", action="store_true")
    аргс = парсер.parse_args()

    if ":" not in аргс.dest:
        парсер.error("dest должен быть в формате host:port")
    новый_sni = аргс.dest.rsplit(":", 1)[0]

    путь_бд = найти_бд()
    if путь_бд is None:
        print("3x-ui не установлен на этом сервере (БД не найдена)", file=sys.stderr)
        return 1

    соединение = sqlite3.connect(путь_бд)
    курсор = соединение.cursor()

    найден = False
    for inbound_id, remark, stream_raw in курсор.execute(
        "SELECT id, remark, stream_settings FROM inbounds"
    ):
        if str(inbound_id) != аргс.inbound and remark != аргс.inbound:
            continue
        найден = True
        stream = json.loads(stream_raw or "{}")
        if stream.get("security") != "reality":
            print(f"inbound {inbound_id} ({remark}) не Reality — нечего менять", file=sys.stderr)
            соединение.close()
            return 1

        старый = stream["realitySettings"].get("dest")
        print(f"{'[apply]' if аргс.apply else '[dry-run]'} inbound {inbound_id} ({remark}): "
              f"dest {старый!r} → {аргс.dest!r}, serverNames → [{новый_sni!r}]")

        if аргс.apply:
            копия = резервная_копия(путь_бд)
            print(f"резервная копия БД: {копия}")
            rs = stream["realitySettings"]
            rs["dest"] = аргс.dest
            rs["serverNames"] = [новый_sni]
            курсор.execute(
                "UPDATE inbounds SET stream_settings = ? WHERE id = ?",
                (json.dumps(stream), inbound_id),
            )
            соединение.commit()
        break

    соединение.close()

    if not найден:
        print(f"нет inbound-а с id/remark = {аргс.inbound!r}", file=sys.stderr)
        return 1

    if аргс.apply:
        перезапустить_x_ui(аргс.apply)
        print("\nтеперь проверь ЖИВЫМ подключением клиента — сервер сам не расскажет, если выбор неудачный")
    else:
        print("\n(dry-run — добавь --apply, чтобы применить)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
