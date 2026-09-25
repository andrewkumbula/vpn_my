#!/usr/bin/env python3
"""Выполняется НА СЕРВЕРЕ (пайпом: `ssh хост python3 - <inbound> [--apply] <
drop_inbound.py`). Убирает неиспользуемый inbound целиком — не отключает
(enable=false), а физически удаляет строку из inbounds + связанные client_traffics.
По умолчанию dry-run, бэкап БД перед --apply.
"""
import argparse
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
    парсер = argparse.ArgumentParser(description=__doc__)
    парсер.add_argument("inbound", help="id или remark inbound-а")
    парсер.add_argument("--apply", action="store_true")
    аргс = парсер.parse_args()

    путь_бд = найти_бд()
    if путь_бд is None:
        print("3x-ui не установлен на этом сервере (БД не найдена)", file=sys.stderr)
        return 1

    соединение = sqlite3.connect(путь_бд)
    курсор = соединение.cursor()

    строка = курсор.execute(
        "SELECT id, remark, port, protocol FROM inbounds WHERE id = ? OR remark = ?",
        (аргс.inbound, аргс.inbound),
    ).fetchone()

    if строка is None:
        print(f"нет inbound-а с id/remark = {аргс.inbound!r}", file=sys.stderr)
        соединение.close()
        return 1

    inbound_id, remark, порт, протокол = строка
    клиентов = курсор.execute(
        "SELECT COUNT(*) FROM client_traffics WHERE inbound_id = ?", (inbound_id,)
    ).fetchone()[0]

    print(f"{'[apply]' if аргс.apply else '[dry-run]'} удалить inbound {inbound_id} "
          f"({remark}, {протокол}:{порт}), клиентов в нём: {клиентов}")

    if аргс.apply:
        копия = резервная_копия(путь_бд)
        print(f"резервная копия БД: {копия}")
        курсор.execute("DELETE FROM client_traffics WHERE inbound_id = ?", (inbound_id,))
        курсор.execute("DELETE FROM inbounds WHERE id = ?", (inbound_id,))
        соединение.commit()

    соединение.close()

    if аргс.apply:
        перезапустить_x_ui(аргс.apply)
    else:
        print("\n(dry-run — добавь --apply, чтобы применить)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
