#!/usr/bin/env python3
"""Выполняется НА СЕРВЕРЕ (пайпом: `ssh хост python3 - <inbound> [--apply] <
fix_reality_minver.py`). Чинит конкретную несовместимость 3x-ui ↔ Xray-core:

Панель 3x-ui хранит в realitySettings ключи "minClient"/"maxClient" (без "Ver"),
а Xray-core (проверено по исходникам, infra/conf/transport_security.go) читает
ТОЛЬКО "minClientVer"/"maxClientVer". Из-за опечатки в имени поля значение
никогда не доходит до xray-core, и с недавнего апдейта xray-core в этом случае
сам подставляет дефолт [26, 3, 27] ("REALITY: The default minimal client version
is Xray-core v26.3.27, other clients may be refused to connect" — видно в
`journalctl -u x-ui`). Любой клиент, не умеющий сообщить о себе такую же
xray-core-версию (весь не-xray-core мир: sing-box, и другие независимые
реализации), сервер тихо отбивает камуфляжем на dest — TLS-хендшейк проходит,
дальше зависает, никакого сообщения об ошибке клиенту не приходит.

Правка: прописывает "minClientVer": "0.0.0" (принимать вообще любую версию —
это то поведение, которое панель, видимо, и пыталась настроить, просто с опечаткой
в имени поля). По умолчанию dry-run, бэкап БД перед --apply.
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
    парсер.add_argument("inbound", nargs="?", default=None,
                         help="id или remark inbound-а; без аргумента — все Reality-inbound-ы")
    парсер.add_argument("--min-version", default="0.0.0",
                         help="значение minClientVer (по умолчанию 0.0.0 — принимать любую версию)")
    парсер.add_argument("--apply", action="store_true")
    аргс = парсер.parse_args()

    путь_бд = найти_бд()
    if путь_бд is None:
        print("3x-ui не установлен на этом сервере (БД не найдена)", file=sys.stderr)
        return 1

    соединение = sqlite3.connect(путь_бд)
    курсор = соединение.cursor()

    изменений = 0
    for inbound_id, remark, stream_raw in курсор.execute(
        "SELECT id, remark, stream_settings FROM inbounds"
    ):
        if аргс.inbound and str(inbound_id) != аргс.inbound and remark != аргс.inbound:
            continue
        stream = json.loads(stream_raw or "{}")
        if stream.get("security") != "reality":
            continue

        rs = stream["realitySettings"]
        текущий = rs.get("minClientVer")
        if текущий == аргс.min_version:
            print(f"  inbound {inbound_id} ({remark}): minClientVer уже {аргс.min_version!r}, пропуск")
            continue

        print(f"{'[apply]' if аргс.apply else '[dry-run]'} inbound {inbound_id} ({remark}): "
              f"minClientVer {текущий!r} → {аргс.min_version!r} "
              f"(старые опечатанные ключи minClient/maxClient оставляю как есть — xray-core их просто игнорирует)")

        if аргс.apply:
            rs["minClientVer"] = аргс.min_version
            курсор.execute(
                "UPDATE inbounds SET stream_settings = ? WHERE id = ?",
                (json.dumps(stream), inbound_id),
            )
        изменений += 1

    if изменений and аргс.apply:
        копия = резервная_копия(путь_бд)
        print(f"резервная копия БД: {копия}")
        соединение.commit()
    соединение.close()

    if not изменений:
        print("нечего чинить — либо нет Reality-inbound-ов, либо minClientVer уже верный")
        return 0

    if аргс.apply:
        перезапустить_x_ui(аргс.apply)
        print("\nготово — проверь ЖИВЫМ подключением клиента (sing-box/др.), не только TLS-хендшейком")
    else:
        print("\n(dry-run — добавь --apply, чтобы применить)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
