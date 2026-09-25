#!/usr/bin/env python3
"""Выполняется НА СЕРВЕРЕ (пайпом: `ssh хост python3 - ... < rotate_keys.py`).
Меняет БД — по умолчанию dry-run, реально пишет только с --apply. Бэкап БД —
перед любой правкой.

Когда нужен: если база панели скопирована с другого сервера "как есть" (например,
клонировали образ) — UUID клиентов и пара ключей Reality совпадают между
серверами, и одна утёкшая ссылка открывает оба. Разводим.

  --client EMAIL         новый UUID для одного клиента (email как в панели)
  --reality-inbound ID   новая пара ключей Reality для inbound-а (id или remark);
                          затрагивает ВСЕХ клиентов на нём — старые ссылки с этим
                          inbound-ом перестанут работать, это ожидаемо
  --all                  и то, и другое, для всех клиентов/inbound-ов сразу
"""
import argparse
import base64
import json
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import uuid as uuid_lib

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


def новая_reality_пара():
    """X25519-пара через openssl (в стандартной библиотеке python нет x25519
    keygen). Проверено сверкой -text и DER-хвоста — 32 сырых байта, как и
    ожидается для этого алгоритма."""
    with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
        priv_path = f.name
    try:
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "X25519", "-out", priv_path],
            check=True, capture_output=True,
        )
        priv_der = subprocess.run(
            ["openssl", "pkey", "-in", priv_path, "-outform", "DER"],
            check=True, capture_output=True,
        ).stdout
        pub_der = subprocess.run(
            ["openssl", "pkey", "-in", priv_path, "-pubout", "-outform", "DER"],
            check=True, capture_output=True,
        ).stdout
    finally:
        import os
        os.unlink(priv_path)

    def b64(raw):
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    return b64(priv_der[-32:]), b64(pub_der[-32:])


def ротация_клиента(курсор, email, apply_):
    изменений = 0
    for inbound_id, remark, settings_raw in курсор.execute(
        "SELECT id, remark, settings FROM inbounds"
    ):
        settings = json.loads(settings_raw or "{}")
        for клиент in settings.get("clients", []):
            if клиент.get("email") != email:
                continue
            старый = клиент["id"]
            новый = str(uuid_lib.uuid4())
            print(f"  {'[apply]' if apply_ else '[dry-run]'} inbound {inbound_id} ({remark}): "
                  f"{email}: {старый} → {новый}")
            if apply_:
                клиент["id"] = новый
                курсор.execute(
                    "UPDATE inbounds SET settings = ? WHERE id = ?",
                    (json.dumps(settings), inbound_id),
                )
            изменений += 1
    return изменений


def ротация_reality(курсор, inbound_ref, apply_):
    изменений = 0
    for inbound_id, remark, stream_raw in курсор.execute(
        "SELECT id, remark, stream_settings FROM inbounds"
    ):
        if str(inbound_id) != str(inbound_ref) and remark != inbound_ref:
            continue
        stream = json.loads(stream_raw or "{}")
        if stream.get("security") != "reality":
            print(f"  пропуск: inbound {inbound_id} ({remark}) не Reality")
            continue

        приват, публич = новая_reality_пара()
        print(f"  {'[apply]' if apply_ else '[dry-run]'} inbound {inbound_id} ({remark}): "
              f"новая пара Reality, публичный ключ {публич}")
        if apply_:
            rs = stream["realitySettings"]
            rs["privateKey"] = приват
            rs.setdefault("settings", {})["publicKey"] = публич
            курсор.execute(
                "UPDATE inbounds SET stream_settings = ? WHERE id = ?",
                (json.dumps(stream), inbound_id),
            )
        изменений += 1
    return изменений


def перезапустить_x_ui(apply_):
    if not apply_:
        print("  [dry-run] перезапустил бы systemctl restart x-ui")
        return
    subprocess.run(["systemctl", "restart", "x-ui"], check=True)
    print("  x-ui перезапущен")


def main():
    парсер = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    парсер.add_argument("--client", help="email клиента — новый UUID")
    парсер.add_argument("--reality-inbound", help="id или remark inbound-а — новая пара Reality")
    парсер.add_argument("--all", action="store_true", help="ротация всего сразу")
    парсер.add_argument("--apply", action="store_true")
    аргс = парсер.parse_args()

    if not (аргс.client or аргс.reality_inbound or аргс.all):
        парсер.error("укажи --client, --reality-inbound или --all")

    путь_бд = найти_бд()
    if путь_бд is None:
        print("3x-ui не установлен на этом сервере (БД не найдена)", file=sys.stderr)
        return 1

    if аргс.apply:
        копия = резервная_копия(путь_бд)
        print(f"резервная копия БД: {копия}")

    соединение = sqlite3.connect(путь_бд)
    курсор = соединение.cursor()

    изменений = 0
    if аргс.all:
        for email, in курсор.execute(
            "SELECT DISTINCT json_extract(value, '$.email') FROM inbounds, "
            "json_each(json_extract(settings, '$.clients'))"
        ):
            if email:
                изменений += ротация_клиента(курсор, email, аргс.apply)
        for inbound_id, in курсор.execute(
            "SELECT id FROM inbounds WHERE stream_settings LIKE '%\"security\":\"reality\"%'"
        ):
            изменений += ротация_reality(курсор, str(inbound_id), аргс.apply)
    else:
        if аргс.client:
            изменений += ротация_клиента(курсор, аргс.client, аргс.apply)
        if аргс.reality_inbound:
            изменений += ротация_reality(курсор, аргс.reality_inbound, аргс.apply)

    if аргс.apply and изменений:
        соединение.commit()
    соединение.close()

    if изменений and аргс.apply:
        перезапустить_x_ui(аргс.apply)
    elif not изменений:
        print("изменений нет — ничего не найдено по указанным критериям")
    else:
        print(f"\nэто был dry-run ({изменений}) — добавь --apply, чтобы применить")

    return 0


if __name__ == "__main__":
    sys.exit(main())
