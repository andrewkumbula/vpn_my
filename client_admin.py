#!/usr/bin/env python3
"""Выполняется НА СЕРВЕРЕ (через `ssh хост python3 - <команда> ... < client_admin.py`).
Заводит/убирает именного клиента в 3x-ui. Меняет БД — по умолчанию только
показывает, что сделает; реально пишет только с --apply (см. §8 стиля промта).

Правит ОБЕ схемы хранения клиентов 3x-ui разом (inbounds.settings JSON — источник
истины для xray-core, и client_traffics — для счётчиков/старого UI панели), иначе
они расходятся и панель начинает показывать несуществующее.

Имя ключа складывается из имени человека и протокола (petya-vless-reality-1) —
внутри сервера email обязан быть уникальным, иначе 3x-ui путает клиентов.
"""
import argparse
import base64
import json
import secrets
import shutil
import sqlite3
import subprocess
import sys
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
    """Перед правкой базы — копия рядом, с таймстампом в имени."""
    копия = f"{путь_бд}.bak.{int(time.time())}"
    shutil.copy2(путь_бд, копия)
    return копия


def перезапустить_x_ui(apply_):
    """x-ui генерирует конфиг xray из БД сам — при прямой правке БД в обход панели
    xray-core не увидит изменение, пока x-ui не перечитает и не перегенерирует.
    Простой и надёжный способ — рестарт сервиса; коротко разрывает текущие сессии,
    но это дешевле, чем гонять внутреннюю (не документированную наружу) reload-логику
    панели напрямую."""
    if not apply_:
        print("  [dry-run] перезапустил бы systemctl restart x-ui")
        return
    subprocess.run(["systemctl", "restart", "x-ui"], check=True)
    print("  x-ui перезапущен")


def добавить(соединение, курсор, имя, дни, протоколы, apply_):
    истёк = 0
    if дни:
        истёк = int((time.time() + дни * 86400) * 1000)

    изменений = 0
    # ВАЖНО fetchall(): ниже в цикле идут UPDATE/INSERT тем же курсором, а это
    # сбрасывает незавершённый перебор — без предварительной выборки клиент
    # заводился только в ПЕРВЫЙ подходящий inbound, остальные молча пропускались
    # (поймано вживую при добавлении второго vless).
    строки = курсор.execute(
        "SELECT id, remark, protocol, settings FROM inbounds"
    ).fetchall()
    for строка in строки:
        inbound_id, remark, протокол, settings_raw = строка
        if протоколы and протокол not in протоколы:
            continue
        if протокол not in ("vless", "shadowsocks"):
            # trojan/vmess/wireguard и т.п. — структура клиента другая, не
            # реализовано, осознанно пропускаем, а не пишем наугад.
            continue

        settings = json.loads(settings_raw or "{}")
        clients = settings.setdefault("clients", [])

        email = f"{имя}-{remark or inbound_id}"
        if any(c.get("email") == email for c in clients):
            print(f"  пропуск: {email} уже существует в inbound {inbound_id}")
            continue

        if протокол == "vless":
            новый_uuid = str(uuid_lib.uuid4())
            новый_клиент = {
                "id": новый_uuid,
                "flow": "xtls-rprx-vision",
                "email": email,
                "limitIp": 0,
                "totalGB": 0,
                "expiryTime": истёк,
                "enable": True,
                "tgId": "",
                "subId": uuid_lib.uuid4().hex[:16],
                "reset": 0,
            }
            чем_опознаётся = f"uuid={новый_uuid}"
        else:
            # Shadowsocks-2022 multi-user: у клиента свой PSK той же длины, что
            # и серверный (16 байт для 2022-blake3-aes-128-gcm). Клиент потом
            # подключается паролем "<серверный>:<клиентский>".
            длина_ключа = 32 if "aes-256" in (settings.get("method") or "") else 16
            клиентский_ключ = base64.b64encode(secrets.token_bytes(длина_ключа)).decode()
            новый_клиент = {
                "password": клиентский_ключ,
                "email": email,
                "limitIp": 0,
                "totalGB": 0,
                "expiryTime": истёк,
                "enable": True,
                "tgId": "",
                "subId": uuid_lib.uuid4().hex[:16],
                "reset": 0,
            }
            чем_опознаётся = "psk=<скрыт>"

        print(f"  {'[apply]' if apply_ else '[dry-run]'} inbound {inbound_id} ({remark}, "
              f"{протокол}): + {email}  {чем_опознаётся}  до={истёк or 'бессрочно'}")

        if apply_:
            clients.append(новый_клиент)
            курсор.execute(
                "UPDATE inbounds SET settings = ? WHERE id = ?",
                (json.dumps(settings), inbound_id),
            )
            курсор.execute(
                "INSERT INTO client_traffics (inbound_id, enable, email, up, down, "
                "expiry_time, total, reset) VALUES (?, 1, ?, 0, 0, ?, 0, 0)",
                (inbound_id, email, истёк),
            )
        изменений += 1

    if apply_ and изменений:
        соединение.commit()
    return изменений


def убрать(соединение, курсор, имя, apply_):
    изменений = 0
    # fetchall() по той же причине, что и в добавить(): DELETE/UPDATE внутри
    # цикла обрывают перебор на первой же изменённой строке.
    строки = курсор.execute("SELECT id, remark, settings FROM inbounds").fetchall()
    for строка in строки:
        inbound_id, remark, settings_raw = строка
        settings = json.loads(settings_raw or "{}")
        clients = settings.get("clients", [])
        оставшиеся = [c for c in clients if not c.get("email", "").startswith(f"{имя}-")]
        удалённые = [c for c in clients if c.get("email", "").startswith(f"{имя}-")]
        if not удалённые:
            continue

        for c in удалённые:
            print(f"  {'[apply]' if apply_ else '[dry-run]'} inbound {inbound_id} ({remark}): "
                  f"- {c.get('email')}")

        if apply_:
            settings["clients"] = оставшиеся
            курсор.execute(
                "UPDATE inbounds SET settings = ? WHERE id = ?",
                (json.dumps(settings), inbound_id),
            )
            курсор.execute(
                "DELETE FROM client_traffics WHERE inbound_id = ? AND email LIKE ?",
                (inbound_id, f"{имя}-%"),
            )
        изменений += len(удалённые)

    if apply_ and изменений:
        соединение.commit()
    return изменений


def main():
    парсер = argparse.ArgumentParser(description=__doc__)
    подкоманды = парсер.add_subparsers(dest="действие", required=True)

    p_add = подкоманды.add_parser("add")
    p_add.add_argument("имя")
    p_add.add_argument("--days", type=int, default=0, help="0 = бессрочно")
    p_add.add_argument("--protocols", default="", help="через запятую, например vless")
    p_add.add_argument("--apply", action="store_true")

    p_remove = подкоманды.add_parser("remove")
    p_remove.add_argument("имя")
    p_remove.add_argument("--apply", action="store_true")

    аргс = парсер.parse_args()

    путь_бд = найти_бд()
    if путь_бд is None:
        print("3x-ui не установлен на этом сервере (БД не найдена)", file=sys.stderr)
        return 1

    if аргс.apply:
        копия = резервная_копия(путь_бд)
        print(f"резервная копия БД: {копия}")

    соединение = sqlite3.connect(путь_бд)
    курсор = соединение.cursor()

    if аргс.действие == "add":
        протоколы = {p.strip() for p in аргс.protocols.split(",") if p.strip()}
        изменений = добавить(соединение, курсор, аргс.имя, аргс.days, протоколы, аргс.apply)
    else:
        изменений = убрать(соединение, курсор, аргс.имя, аргс.apply)

    соединение.close()

    if изменений and аргс.apply:
        перезапустить_x_ui(аргс.apply)
    elif not изменений:
        print("изменений нет")
    else:
        print(f"\nэто был dry-run ({изменений} изменени{'е' if изменений == 1 else 'й'}) — добавь --apply, чтобы применить")

    return 0


if __name__ == "__main__":
    sys.exit(main())
