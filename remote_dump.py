#!/usr/bin/env python3
"""ТОЛЬКО ЧТЕНИЕ. Выполняется на сервере (через `ssh хост python3 - < remote_dump.py`),
ничего не меняет. Печатает в stdout один JSON-объект — состояние 3x-ui и/или sing-box
на этой машине. collect.py на маке собирает такие дампы со всех серверов в registry.json.

Не тянет ничего снаружи стандартной библиотеки — запускается на голом сервере без pip.
"""
import json
import os
import socket
import sqlite3
import subprocess
import sys

XUI_DB_ПУТИ = [
    "/etc/x-ui/x-ui.db",
    "/usr/local/x-ui/x-ui.db",
    "/usr/local/x-ui/db/x-ui.db",
]
SINGBOX_CONFIG_ПУТИ = [
    "/etc/sing-box/config.json",
    "/usr/local/etc/sing-box/config.json",
]


def сервис_активен(имя: str) -> bool:
    """systemctl нет смысла парсить целиком — is-active сам возвращает то, что нужно."""
    try:
        r = subprocess.run(
            ["systemctl", "is-active", имя], capture_output=True, text=True, timeout=5
        )
        return r.stdout.strip() == "active"
    except Exception:
        return False


def найти_файл(кандидаты):
    for путь in кандидаты:
        if os.path.isfile(путь):
            return путь
    return None


def дамп_xui():
    """3x-ui хранит клиентов в ДВУХ местах одновременно:
    - inbounds.settings — JSON-блок, который реально читает xray-core (источник истины
      для работы туннеля);
    - client_traffics — отдельная таблица для счётчиков трафика и старого UI панели.
    Правишь одно без другого — они расходятся, панель начинает врать. Дампим оба и не
    пытаемся здесь их «сливать» в одно — пусть collect.py решает, что показывать.
    """
    путь_бд = найти_файл(XUI_DB_ПУТИ)
    итог = {
        "установлена": путь_бд is not None,
        "путь_бд": путь_бд,
        "сервис_активен": сервис_активен("x-ui"),
        "inbounds": [],
    }
    if путь_бд is None:
        return итог

    try:
        соединение = sqlite3.connect(f"file:{путь_бд}?mode=ro", uri=True, timeout=5)
        соединение.row_factory = sqlite3.Row
        курсор = соединение.cursor()

        traffics_по_email = {}
        try:
            for строка in курсор.execute(
                "SELECT inbound_id, enable, email, up, down, expiry_time, total, reset "
                "FROM client_traffics"
            ):
                traffics_по_email.setdefault(строка["inbound_id"], []).append(dict(строка))
        except sqlite3.OperationalError:
            # Старая схема без client_traffics — тоже валидный сервер, просто пусто.
            pass

        for строка in курсор.execute(
            "SELECT id, remark, port, protocol, enable, expiry_time, settings, "
            "stream_settings, up, down, total FROM inbounds"
        ):
            inbound = dict(строка)
            try:
                settings = json.loads(inbound.get("settings") or "{}")
            except json.JSONDecodeError:
                settings = {}
            try:
                stream = json.loads(inbound.get("stream_settings") or "{}")
            except json.JSONDecodeError:
                stream = {}

            reality = None
            if stream.get("security") == "reality":
                rs = stream.get("realitySettings", {})
                reality = {
                    "dest": rs.get("dest"),
                    "server_names": rs.get("serverNames", []),
                    "public_key": rs.get("settings", {}).get("publicKey"),
                    "short_ids": rs.get("shortIds", []),
                    "fingerprint": rs.get("settings", {}).get("fingerprint"),
                    "spider_x": rs.get("settings", {}).get("spiderX"),
                }

            # Shadowsocks-2022 хранит СЕРВЕРНЫЙ ключ прямо в settings (не у
            # клиента) — клиент подключается парой "серверный:клиентский",
            # поэтому без этого поля ссылку не собрать.
            shadowsocks = None
            if inbound["protocol"] == "shadowsocks":
                shadowsocks = {
                    "метод": settings.get("method"),
                    "серверный_ключ": settings.get("password"),
                    "сеть": settings.get("network", "tcp,udp"),
                }

            итог["inbounds"].append(
                {
                    "id": inbound["id"],
                    "remark": inbound["remark"],
                    "порт": inbound["port"],
                    "протокол": inbound["protocol"],
                    "включён": bool(inbound["enable"]),
                    "сеть": stream.get("network"),
                    "безопасность": stream.get("security"),
                    "reality": reality,
                    "shadowsocks": shadowsocks,
                    "клиенты_из_settings": settings.get("clients", []),
                    "клиенты_из_traffics": traffics_по_email.get(inbound["id"], []),
                }
            )
        соединение.close()
    except sqlite3.Error as ошибка:
        итог["ошибка_бд"] = str(ошибка)

    return итог


def дамп_singbox():
    путь = найти_файл(SINGBOX_CONFIG_ПУТИ)
    итог = {
        "установлен": путь is not None,
        "путь_конфига": путь,
        "сервис_активен": сервис_активен("sing-box"),
        "конфиг": None,
    }
    if путь:
        try:
            with open(путь, encoding="utf-8") as f:
                итог["конфиг"] = json.load(f)
        except (OSError, json.JSONDecodeError) as ошибка:
            итог["ошибка_конфига"] = str(ошибка)
    return итог


def main():
    print(
        json.dumps(
            {
                "хост": socket.gethostname(),
                "панель_3xui": дамп_xui(),
                "sing_box": дамп_singbox(),
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    sys.exit(main())
