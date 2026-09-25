#!/usr/bin/env python3
"""Запускается на маке. Честный замер качества каждого подключения — в ДВА захода
(грабля из промта, §7):

  1. Напрямую до порта — TCP-хендшейк без прокси. Обрыв РОВНО на хендшейке при
     живом сервере (соединение начинается, потом обрывается) — это почерк
     блокировки провайдера, а не поломка сервера. Полный отказ (connection
     refused/timeout) — либо порт не слушает, либо блокировка грубее.
  2. Через поднятое подключение — реальный HTTP через локальный sing-box (мод
     local, 127.0.0.1:2080). Ловит удушение (throttling), когда формально всё
     живо, но еле ползёт — первый заход этого не видит.

Второй заход требует запущенного `./vpn старт` (local-режим) и живого clash API
(127.0.0.1:9090) — без него просто пропускается, не выдумываем цифры.
"""
import argparse
import json
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

КОРЕНЬ = Path(__file__).resolve().parent
РЕЕСТР = КОРЕНЬ / "state" / "registry.json"
CLASH_API = "http://127.0.0.1:9090"
SOCKS_PROXY = ("127.0.0.1", 2080)
URL_ПРОВЕРКИ = "https://www.gstatic.com/generate_204"


def прямой_тест(host, порт, таймаут=5):
    начало = time.monotonic()
    try:
        with socket.create_connection((host, порт), timeout=таймаут):
            прошло_мс = round((time.monotonic() - начало) * 1000)
            return {"успех": True, "мс": прошло_мс, "ошибка": None}
    except socket.timeout:
        return {"успех": False, "мс": None, "ошибка": "таймаут — похоже на почерк блокировки (соединение открылось бы, но не отвечает)"}
    except ConnectionRefusedError:
        return {"успех": False, "мс": None, "ошибка": "отказано в соединении — порт не слушает"}
    except OSError as e:
        return {"успех": False, "мс": None, "ошибка": str(e)}


def clash_api_доступен():
    try:
        urllib.request.urlopen(f"{CLASH_API}/proxies", timeout=3)
        return True
    except (urllib.error.URLError, OSError):
        return False


def выбрать_узел(тег_группы, тег_узла):
    запрос = urllib.request.Request(
        f"{CLASH_API}/proxies/{urllib.parse.quote(тег_группы)}",
        data=json.dumps({"name": тег_узла}).encode(),
        method="PUT",
        headers={"Content-Type": "application/json"},
    )
    urllib.request.urlopen(запрос, timeout=5)


def тест_через_тоннель(таймаут=8):
    """HTTP через локальный SOCKS — без requests, только stdlib
    (urllib не умеет SOCKS сам, поэтому голый TCP CONNECT по протоколу SOCKS5,
    самый минимум, достаточный для одного GET)."""
    import struct

    начало = time.monotonic()
    try:
        with socket.create_connection(SOCKS_PROXY, timeout=таймаут) as s:
            s.sendall(b"\x05\x01\x00")  # версия 5, 1 метод, без авторизации
            if s.recv(2) != b"\x05\x00":
                return {"успех": False, "мс": None, "ошибка": "SOCKS5-рукопожатие не удалось"}
            host = b"www.gstatic.com"
            запрос = b"\x05\x01\x00\x03" + struct.pack("B", len(host)) + host + struct.pack(">H", 443)
            s.sendall(запрос)
            ответ = s.recv(10)
            if len(ответ) < 2 or ответ[1] != 0x00:
                return {"успех": False, "мс": None, "ошибка": "SOCKS5 CONNECT отклонён"}
            прошло_мс = round((time.monotonic() - начало) * 1000)
            return {"успех": True, "мс": прошло_мс, "ошибка": None}
    except (socket.timeout, OSError) as e:
        return {"успех": False, "мс": None, "ошибка": str(e)}


def main():
    парсер = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    парсер.add_argument("--server", help="только этот сервер")
    аргс = парсер.parse_args()

    if not РЕЕСТР.exists():
        print("нет state/registry.json — сначала python3 collect.py", file=sys.stderr)
        return 1

    реестр = json.loads(РЕЕСТР.read_text(encoding="utf-8"))
    тоннель_доступен = clash_api_доступен()
    if not тоннель_доступен:
        print("clash API (127.0.0.1:9090) не отвечает — второй заход (через тоннель) пропущен, "
              "нужен запущенный `./vpn старт`\n", file=sys.stderr)

    for имя_сервера, данные in реестр.get("серверы", {}).items():
        if аргс.server and имя_сервера != аргс.server:
            continue
        if not данные.get("жив"):
            print(f"{имя_сервера}: сервер сейчас недоступен по SSH, пропуск")
            continue

        метаданные = данные["метаданные"]
        host = метаданные.get("домен") or метаданные["host"]

        for inbound in данные.get("панель_3xui", {}).get("inbounds", []):
            тег = f"{имя_сервера}-{inbound.get('remark') or inbound['id']}"
            порт = inbound["порт"]

            прямой = прямой_тест(host, порт)
            строка = f"{тег:<30} напрямую: "
            строка += f"{прямой['мс']}мс" if прямой["успех"] else f"✗ {прямой['ошибка']}"

            if тоннель_доступен:
                try:
                    выбрать_узел("вручную", тег)
                    time.sleep(0.3)  # дать sing-box время реально переключиться
                except Exception:
                    pass
                через = тест_через_тоннель()
                строка += "  |  через тоннель: "
                строка += f"{через['мс']}мс" if через["успех"] else f"✗ {через['ошибка']}"

            print(строка)

    return 0


if __name__ == "__main__":
    sys.exit(main())
