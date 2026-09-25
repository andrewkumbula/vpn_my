#!/usr/bin/env python3
"""ТОЛЬКО ЧТЕНИЕ. Строит клиентские ссылки (vless://, hysteria2://, ...) из
state/registry.json — то есть из реального состояния серверов, а не из отдельного
файла с паролями/UUID: такой файл рано или поздно разойдётся с сервером, а
реестр, собранный `collect.py`, — нет.

Запусти сперва `python3 collect.py`, потом это.
"""
import argparse
import base64
import json
import sys
from pathlib import Path
from urllib.parse import quote

КОРЕНЬ = Path(__file__).resolve().parent
РЕЕСТР = КОРЕНЬ / "state" / "registry.json"


def адрес_сервера(метаданные):
    """Если есть домен с настоящим TLS — ссылка идёт на домен, иначе на голый IP
    (так живёт Reality без домена)."""
    return метаданные.get("домен") or метаданные["host"]


def ссылки_из_inbound(метаданные, inbound, фильтр_email=None):
    """Собираем по одной ссылке на каждого клиента, обе схемы хранения клиентов
    (settings и client_traffics) мёржим по email — где есть UUID, там и ссылка.
    фильтр_email — если задан, берём только клиентов, чей email начинается с
    этой строки (используется `./vpn конфиг <устройство>` — устройства заведены
    как <имя>-<протокол>, см. client_admin.py)."""
    итог = []
    host = адрес_сервера(метаданные)
    порт = inbound["порт"]
    remark_сервера = метаданные.get("имя", host)

    for клиент in inbound.get("клиенты_из_settings", []):
        email = клиент.get("email", "?")
        if фильтр_email and not email.startswith(фильтр_email):
            continue
        протокол = inbound.get("протокол")
        безопасность = inbound.get("безопасность")
        имя_ссылки = quote(f"{remark_сервера}-{email}")

        # UUID есть только у vless/vmess; у shadowsocks клиент опознаётся
        # своим PSK в поле password — поэтому проверку делаем внутри веток,
        # а не до них (иначе ss-клиенты молча отсеивались бы).
        uuid = клиент.get("id")
        if протокол in ("vless", "vmess") and not uuid:
            continue

        if протокол == "vless" and безопасность == "reality":
            r = inbound.get("reality") or {}
            параметры = {
                "encryption": "none",
                "security": "reality",
                "sni": (r.get("server_names") or [""])[0],
                "fp": r.get("fingerprint") or "chrome",
                "pbk": r.get("public_key") or "",
                "sid": (r.get("short_ids") or [""])[0],
                "spx": r.get("spider_x") or "",
                "type": inbound.get("сеть") or "tcp",
                "flow": клиент.get("flow") or "",
            }
            query = "&".join(f"{k}={quote(str(v))}" for k, v in параметры.items() if v != "")
            итог.append(f"vless://{uuid}@{host}:{порт}?{query}#{имя_ссылки}")

        elif протокол == "vless" and безопасность == "tls":
            домен = метаданные.get("домен")
            параметры = {
                "encryption": "none",
                "security": "tls",
                "sni": домен or host,
                "fp": "chrome",
                "type": inbound.get("сеть") or "tcp",
                "flow": клиент.get("flow") or "",
            }
            if метаданные.get("tls_insecure", False):
                # НЕ по наличию домена — на senko-1 домена нет, но сертификат
                # настоящий (Let's Encrypt на голый IP), allowInsecure не нужен
                # и без надобности его выключать не стоит. Источник — то же
                # servers.json → tls_insecure, что использует render_client.py.
                параметры["allowInsecure"] = "1"
            query = "&".join(f"{k}={quote(str(v))}" for k, v in параметры.items() if v != "")
            итог.append(f"vless://{uuid}@{host}:{порт}?{query}#{имя_ссылки}")

        else:
            # trojan / vmess / wireguard и прочее — на серверах не заведены,
            # формат ссылки для них не проверен вживую. Отмечаем, не выдумываем.
            итог.append(
                f"# ссылка для протокола {протокол}/{безопасность} "
                f"(inbound {inbound.get('id')}, клиент {email}) не реализована — "
                f"нет живого сервера с этим протоколом для проверки"
            )
    return итог


def ссылка_shadowsocks(метаданные, inbound):
    """У shadowsocks-inbound-а на этом парке ОДИН общий серверный ключ (multi-user
    панель в xray не пробрасывает — проверено на сервере), поэтому ссылка одна на
    весь inbound, а не по клиенту. Это резервный канал владельца: раздавать его
    людям нельзя — отозвать индивидуально не получится, только сменив ключ всем."""
    ss = inbound.get("shadowsocks") or {}
    серверный = ss.get("серверный_ключ")
    if not серверный:
        return None
    host = адрес_сервера(метаданные)
    имя_ссылки = quote(f"{метаданные.get('имя', host)}-{inbound.get('remark') or inbound['id']}")
    # SIP002: base64url("<метод>:<пароль>") в userinfo-части.
    userinfo = base64.urlsafe_b64encode(
        f"{ss.get('метод')}:{серверный}".encode()
    ).decode().rstrip("=")
    return f"ss://{userinfo}@{host}:{inbound['порт']}#{имя_ссылки}"


def собрать_ссылки(реестр, только_сервер=None, только_протокол=None, фильтр_email=None):
    итог = {}
    for имя, данные in реестр["серверы"].items():
        if только_сервер and имя != только_сервер:
            continue
        if not данные.get("жив"):
            continue
        метаданные = данные["метаданные"]
        for inbound in данные.get("панель_3xui", {}).get("inbounds", []):
            if только_протокол and inbound.get("протокол") != только_протокол:
                continue
            if inbound.get("протокол") == "shadowsocks":
                # Общий ключ — фильтр по клиенту к нему неприменим, поэтому при
                # запросе конкретного устройства такой inbound пропускаем.
                if фильтр_email:
                    continue
                ссылка = ссылка_shadowsocks(метаданные, inbound)
                if ссылка:
                    итог.setdefault(имя, []).append(ссылка)
                continue
            for ссылка in ссылки_из_inbound(метаданные, inbound, фильтр_email):
                итог.setdefault(имя, []).append(ссылка)
    return итог


def main():
    парсер = argparse.ArgumentParser(description="Клиентские ссылки из реестра")
    парсер.add_argument("--server", dest="сервер", help="только этот сервер (имя)")
    парсер.add_argument("--protocol", dest="протокол", help="только этот протокол")
    парсер.add_argument("--email-prefix", dest="email_prefix", help="только клиенты с email, начинающимся на это")
    аргс = парсер.parse_args()

    if not РЕЕСТР.exists():
        print("нет state/registry.json — сначала запусти collect.py", file=sys.stderr)
        return 1

    реестр = json.loads(РЕЕСТР.read_text(encoding="utf-8"))
    ссылки = собрать_ссылки(реестр, аргс.сервер, аргс.протокол, аргс.email_prefix)

    if not ссылки:
        print("ссылок нет — либо сервер недоступен, либо на нём ещё нет клиентов", file=sys.stderr)
        return 0

    for сервер, список in ссылки.items():
        print(f"\n== {сервер} ==")
        for ссылка in список:
            print(ссылка)
    return 0


if __name__ == "__main__":
    sys.exit(main())
