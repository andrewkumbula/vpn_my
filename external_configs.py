#!/usr/bin/env python3
"""Внешние конфиги — vless-ссылки не с наших серверов (получены откуда-то ещё),
которые пользователь добавляет сам через морду, чтобы иметь их как ещё один
вариант в группе "авто"/"вручную". Хранятся отдельно от servers.json: там —
серверы, которыми мы управляем по SSH (собираем состояние, заводим людей), тут —
просто ссылка, за которой мы ничего не знаем и ничем не управляем.

Только чтение/запись json-файла + разбор ссылки. Разбор — ОБРАТНАЯ операция
к links.py (там строим ссылку из состояния сервера, здесь — outbound sing-box
из чужой ссылки).
"""
import json
import re
from pathlib import Path
from urllib.parse import parse_qs, unquote

КОРЕНЬ = Path(__file__).resolve().parent
ФАЙЛ = КОРЕНЬ / "state" / "external_configs.json"


def читать():
    if not ФАЙЛ.exists():
        return []
    return json.loads(ФАЙЛ.read_text(encoding="utf-8"))


def записать(список):
    ФАЙЛ.parent.mkdir(exist_ok=True)
    ФАЙЛ.write_text(json.dumps(список, ensure_ascii=False, indent=2), encoding="utf-8")


def тег_для(имя, индекс):
    """Тег outbound-а в sing-box — латиница/цифры/дефис, никаких спецсимволов,
    иначе конфиг не пройдёт валидацию имени тега."""
    slug = re.sub(r"[^a-zA-Zа-яА-ЯёЁ0-9]+", "-", имя).strip("-").lower()
    return f"внешний-{slug or индекс}"


def разобрать_vless(ссылка):
    """vless://<uuid>@host:port?параметры#имя → outbound для sing-box.
    Бросает ValueError с понятным текстом, если ссылка не разбирается или
    использует то, что мы не умеем (ws/grpc-транспорт и т.п.) — лучше явная
    ошибка при добавлении, чем молча нерабочий узел в списке."""
    ссылка = ссылка.strip()
    if not ссылка.startswith("vless://"):
        raise ValueError("пока умею разбирать только vless:// ссылки")
    тело = ссылка[len("vless://"):]
    if "#" in тело:
        тело = тело.split("#", 1)[0]
    if "@" not in тело:
        raise ValueError("нет '@' в ссылке — не похоже на vless")
    uuid_часть, остаток = тело.split("@", 1)
    host_port, _, query = остаток.partition("?")
    if ":" not in host_port:
        raise ValueError("нет порта после '@' (ожидался вид host:port)")
    host, port_s = host_port.rsplit(":", 1)
    try:
        port = int(port_s)
    except ValueError:
        raise ValueError(f"порт не число: {port_s!r}")

    параметры = parse_qs(query)

    def значение(ключ, по_умолчанию=""):
        return unquote(параметры.get(ключ, [по_умолчанию])[0])

    security = значение("security", "none")
    network = значение("type", "tcp") or "tcp"
    if network != "tcp":
        raise ValueError(f"type={network!r} не поддержан — умею только tcp (без ws/grpc/h2)")

    host = unquote(host)
    outbound = {
        "type": "vless",
        "server": host,
        "server_port": port,
        "uuid": unquote(uuid_часть),
        "flow": значение("flow"),
        "packet_encoding": "xudp",
    }

    if security == "reality":
        pbk = значение("pbk")
        if not pbk:
            raise ValueError("security=reality, но в ссылке нет 'pbk' (публичного ключа)")
        outbound["tls"] = {
            "enabled": True,
            "server_name": значение("sni") or host,
            "utls": {"enabled": True, "fingerprint": значение("fp", "chrome") or "chrome"},
            "reality": {"enabled": True, "public_key": pbk, "short_id": значение("sid")},
        }
    elif security == "tls":
        outbound["tls"] = {
            "enabled": True,
            "server_name": значение("sni") or host,
            "insecure": значение("allowInsecure") == "1",
            "utls": {"enabled": True, "fingerprint": значение("fp", "chrome") or "chrome"},
        }
    elif security == "none":
        pass
    else:
        raise ValueError(f"security={security!r} не поддержан (умею tls/reality/none)")

    return outbound


def outbounds_и_теги():
    """Возвращает (outbounds, теги) по всем сохранённым внешним конфигам —
    невалидные пропускаются (уже отфильтрованы при добавлении, но конфиг мог
    протухнуть, например истёк сертификат)."""
    outbounds, теги = [], []
    for индекс, запись in enumerate(читать()):
        try:
            ob = разобрать_vless(запись["ссылка"])
        except ValueError:
            continue
        тег = тег_для(запись.get("название", ""), индекс)
        ob["tag"] = тег
        outbounds.append(ob)
        теги.append(тег)
    return outbounds, теги
