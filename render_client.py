#!/usr/bin/env python3
"""Собирает клиентский конфиг sing-box из state/registry.json (реальное состояние
серверов, не файл с паролями) + servers.json (метаданные: домен, морда, корп-домены).

Два режима:
  --mode local — SOCKS/HTTP на 127.0.0.1:2080, системный трафик не трогает. Не требует
                 root, можно гонять из-под обычного пользователя.
  --mode tun   — отдельный utun, перехватывает весь трафик машины. Требует root —
                 запускается только через privileged/vpn-run, не напрямую.

Списки правил (rulesets/*.srs) подключаются по АБСОЛЮТНОМУ пути этого репозитория.
При публикации в root-владение (publish.sh) пути внутри уже сгенерированного конфига
переписываются на путь в /usr/local/libexec/vpnctl — см. publish.sh.
"""
import argparse
import json
import sys
from pathlib import Path

import external_configs

КОРЕНЬ = Path(__file__).resolve().parent
РЕЕСТР = КОРЕНЬ / "state" / "registry.json"
СЕРВЕРЫ = КОРЕНЬ / "servers.json"
RULESETS = КОРЕНЬ / "rulesets"
UI_PANEL = КОРЕНЬ / "ui-panel"

# Мессенджеры и сервисы, которые всегда идут через туннель (группа "выбор"),
# даже если попадают в российскую зону по IP — geosite точнее, чем geoip, для CDN.
GEOSITE_ЧЕРЕЗ_ТУННЕЛЬ = [
    "geosite-telegram",
    "geosite-google",
    "geosite-youtube",
    "geosite-twitter",
    "geosite-instagram",
    "geosite-whatsapp",
    "geosite-speedtest",
]
# geosite для anthropic/claude в публичных списках не существует отдельной
# категорией — держим руками.
ДОМЕНЫ_ЧЕРЕЗ_ТУННЕЛЬ = ["anthropic.com", "claude.ai", "claude.com"]

РОССИЙСКИЕ_ЗОНЫ = [".ru", ".su", ".pro", ".top", ".me", ".рф"]


def читать_json(путь):
    with open(путь, encoding="utf-8") as f:
        return json.load(f)


def outbound_shadowsocks(тег, метаданные_сервера, inbound):
    """Shadowsocks-2022 — второй протокол «на другой почерк»: без TLS-рукопожатия
    вообще, шифрование с первого байта. Режут TLS-подобный трафик — этот ещё
    ходит, и наоборот. В этом и смысл второго протокола по ТЗ.

    ВАЖНО про ключ: используется ОДИН серверный PSK, а не пара
    "серверный:клиентский". Multi-user здесь не работает — проверено эмпирически
    прямо на сервере (все три порядка пары дают таймаут, одиночный серверный
    ключ работает): эта сборка 3x-ui не пробрасывает список clients в xray для
    shadowsocks-inbound-а. Следствие, которое надо знать: на этом протоколе НЕТ
    поимённого отзыва доступа — он резервный канал для владельца. Раздача людям
    и отзыв живут на vless-inbound-е, где multi-user работает штатно."""
    ss = inbound.get("shadowsocks") or {}
    серверный = ss.get("серверный_ключ")
    if not серверный:
        return None
    return {
        "type": "shadowsocks",
        "tag": тег,
        "server": метаданные_сервера.get("домен") or метаданные_сервера["host"],
        "server_port": inbound["порт"],
        "method": ss.get("метод"),
        "password": серверный,
    }


def outbound_vless(тег, метаданные_сервера, inbound, клиент):
    """Один outbound sing-box на один (сервер, inbound, клиент)."""
    host = метаданные_сервера.get("домен") or метаданные_сервера["host"]
    базовый = {
        "type": "vless",
        "tag": тег,
        "server": host,
        "server_port": inbound["порт"],
        "uuid": клиент["id"],
        "flow": клиент.get("flow") or "",
        "packet_encoding": "xudp",
    }
    if inbound.get("безопасность") == "reality":
        r = inbound.get("reality") or {}
        базовый["tls"] = {
            "enabled": True,
            "server_name": (r.get("server_names") or [""])[0],
            "utls": {"enabled": True, "fingerprint": r.get("fingerprint") or "chrome"},
            "reality": {
                "enabled": True,
                "public_key": r.get("public_key") or "",
                "short_id": (r.get("short_ids") or [""])[0],
            },
        }
    elif inbound.get("безопасность") == "tls":
        домен = метаданные_сервера.get("домен")
        базовый["tls"] = {
            "enabled": True,
            "server_name": домен or host,
            # НЕ угадываем по наличию домена — на senko-1 домена нет, но
            # сертификат настоящий (Let's Encrypt на голый IP, короткоживущий),
            # и insecure=False проверено живым подключением. Источник —
            # servers.json → tls_insecure (по умолчанию false); ставь true
            # только если сервер реально на самоподписанном сертификате.
            "insecure": метаданные_сервера.get("tls_insecure", False),
            "utls": {"enabled": True, "fingerprint": "chrome"},
        }
    else:
        # anytls / hysteria2 и т.п. — на живых серверах пока не заведены, схему
        # outbound-а для них здесь не строим, чтобы не выдумывать непроверенное.
        return None
    return базовый


def собрать_proxy_outbounds(реестр, клиент_email):
    """Возвращает (список outbound-ов, список тегов) для всех живых серверов, где
    у указанного клиента есть доступ хотя бы в одном поддержанном inbound-е.
    Каждый inbound даёт свой outbound — в этом и смысл нескольких протоколов:
    группа `авто` сама выберет живой, когда один почерк начнут резать."""
    outbounds = []
    теги = []
    for имя_сервера, данные in реестр.get("серверы", {}).items():
        if not данные.get("жив"):
            continue
        метаданные = данные["метаданные"]
        for inbound in данные.get("панель_3xui", {}).get("inbounds", []):
            # ОТЛОЖЕНО: shadowsocks в конфиг sing-box пока не включаем.
            # Серверная сторона рабочая (проверено и с сервера, и с мака
            # xray-клиентом, и sing-box-ом в ИЗОЛИРОВАННОМ конфиге), но в этом
            # полном конфиге sing-box через неё не ходит — причина не найдена:
            # отсечены DNS, правила, sniff, селекторы и cache_file, ни одно не
            # виновато. Пока не разобрано — не тащим в рабочий контур, чтобы
            # группа `авто` не переключалась на заведомо мёртвый узел.
            # Ссылка ss:// при этом продолжает генерироваться (links.py) —
            # обычные клиенты (v2rayNG и т.п.) этот inbound используют штатно.
            if inbound.get("протокол") == "shadowsocks":
                continue

            for клиент in inbound.get("клиенты_из_settings", []):
                email = клиент.get("email") or ""
                # client_admin.py заводит клиентов как "<имя>-<ремарка inbound-а>"
                # (email обязан быть уникальным в пределах сервера), а созданные
                # руками через панель — просто "<имя>". Принимаем оба вида,
                # иначе второй протокол молча не попадает в конфиг.
                if email != клиент_email and not email.startswith(f"{клиент_email}-"):
                    continue
                тег = f"{имя_сервера}-{inbound.get('remark') or inbound['id']}"
                # Один inbound = один outbound. Если у одного человека в одном
                # inbound-е почему-то два доступа (например 'me' и 'me-main' —
                # так получилось из-за бага в client_admin.py), без этой проверки
                # получится два outbound-а с ОДИНАКОВЫМ тегом, и sing-box откажется
                # запускаться целиком. Берём первый и идём дальше.
                if тег in теги:
                    break
                ob = (outbound_vless(тег, метаданные, inbound, клиент)
                      if inbound.get("протокол") == "vless" else None)
                if ob:
                    outbounds.append(ob)
                    теги.append(тег)
    return outbounds, теги


def морда_outbound_tag(реестр, конфиг_морды):
    """Тег outbound-а сервера, на котором живёт морда — чтобы направить туда
    трафик по фиктивному имени/IP напрямую, а не через селектор 'выбор'."""
    if not конфиг_морды:
        return None
    сервер = конфиг_морды.get("сервер")
    данные = реестр.get("серверы", {}).get(сервер)
    if not данные or not данные.get("жив"):
        return None
    inbounds = данные.get("панель_3xui", {}).get("inbounds", [])
    if not inbounds:
        return None
    return f"{сервер}-{inbounds[0].get('remark') or inbounds[0]['id']}"


def собрать_route_rules(конфиг_морды, тег_морды, корп_домены):
    правила = [
        {"action": "sniff"},
        {"protocol": "dns", "action": "hijack-dns"},
    ]

    if конфиг_морды and тег_морды:
        # override_address/override_port: пакет летит на фиктивный IP, но реально
        # заказывается адрес назначения 127.0.0.1:порт УЖЕ на стороне сервера —
        # xray-core там сам достучится до петли, где слушает морда. Так наружу
        # не открывается ничего, а с мака морда видна только через свой же туннель.
        морда_override = {
            "outbound": тег_морды,
            "override_address": "127.0.0.1",
            "override_port": конфиг_морды["порт"],
        }
        правила.append({"domain": конфиг_морды["хост"], **морда_override})
        правила.append({"ip_cidr": [f"{конфиг_морды['фиктивный_ip']}/32"], **морда_override})
    # иначе — морда ещё не развёрнута, шаг просто пропускается

    правила.append({"ip_is_private": True, "outbound": "direct"})

    if корп_домены:
        правила.append({"domain_suffix": корп_домены, "outbound": "direct"})
    # корп-туннель в этом проходе не строится — список пуст, правило не нужно

    правила.append({"rule_set": "geosite-category-ads-all", "action": "reject"})

    правила.append(
        {
            "rule_set": GEOSITE_ЧЕРЕЗ_ТУННЕЛЬ,
            "domain_suffix": ДОМЕНЫ_ЧЕРЕЗ_ТУННЕЛЬ,
            "outbound": "выбор",
        }
    )

    правила.append({"domain_suffix": РОССИЙСКИЕ_ЗОНЫ, "outbound": "direct"})
    правила.append({"rule_set": "geoip-ru", "outbound": "direct"})

    return правила


def собрать_rule_sets():
    """rule_set-объекты — все .srs, что реально лежат в rulesets/ (после
    `./vpn обнови`). Путь абсолютный — publish.sh перепишет его при установке
    в root-владение."""
    итог = []
    for файл in sorted(RULESETS.glob("*.srs")):
        итог.append(
            {
                "type": "local",
                "tag": файл.stem,
                "format": "binary",
                "path": str(файл),
            }
        )
    return итог


def собрать_dns(тег_выбор, конфиг_морды):
    """Новый формат DNS-серверов sing-box (с 1.12.0, legacy формат в 1.13 уже не
    запускается без ENABLE_DEPRECATED_LEGACY_DNS_SERVERS — проверено `sing-box check`).

    Российские зоны — быстрый российский резолвер напрямую (и быстрее, и не светимся
    в тоннеле почём зря). Всё остальное — DoH через туннель, чтобы запросы не утекали
    мимо. Имя морды резолвится статически (hosts-сервер) в фиктивный IP — никакой
    реальный DNS про него не знает и знать не должен.
    """
    servers = []
    rules = []

    if конфиг_морды:
        servers.append(
            {
                "type": "hosts",
                "tag": "hosts-морда",
                "predefined": {конфиг_морды["хост"]: конфиг_морды["фиктивный_ip"]},
            }
        )
        rules.append({"domain": конфиг_морды["хост"], "server": "hosts-морда"})

    # detour НЕ указываем: sing-box без detour уже резолвит напрямую (эквивалент
    # пустого direct-outbound-а) — явное "detour": "direct" на такой же пустой
    # direct он считает бессмысленным и отказывается стартовать ("detour to an
    # empty direct outbound makes no sense", проверено `sing-box run`).
    servers.append({"type": "udp", "tag": "ru-dns", "server": "77.88.8.8", "server_port": 53})
    servers.append(
        {
            "type": "https",
            "tag": "remote-dns",
            "server": "1.1.1.1",
            "server_port": 443,
            "path": "/dns-query",
            "detour": тег_выбор,
        }
    )

    rules.append({"domain_suffix": РОССИЙСКИЕ_ЗОНЫ, "server": "ru-dns"})

    return {
        "servers": servers,
        "rules": rules,
        "final": "remote-dns",
        "strategy": "prefer_ipv4",
        "independent_cache": True,
    }


def собрать_конфиг(режим, реестр, конфиг_морды, корп_домены, клиент_email, стартовый_узел=None):
    proxy_outbounds, теги = собрать_proxy_outbounds(реестр, клиент_email)
    # Внешние конфиги — ссылки не с наших серверов, добавленные вручную через
    # морду. Живут рядом с "нашими" узлами в тех же группах авто/вручную.
    внешние_outbounds, внешние_теги = external_configs.outbounds_и_теги()
    proxy_outbounds += внешние_outbounds
    теги += внешние_теги
    тег_морды = морда_outbound_tag(реестр, конфиг_морды)

    группы = []
    if теги:
        группы.append(
            {
                "type": "urltest",
                "tag": "авто",
                "outbounds": теги,
                "url": "https://www.gstatic.com/generate_204",
                "interval": "1m",
            }
        )
        группы.append(
            {
                "type": "selector",
                "tag": "вручную",
                # Если при запуске выбран конкретный узел — он и стоит по
                # умолчанию, ещё до первого пакета. Переключать после старта
                # через clash API тоже можно, но тогда первые соединения
                # успевают уйти не туда, куда просили.
                "outbounds": теги,
                "default": стартовый_узел if стартовый_узел in теги else теги[0],
            }
        )
    выбор_members = (["авто"] if теги else []) + (["вручную"] if теги else []) + ["direct"]
    if стартовый_узел == "direct":
        стартовый_режим = "direct"
    elif стартовый_узел and стартовый_узел in теги:
        стартовый_режим = "вручную"
    else:
        стартовый_режим = "авто" if теги else "direct"
    группы.append(
        {
            "type": "selector",
            "tag": "выбор",
            "outbounds": выбор_members,
            "default": стартовый_режим,
        }
    )
    # "авто-через-рф" не строится: среди серверов нет ни одного с "релей_для_ру":
    # true — добавлять пустую/нерабочую группу в конфиг хуже, чем не добавлять её.

    # "dns"-outbound — legacy, убран в sing-box 1.13: DNS перехватывается правилом
    # {"action": "hijack-dns"} и обслуживается модулем dns напрямую, отдельный
    # outbound для этого больше не нужен.
    outbounds = proxy_outbounds + группы + [
        {"type": "direct", "tag": "direct"},
        {"type": "block", "tag": "block"},
    ]

    inbounds = []
    if режим == "tun":
        inbounds.append(
            {
                "type": "tun",
                "tag": "tun-in",
                # interface_name НЕ задаём: на macOS utun-интерфейсы обязаны
                # называться utunN (число, выбирает ядро) — кастомное имя
                # ("utun-vpnctl") ядро отклоняет с "bad tun name" (проверено
                # `sing-box run`). Пустое поле — "выбирается автоматически".
                "address": ["172.19.0.1/30"],
                "mtu": 9000,
                "auto_route": True,
                "strict_route": True,
                "stack": "gvisor",
            }
        )
    else:
        inbounds.append(
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": 2080,
            }
        )
    # sniff как поле inbound-а — legacy, убран из sing-box 1.13. Вместо него
    # первое правило маршрутизации {"action": "sniff"} (см. собрать_route_rules).

    конфиг = {
        "log": {"level": "info"},
        "experimental": {
            "cache_file": {"enabled": True, "path": str(КОРЕНЬ / "state" / "cache.db")},
            "clash_api": {
                "external_controller": "127.0.0.1:9090",
                # Веб-панель (metacubexd) — графики трафика, логи, правила,
                # переключение узлов. Качается `./vpn обнови`, поэтому путь
                # может не существовать: sing-box в этом случае просто не
                # отдаёт /ui, работать это не мешает.
                "external_ui": str(UI_PANEL) if UI_PANEL.is_dir() else "",
            },
        },
        "dns": собрать_dns("выбор", конфиг_морды),
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {
            "rules": собрать_route_rules(конфиг_морды, тег_морды, корп_домены),
            "rule_set": собрать_rule_sets(),
            "final": "выбор",
            "auto_detect_interface": True,
            # Без этого поля sing-box 1.12+ не знает, каким резолвером бить домены
            # в outbound.server у прокси — используем тот же DoH-через-туннель.
            "default_domain_resolver": "remote-dns",
        },
    }
    return конфиг


def main():
    парсер = argparse.ArgumentParser(description="Собрать клиентский конфиг sing-box")
    парсер.add_argument("--mode", choices=["tun", "local"], required=True)
    парсер.add_argument("--client", default=None,
                         help="email клиента в панели (по умолчанию — servers.json → клиент.мой_email)")
    парсер.add_argument("--node", default=None,
                         help="с какого узла стартовать: тег узла (senko-1-main), "
                              "'direct' или ничего (тогда 'авто' — сам выберет лучший)")
    парсер.add_argument("--список-узлов", dest="список", action="store_true",
                         help="показать доступные узлы и выйти")
    парсер.add_argument("--out", help="куда писать (по умолчанию state/client-<mode>.json)")
    аргс = парсер.parse_args()

    if not РЕЕСТР.exists():
        print("нет state/registry.json — сначала `python3 collect.py`", file=sys.stderr)
        return 1

    реестр = читать_json(РЕЕСТР)
    servers_данные = читать_json(СЕРВЕРЫ)
    конфиг_морды = servers_данные.get("морда")
    корп_домены = servers_данные.get("клиент", {}).get("корп_домены", [])

    клиент = аргс.client or servers_данные.get("клиент", {}).get("мой_email")
    if not клиент:
        print("нет --client и нет 'клиент.мой_email' в servers.json — некого искать в реестре", file=sys.stderr)
        return 1

    if аргс.список:
        _, доступные = собрать_proxy_outbounds(реестр, клиент)
        for тег in доступные:
            print(тег)
        print("direct")
        return 0

    конфиг = собрать_конфиг(аргс.mode, реестр, конфиг_морды, корп_домены, клиент, аргс.node)

    if аргс.node:
        _, доступные = собрать_proxy_outbounds(реестр, клиент)
        if аргс.node not in доступные and аргс.node != "direct":
            print(f"нет узла {аргс.node!r}. Доступны: {', '.join(доступные + ['direct'])}",
                  file=sys.stderr)
            return 1

    путь_вывода = Path(аргс.out) if аргс.out else КОРЕНЬ / "state" / f"client-{аргс.mode}.json"
    путь_вывода.parent.mkdir(exist_ok=True)
    путь_вывода.write_text(json.dumps(конфиг, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"записано → {путь_вывода}")

    if not реестр.get("серверы") or not any(
        d.get("жив") for d in реестр["серверы"].values()
    ):
        print("предупреждение: ни один сервер не жив — outbound-ов на прокси нет, "
              "конфиг работает только как direct", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
