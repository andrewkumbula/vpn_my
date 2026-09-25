#!/usr/bin/env python3
"""Выполняется НА СЕРВЕРЕ (пайпом: `ssh хост python3 - <порт> --remark <имя> [--apply] <
add_inbound.py`). Заводит НОВЫЙ inbound (не клиента в существующем — это делает
client_admin.py). По умолчанию dry-run, бэкап БД перед --apply, клиентов внутри
не создаёт — это отдельный шаг через client_admin.py/people.py.

⚠️ НЕ РАБОТАЕТ на текущей сборке 3x-ui — проверено дважды, вживую:
  * созданный этим скриптом vless-inbound слушает порт и отдаёт валидный TLS,
    но VLESS-аутентификация не проходит даже когда сервер подключается сам к
    себе, при БУКВАЛЬНО одинаковой с рабочим inbound-ом записью в БД;
  * у shadowsocks аналогично не подхватывается список clients (работает только
    общий серверный ключ).
Причина: панель не просто хранит JSON — при выкладке в xray она прогоняет его
через собственную обработку (Heal*/Strip* в internal/database/model/model.go),
и прямая запись в sqlite мимо панели даёт формально верную, но нерабочую
конфигурацию.

Как заводить inbound на самом деле: через веб-панель 3x-ui. Наши инструменты
читают результат сами (collect.py) — ЧТЕНИЕ базы работает надёжно, ломается
только запись. Скрипт оставлен для серверов с другой панелью/сборкой и как
готовая схема настроек; перед использованием убедись, что созданный им inbound
реально пускает трафик.

По умолчанию — vless+tls без домена (та же схема, что на 'main'): на этом
сервере Reality оказался сломан на уровне xray-core (см. диагностику — хендшейк
не проходит даже сервер сам с собой), поэтому tls — единственный проверенный
рабочий вариант. --security reality оставлен для будущего (другой сервер / после
починки xray), но предупреждение не убираю — сам по себе флаг ничего не чинит.
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

# Shadowsocks-2022: AEAD с ключом из 16 байт, поддерживается и xray-core
# (сервер), и sing-box (клиент). Выбран как ВТОРОЙ протокол именно из-за
# другого почерка: в отличие от vless+tls тут нет TLS-рукопожатия вообще,
# шифрование с первого байта — режут TLS-почерк, этот ещё ходит.
SS_МЕТОД = "2022-blake3-aes-128-gcm"

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


def открыть_порт(порт, apply_):
    """UFW по умолчанию пускает только 22/80/443 — новый inbound без этого шага
    слушает, но снаружи недоступен, и выглядит это как «протокол не работает»
    (потеряно на этом изрядно времени). Открываем и tcp, и udp: udp нужен
    hysteria/quic-подобным и shadowsocks с udp-релеем."""
    if not shutil.which("ufw"):
        print("  ufw не найден — проверь файрвол сам, порт может быть закрыт")
        return
    статус = subprocess.run(["ufw", "status"], capture_output=True, text=True).stdout
    if статус.strip().startswith("Status: inactive"):
        print("  ufw выключен — порт открывать не нужно")
        return
    if not apply_:
        print(f"  [dry-run] открыл бы в ufw порт {порт} (tcp и udp)")
        return
    for протокол in ("tcp", "udp"):
        subprocess.run(["ufw", "allow", f"{порт}/{протокол}"], capture_output=True, check=False)
    print(f"  порт {порт} открыт в ufw (tcp+udp)")


def собрать_settings(протокол, безопасность):
    """settings-часть inbound-а. Для vless — пустой список клиентов (заводятся
    отдельно через client_admin.py). Для shadowsocks-2022 — серверный ключ
    (PSK) плюс пустой список клиентов: в multi-user режиме клиент подключается
    паролем вида "<серверный PSK>:<клиентский PSK>"."""
    if протокол == "vless":
        return json.dumps({"clients": [], "decryption": "none", "fallbacks": []})
    if протокол == "shadowsocks":
        # 2022-blake3-aes-128-gcm → ключ ровно 16 байт в base64.
        серверный_ключ = base64.b64encode(secrets.token_bytes(16)).decode()
        return json.dumps({
            "method": SS_МЕТОД,
            "password": серверный_ключ,
            "network": "tcp,udp",
            "clients": [],
        })
    raise ValueError(f"неизвестный протокол: {протокол}")


def собрать_stream_settings(безопасность):
    if безопасность == "none":
        # shadowsocks сам себе транспорт — TLS поверх не нужен и вреден
        # (лишний слой, лишний почерк).
        return json.dumps({"network": "tcp", "security": "none"})
    if безопасность == "tls":
        # Переиспользуем РЕАЛЬНЫЙ сертификат существующего inbound-а 'main' —
        # это не самоподпись, а настоящий Let's Encrypt на голый IP (LE теперь
        # это умеет, короткоживущий ~7 дней, автообновление — забота панели).
        # Один и тот же файл можно вешать на несколько портов одновременно.
        return json.dumps({
            "network": "tcp",
            "security": "tls",
            "tlsSettings": {
                "serverName": "",
                "minVersion": "1.2",
                "maxVersion": "1.3",
                "certificates": [{
                    "certificateFile": "/etc/x-ui/tls/vpn-le.crt",
                    "keyFile": "/etc/x-ui/tls/vpn-le.key",
                }],
                "alpn": ["http/1.1"],
                "settings": {"allowInsecure": False, "fingerprint": "chrome"},
            },
        })
    if безопасность == "reality":
        import base64
        import tempfile
        import os

        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
            priv_path = f.name
        try:
            subprocess.run(["openssl", "genpkey", "-algorithm", "X25519", "-out", priv_path],
                            check=True, capture_output=True)
            priv_der = subprocess.run(["openssl", "pkey", "-in", priv_path, "-outform", "DER"],
                                       check=True, capture_output=True).stdout
            pub_der = subprocess.run(["openssl", "pkey", "-in", priv_path, "-pubout", "-outform", "DER"],
                                      check=True, capture_output=True).stdout
        finally:
            os.unlink(priv_path)

        def b64(raw):
            return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

        return json.dumps({
            "network": "tcp",
            "security": "reality",
            "realitySettings": {
                "show": False,
                "dest": "www.microsoft.com:443",
                "xver": 0,
                "serverNames": ["www.microsoft.com"],
                "privateKey": b64(priv_der[-32:]),
                "minClientVer": "0.0.0",
                "maxTimeDiff": 0,
                "shortIds": [secrets.token_hex(4)],
                "settings": {"publicKey": b64(pub_der[-32:]), "fingerprint": "chrome",
                             "serverName": "", "spiderX": "/"},
            },
        })
    raise ValueError(f"неизвестная безопасность: {безопасность}")


def main():
    парсер = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    парсер.add_argument("port", type=int)
    парсер.add_argument("--remark", required=True)
    парсер.add_argument("--protocol", choices=["vless", "shadowsocks"], default="vless")
    парсер.add_argument("--security", choices=["tls", "reality", "none"], default=None,
                         help="по умолчанию: tls для vless, none для shadowsocks")
    парсер.add_argument("--apply", action="store_true")
    аргс = парсер.parse_args()

    # shadowsocks шифрует сам, TLS поверх ему не нужен — если явно не сказано
    # иное, ставим none, иначе получится лишний слой и лишний почерк.
    if аргс.security is None:
        аргс.security = "none" if аргс.protocol == "shadowsocks" else "tls"

    if аргс.protocol == "shadowsocks" and аргс.security != "none":
        print("shadowsocks поверх TLS не поддерживается этим скриптом — "
              "смысл протокола именно в отсутствии TLS-рукопожатия", file=sys.stderr)
        return 1

    if аргс.security == "reality":
        print("предупреждение: Reality на этом сервере ранее не проходил хендшейк "
              "(диагностировано отдельно) — этот флаг не чинит xray-core, "
              "используй только если проверяешь именно это заново", file=sys.stderr)

    путь_бд = найти_бд()
    if путь_бд is None:
        print("3x-ui не установлен на этом сервере (БД не найдена)", file=sys.stderr)
        return 1

    соединение = sqlite3.connect(путь_бд)
    курсор = соединение.cursor()

    занят = курсор.execute("SELECT id, remark FROM inbounds WHERE port = ?", (аргс.port,)).fetchone()
    if занят:
        print(f"порт {аргс.port} уже занят inbound-ом {занят[0]} ({занят[1]})", file=sys.stderr)
        соединение.close()
        return 1

    settings = собрать_settings(аргс.protocol, аргс.security)
    stream = собрать_stream_settings(аргс.security)
    tag = f"in-{аргс.port}-tcp"

    print(f"{'[apply]' if аргс.apply else '[dry-run]'} новый inbound: "
          f"порт={аргс.port}, protocol={аргс.protocol}, security={аргс.security}, "
          f"remark={аргс.remark!r}, клиентов пока 0 (добавь через client_admin.py/people.py)")

    if аргс.apply:
        копия = резервная_копия(путь_бд)
        print(f"резервная копия БД: {копия}")
        курсор.execute(
            "INSERT INTO inbounds (user_id, up, down, total, remark, enable, expiry_time, "
            "listen, port, protocol, settings, stream_settings, tag, sniffing, disable_flow) "
            "VALUES (1, 0, 0, 0, ?, 1, 0, '', ?, ?, ?, ?, ?, "
            "'{\"enabled\": true, \"destOverride\": [\"http\",\"tls\",\"quic\",\"fakedns\"]}', 0)",
            (аргс.remark, аргс.port, аргс.protocol, settings, stream, tag),
        )
        соединение.commit()

    соединение.close()

    if аргс.apply:
        открыть_порт(аргс.port, аргс.apply)
        перезапустить_x_ui(аргс.apply)
        print(f"\nготово — добавь клиента: ssh ... python3 - add <имя> --protocols vless "
              f"--apply < client_admin.py  (но там фильтр по протоколу общий на все "
              f"vless-inbound-ы — если нужно точечно в этот, использовать напрямую 3x-ui API "
              f"или расширить client_admin.py под --port)")
    else:
        открыть_порт(аргс.port, False)
        print("\n(dry-run — добавь --apply, чтобы применить)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
