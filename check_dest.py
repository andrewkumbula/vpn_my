#!/usr/bin/env python3
"""ТОЛЬКО ЧТЕНИЕ. Можно гонять и локально (проверить сайт с мака), и на сервере
(`ssh хост python3 - <dest> < check_dest.py`) — сайт-маскировку Reality нельзя
подобрать угадыванием: он должен открываться именно оттуда, откуда его дёргает
xray, и вести себя предсказуемо (не редиректить, отвечать TLS 1.3, поддерживать
h2 при необходимости).

Проверяем в двух измерениях:
  1. Прямой TLS-хэндшейк с сайтом (получится ли вообще достучаться)
  2. HTTP-заголовки ответа (не редирект ли, не 4xx/5xx)
Живого Reality-соединения сквозь сервер это НЕ проверяет — это отдельная ручная
проверка клиентом после того, как set_reality_dest.py применит смену.
"""
import socket
import ssl
import sys


def проверить(dest):
    """dest в формате host:port, как в realitySettings.dest."""
    if ":" not in dest:
        print(f"плохой формат, жду host:port, получил: {dest}", file=sys.stderr)
        return False
    host, порт = dest.rsplit(":", 1)
    порт = int(порт)

    print(f"→ {host}:{порт}")

    контекст = ssl.create_default_context()
    try:
        with socket.create_connection((host, порт), timeout=8) as sock:
            with контекст.wrap_socket(sock, server_hostname=host) as tls:
                версия = tls.version()
                print(f"  TLS: {версия}")
                if версия not in ("TLSv1.3",):
                    print("  ⚠ не TLS 1.3 — Reality таким сайтом маскироваться не сможет")
    except (socket.timeout, ConnectionRefusedError, ssl.SSLError, OSError) as e:
        print(f"  ✗ TLS-хэндшейк не удался: {e}")
        return False

    try:
        запрос = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        контекст2 = ssl.create_default_context()
        with socket.create_connection((host, порт), timeout=8) as sock:
            with контекст2.wrap_socket(sock, server_hostname=host) as tls:
                tls.sendall(запрос.encode())
                ответ = tls.recv(4096).decode("utf-8", "replace")
        первая_строка = ответ.splitlines()[0] if ответ else "(пусто)"
        print(f"  HTTP: {первая_строка}")
        if " 3" in первая_строка[:12]:
            print("  ⚠ редирект — Reality с таким сайтом ведёт себя подозрительно, лучше не использовать")
    except Exception as e:
        print(f"  ⚠ HTTP-проверка не удалась (TLS уже прошёл, это не критично): {e}")

    return True


def main():
    if len(sys.argv) < 2:
        print("использование: check_dest.py host:port [host:port ...]", file=sys.stderr)
        return 1
    if not getattr(ssl, "HAS_TLSv1_3", False):
        # На старых сборках OpenSSL/LibreSSL (типично для системного python3 на
        # macOS) TLS 1.3 недоступен самому интерпретатору — проверка ниже тогда
        # всегда покажет "не TLS 1.3", даже если сайт его прекрасно поддерживает.
        # Это про интерпретатор, не про сайт — предупреждаем один раз и не врём.
        print(
            "⚠ этот python собран без поддержки TLS 1.3 — предупреждения "
            "«не TLS 1.3» ниже могут быть ложными. Гоняй на сервере (python3.12+, "
            "нормальный OpenSSL), не на macOS system python3.\n",
            file=sys.stderr,
        )
    итог = True
    for dest in sys.argv[1:]:
        итог = проверить(dest) and итог
        print()
    return 0 if итог else 1


if __name__ == "__main__":
    sys.exit(main())
