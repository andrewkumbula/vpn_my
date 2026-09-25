#!/usr/bin/env python3
"""Живёт НА СЕРВЕРЕ (деплоится deploy_ui.py вместе с remote_dump.py, links.py,
ui_page.html). ТОЛЬКО ЧТЕНИЕ — инвариант №10: заводить/отзывать отсюда нельзя,
иначе серверу нужны ключи к соседям, и его взлом отдаёт управление всем парком.
Никаких /api/people/* маршрутов здесь нет вообще, не «выключены» — их физически
не существует в этом файле.

Слушает только 127.0.0.1 — наружу порт не открыт (инвариант №9). Достаётся с мака
через фиктивный IP/имя в его собственном туннеле — см. render_client.py
и servers.json → "морда". Плюс пароль (HTTP Basic) — чтобы не хватило одного
только рабочего ключа для просмотра.
"""
import base64
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse

КОРЕНЬ = Path(__file__).resolve().parent
UI_PAGE = КОРЕНЬ / "ui_page.html"
ХЭШ_ПАРОЛЯ_ФАЙЛ = КОРЕНЬ / "password.hash"
ПОРТ = int(os.environ.get("VPNCTL_UI_PORT", "8443"))

sys.path.insert(0, str(КОРЕНЬ))
import links as links_модуль  # noqa: E402
import remote_dump  # noqa: E402


def проверить_пароль(пароль):
    if not ХЭШ_ПАРОЛЯ_ФАЙЛ.exists():
        return False
    соль_hex, хэш_hex = ХЭШ_ПАРОЛЯ_ФАЙЛ.read_text().strip().split(":")
    соль = bytes.fromhex(соль_hex)
    вычисленный = hashlib.pbkdf2_hmac("sha256", пароль.encode(), соль, 200_000).hex()
    return вычисленный == хэш_hex


def дамп_в_форме_реестра():
    """Та же форма, что registry.json на маке — {"серверы": {"этот-сервер": {...}}} —
    чтобы ui_page.html работал без развилки клиент/сервер."""
    return {
        "собрано": datetime.now(timezone.utc).isoformat(),
        "серверы": {
            "этот-сервер": {
                "жив": True,
                "метаданные": {"имя": "этот-сервер", "host": "127.0.0.1", "домен": None},
                "панель_3xui": remote_dump.дамп_xui(),
            }
        },
    }


class Обработчик(BaseHTTPRequestHandler):
    server_version = "vpnctl-ui-ro/1.0"

    def log_message(self, формат, *аргс):
        pass

    def _авторизован(self):
        заголовок = self.headers.get("Authorization", "")
        if not заголовок.startswith("Basic "):
            return False
        try:
            декод = base64.b64decode(заголовок[6:]).decode()
            _, пароль = декод.split(":", 1)
        except Exception:
            return False
        return проверить_пароль(пароль)

    def _требуем_пароль(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="vpnctl"')
        self.end_headers()

    def _json(self, данные, код=200):
        тело = json.dumps(данные, ensure_ascii=False).encode()
        self.send_response(код)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(тело)))
        self.end_headers()
        self.wfile.write(тело)

    def do_GET(self):
        if not self._авторизован():
            return self._требуем_пароль()

        путь = urlparse(self.path).path
        if путь == "/":
            текст = UI_PAGE.read_text(encoding="utf-8")
            текст = текст.replace("__VPNCTL_TOKEN__", "").replace("__READ_ONLY__", "true")
            тело = текст.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(тело)))
            self.end_headers()
            self.wfile.write(тело)
            return

        if путь == "/api/state":
            return self._json(дамп_в_форме_реестра())

        if путь == "/api/links":
            # По одной ссылке на каждого клиента, фильтр по его собственному
            # email — иначе (как было раньше) второй заведённый человек видит
            # чужую ссылку с чужим UUID.
            реестр = дамп_в_форме_реестра()
            итог = []
            for имя_сервера, данные in реестр["серверы"].items():
                метаданные = данные["метаданные"]
                for inbound in данные["панель_3xui"].get("inbounds", []):
                    for клиент in inbound.get("клиенты_из_settings", []):
                        email = клиент.get("email")
                        for ссылка in links_модуль.ссылки_из_inbound(метаданные, inbound, email):
                            if ссылка.startswith("#"):
                                continue
                            итог.append({
                                "сервер": имя_сервера,
                                "inbound_id": inbound["id"],
                                "email": email,
                                "ссылка": ссылка,
                                "qr": None,  # qrencode на сервере не ставим — не нужен для чтения
                            })
            return self._json(итог)

        self.send_response(404)
        self.end_headers()

    # do_POST сознательно не реализован — read-only означает read-only,
    # а не "POST есть, но проверка блокирует".


def main():
    сервер = HTTPServer(("127.0.0.1", ПОРТ), Обработчик)
    print(f"read-only морда: http://127.0.0.1:{ПОРТ}/")
    try:
        сервер.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
