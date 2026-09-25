#!/usr/bin/env python3
"""Морда на маке — полный доступ (в отличие от deploy_ui.py на сервере, который
только читает, инвариант №10 — заводить/отзывать можно только отсюда, локально).

Слушает 127.0.0.1 — наружу не торчит. Токен в заголовке X-Vpnctl-Token защищает
от CSRF с открытой в браузере левой вкладки (localhost-сервисы иначе бьются
блайндом безо всякого доступа к содержимому ответа) — не от кого-то постороннего:
посторонний до 127.0.0.1 этой машины и так не достучится.

Только стандартная библиотека — http.server, никаких flask/fastapi.
"""
import base64
import json
import secrets
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse

КОРЕНЬ = Path(__file__).resolve().parent
РЕЕСТР = КОРЕНЬ / "state" / "registry.json"
UI_PAGE = КОРЕНЬ / "ui_page.html"
ПОРТ = 7890

sys.path.insert(0, str(КОРЕНЬ))
import external_configs  # noqa: E402
import links as links_модуль  # noqa: E402

ТОКЕН = secrets.token_hex(16)
VPN_SCRIPT = str(КОРЕНЬ / "vpn")
CLASH_API = "http://127.0.0.1:9090"
URL_ЗАМЕРА = "https://www.gstatic.com/generate_204"

# Служебные outbound-ы sing-box, которые не являются "узлами" в человеческом
# смысле — в списке для выбора их показывать не надо.
СЛУЖЕБНЫЕ_ВЫХОДЫ = {"block", "dns-out"}


def clash_запрос(путь, метод="GET", тело=None, таймаут=3):
    запрос = urllib.request.Request(
        f"{CLASH_API}{путь}",
        data=json.dumps(тело).encode() if тело is not None else None,
        method=метод,
        headers={"Content-Type": "application/json"} if тело is not None else {},
    )
    with urllib.request.urlopen(запрос, timeout=таймаут) as ответ:
        сырое = ответ.read()
    return json.loads(сырое) if сырое else {}


def процесс_жив():
    """Тот же признак, что и в самом `vpn`-скрипте — pgrep по общему шаблону,
    не по своему pid-файлу (см. граблю в privileged/vpn-run: экземпляр из
    старого места публикации иначе останется невидимым)."""
    return subprocess.run(["pgrep", "-f", "sing-box run"], capture_output=True).returncode == 0


def тоннель_статус():
    запущен = процесс_жив()
    активный_узел = None
    режим = None
    if запущен:
        try:
            выбор = clash_запрос("/proxies/" + urllib.parse.quote("выбор"))
            режим = выбор.get("now")
            активный_узел = режим
            # "выбор" указывает на группу (авто/вручную) — разворачиваем до
            # конкретного узла, иначе в интерфейсе видно "авто" вместо страны.
            for _ in range(3):
                группа = clash_запрос("/proxies/" + urllib.parse.quote(активный_узел))
                вложенный = группа.get("now")
                if not вложенный or вложенный == активный_узел:
                    break
                активный_узел = вложенный
        except Exception:
            pass
    return {"запущен": запущен, "активный_узел": активный_узел, "режим": режим}


def задержка_из_истории(запись):
    история = запись.get("history") or []
    if not история:
        return None
    последняя = история[-1]
    задержка = последняя.get("delay")
    # 0 в clash-API значит "замер не удался", а не "мгновенно".
    return задержка if задержка else None


def узлы_и_группы():
    """Полная картина для морды: какие группы есть, что в них выбрано, какая у
    каждого узла последняя измеренная задержка."""
    if not процесс_жив():
        return {"доступно": False, "группы": [], "узлы": []}
    try:
        все = clash_запрос("/proxies").get("proxies", {})
    except Exception:
        return {"доступно": False, "группы": [], "узлы": []}

    группы, узлы = [], []
    for имя, запись in все.items():
        тип = запись.get("type", "")
        if имя in СЛУЖЕБНЫЕ_ВЫХОДЫ or имя == "GLOBAL":
            continue
        if тип in ("Selector", "URLTest"):
            группы.append({
                "имя": имя,
                "тип": тип,
                "выбрано": запись.get("now"),
                "варианты": [в for в in запись.get("all", []) if в not in СЛУЖЕБНЫЕ_ВЫХОДЫ],
            })
        else:
            узлы.append({
                "имя": имя,
                "тип": тип,
                "задержка_мс": задержка_из_истории(запись),
            })
    return {"доступно": True, "группы": группы, "узлы": узлы}


def замерить_узел(имя_узла, таймаут_мс=5000):
    путь = (f"/proxies/{urllib.parse.quote(имя_узла)}/delay"
            f"?timeout={таймаут_мс}&url={urllib.parse.quote(URL_ЗАМЕРА)}")
    try:
        ответ = clash_запрос(путь, таймаут=(таймаут_мс / 1000) + 2)
        return {"имя": имя_узла, "задержка_мс": ответ.get("delay"), "ошибка": None}
    except Exception as ошибка:
        # 504 от clash-API = узел не ответил в срок. Это валидный результат
        # замера ("мёртв"), а не поломка морды — так и показываем.
        return {"имя": имя_узла, "задержка_мс": None, "ошибка": str(ошибка)}


def внешний_ip():
    """Через какой адрес нас видит интернет прямо сейчас. В режиме перехвата
    идём напрямую (весь трафик и так в тоннеле), в локальном — через SOCKS,
    иначе увидим адрес провайдера и решим, что тоннель не работает."""
    попытки = []
    if процесс_жив():
        попытки.append(["curl", "-s", "-m", "6", "--socks5", "127.0.0.1:2080", "https://api.ipify.org"])
    попытки.append(["curl", "-s", "-m", "6", "https://api.ipify.org"])
    for команда in попытки:
        r = subprocess.run(команда, capture_output=True, text=True)
        значение = r.stdout.strip()
        if r.returncode == 0 and значение:
            return {"ip": значение, "через": "туннель" if "--socks5" in команда else "напрямую"}
    return {"ip": None, "через": None}


def qrencode_доступен():
    return shutil.which("qrencode") is not None


def qr_png_base64(текст):
    if not qrencode_доступен():
        return None
    try:
        r = subprocess.run(
            ["qrencode", "-t", "PNG", "-o", "-", "-s", "5", текст],
            capture_output=True, timeout=5, check=True,
        )
        return base64.b64encode(r.stdout).decode()
    except (subprocess.SubprocessError, OSError):
        return None


class Обработчик(BaseHTTPRequestHandler):
    server_version = "vpnctl-ui/1.0"

    def log_message(self, формат, *аргс):
        pass  # тихо — это личный инструмент, не веб-сервис с access.log

    def _токен_ок(self):
        return self.headers.get("X-Vpnctl-Token") == ТОКЕН

    def _json(self, данные, код=200):
        тело = json.dumps(данные, ensure_ascii=False).encode()
        self.send_response(код)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(тело)))
        self.end_headers()
        self.wfile.write(тело)

    def _html(self):
        текст = UI_PAGE.read_text(encoding="utf-8")
        текст = текст.replace("__VPNCTL_TOKEN__", ТОКЕН).replace("__READ_ONLY__", "false")
        тело = текст.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(тело)))
        self.end_headers()
        self.wfile.write(тело)

    def do_GET(self):
        путь = urlparse(self.path).path
        if путь == "/":
            return self._html()
        if путь == "/api/state":
            if not self._токен_ок():
                return self._json({"ошибка": "нет токена"}, 403)
            if not РЕЕСТР.exists():
                return self._json({"собрано": None, "серверы": {}})
            return self._json(json.loads(РЕЕСТР.read_text(encoding="utf-8")))
        if путь == "/api/links":
            if not self._токен_ок():
                return self._json({"ошибка": "нет токена"}, 403)
            return self._отдать_ссылки()
        if путь == "/api/tunnel/status":
            if not self._токен_ок():
                return self._json({"ошибка": "нет токена"}, 403)
            return self._json(тоннель_статус())
        if путь == "/api/nodes":
            if not self._токен_ок():
                return self._json({"ошибка": "нет токена"}, 403)
            return self._json(узлы_и_группы())
        if путь == "/api/ip":
            if not self._токен_ок():
                return self._json({"ошибка": "нет токена"}, 403)
            return self._json(внешний_ip())
        if путь == "/api/external":
            if not self._токен_ок():
                return self._json({"ошибка": "нет токена"}, 403)
            return self._json(external_configs.читать())
        self.send_response(404)
        self.end_headers()

    def _отдать_ссылки(self):
        """По ОДНОЙ ссылке на каждого клиента — фильтруем по его собственному
        email через links_модуль (тот же фильтр, что и `./vpn конфиг`). Раньше
        здесь брали только первую сгенерированную ссылку и приклеивали её ко
        ВСЕМ email-ам подряд — второй заведённый человек получал чужой UUID."""
        if not РЕЕСТР.exists():
            return self._json([])
        реестр = json.loads(РЕЕСТР.read_text(encoding="utf-8"))
        итог = []
        for имя_сервера, данные in реестр.get("серверы", {}).items():
            if not данные.get("жив"):
                continue
            метаданные = данные["метаданные"]
            for inbound in данные.get("панель_3xui", {}).get("inbounds", []):
                for клиент in inbound.get("клиенты_из_settings", []):
                    email = клиент.get("email")
                    свои_ссылки = links_модуль.ссылки_из_inbound(метаданные, inbound, email)
                    for ссылка in свои_ссылки:
                        if ссылка.startswith("#"):
                            continue
                        итог.append({
                            "сервер": имя_сервера,
                            "inbound_id": inbound["id"],
                            "email": email,
                            "ссылка": ссылка,
                            "qr": qr_png_base64(ссылка),
                        })
        return self._json(итог)

    def do_POST(self):
        путь = urlparse(self.path).path
        if not self._токен_ок():
            return self._json({"ошибка": "нет токена"}, 403)

        длина = int(self.headers.get("Content-Length", 0))
        тело = self.rfile.read(длина) if длина else b"{}"
        try:
            данные = json.loads(тело or b"{}")
        except json.JSONDecodeError:
            данные = {}

        if путь == "/api/refresh":
            subprocess.run([sys.executable, str(КОРЕНЬ / "collect.py")], check=False)
            return self._json({"ок": True})

        if путь == "/api/tunnel/start":
            режим = данные.get("режим", "local")
            команда = "перехват" if режим == "tun" else "старт"
            # Без интерактивного tty sudo сам не станет ждать пароль — если
            # NOPASSWD ещё не выдан (./vpn опубликовать не запускали), команда
            # просто вернёт ошибку с понятным текстом, а не подвиснет.
            r = subprocess.run([VPN_SCRIPT, команда], capture_output=True, text=True, timeout=30)
            return self._json({"ок": r.returncode == 0, "вывод": (r.stdout + r.stderr).strip()})

        if путь == "/api/tunnel/stop":
            r = subprocess.run([VPN_SCRIPT, "стоп"], capture_output=True, text=True, timeout=15)
            return self._json({"ок": r.returncode == 0, "вывод": (r.stdout + r.stderr).strip()})

        if путь == "/api/nodes/select":
            # Переключение режима ("выбор" → авто/вручную/direct) и «держаться
            # одного узла» ("вручную" → конкретный узел) — это одна и та же
            # операция clash-API, разница только в том, какую группу трогаем.
            группа = (данные.get("группа") or "").strip()
            вариант = (данные.get("вариант") or "").strip()
            if not группа or not вариант:
                return self._json({"ошибка": "нужны группа и вариант"}, 400)
            try:
                clash_запрос(f"/proxies/{urllib.parse.quote(группа)}", метод="PUT",
                             тело={"name": вариант})
                return self._json({"ок": True})
            except Exception as ошибка:
                return self._json({"ок": False, "ошибка": str(ошибка)}, 502)

        if путь == "/api/nodes/test":
            имя = (данные.get("узел") or "").strip()
            if имя:
                return self._json({"результаты": [замерить_узел(имя)]})
            # Без имени — прогоняем все реальные узлы разом (кнопка «замерить всё»).
            результаты = [замерить_узел(у["имя"]) for у in узлы_и_группы().get("узлы", [])]
            return self._json({"результаты": результаты})

        if путь == "/api/external/add":
            название = (данные.get("название") or "").strip()
            ссылка = (данные.get("ссылка") or "").strip()
            if not название or not ссылка:
                return self._json({"ошибка": "нужны название и ссылка"}, 400)
            try:
                external_configs.разобрать_vless(ссылка)
            except ValueError as е:
                # Не сохраняем то, что не разобрали — иначе в списке появится
                # узел, который никогда не заработает, и это станет непонятно
                # только после старта тоннеля.
                return self._json({"ок": False, "ошибка": str(е)}, 400)
            список = external_configs.читать()
            список.append({"название": название, "ссылка": ссылка})
            external_configs.записать(список)
            return self._json({"ок": True, "нужен_перезапуск": процесс_жив()})

        if путь == "/api/external/remove":
            название = (данные.get("название") or "").strip()
            список = external_configs.читать()
            оставшиеся = [з for з in список if з.get("название") != название]
            if len(оставшиеся) == len(список):
                return self._json({"ошибка": "не найдено"}, 404)
            external_configs.записать(оставшиеся)
            return self._json({"ок": True, "нужен_перезапуск": процесс_жив()})

        if путь == "/api/people/add":
            имя = данные.get("имя", "").strip()
            дни = int(данные.get("дни", 0) or 0)
            if not имя:
                return self._json({"ошибка": "нужно имя"}, 400)
            аргументы = [sys.executable, str(КОРЕНЬ / "people.py"), "добавь", имя,
                         "--days", str(дни), "--apply"]
            r = subprocess.run(аргументы, capture_output=True, text=True)
            return self._json({"ок": r.returncode == 0, "вывод": r.stdout + r.stderr})

        if путь == "/api/people/remove":
            имя = данные.get("имя", "").strip()
            if not имя:
                return self._json({"ошибка": "нужно имя"}, 400)
            аргументы = [sys.executable, str(КОРЕНЬ / "people.py"), "убери", имя, "--apply"]
            r = subprocess.run(аргументы, capture_output=True, text=True)
            return self._json({"ок": r.returncode == 0, "вывод": r.stdout + r.stderr})

        self.send_response(404)
        self.end_headers()


def main():
    сервер = HTTPServer(("127.0.0.1", ПОРТ), Обработчик)
    print(f"морда: http://127.0.0.1:{ПОРТ}/  (токен подставляется в страницу автоматически)")
    if not qrencode_доступен():
        print("подсказка: `brew install qrencode` — тогда появятся QR-коды ссылок")
    try:
        сервер.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
