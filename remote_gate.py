#!/usr/bin/env python3
"""ПРИВРАТНИК. Живёт на сервере, запускается как forced command (`command=` в
authorized_keys) для отдельной, урезанной пары ключей управляющей коробки —
см. gate_deploy.py. Проброс портов и agent forwarding на той записи запрещены,
так что единственный канал наружу — то, что этот файл сам решит выполнить.

НЕ доверяет $SSH_ORIGINAL_COMMAND: разбирает вручную, всё незнакомое — отказ.
Знает ровно четыре команды: dump, list, add, remove. Ничего похожего на shell,
никакой генерации команд по шаблону — только явные, руками прописанные ветки.

Коробка висит в сети круглосуточно. Если её вскроют, взлом не должен отдавать
ни шелла, ни доступа к соседним серверам — поэтому здесь нет ничего, кроме
того, что нужно ровно этим четырём операциям.
"""
import os
import re
import shlex
import sys

# remote_dump.py и client_admin.py лежат рядом — деплоит gate_deploy.py.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import client_admin  # noqa: E402
import remote_dump  # noqa: E402

ИМЯ_RE = re.compile(r"^[a-zA-Z0-9_-]{1,32}$")
ЧИСЛО_RE = re.compile(r"^\d{1,4}$")


def отказ(причина):
    print(f"отказ: {причина}", file=sys.stderr)
    return 1


def команда_dump():
    remote_dump.main()
    return 0


def команда_list():
    """Урезанный dump — только email и expiry, без uuid/ключей. Смотреть можно,
    получить чужой ключ через 'list' нельзя."""
    import json
    итог = []
    for inbound in remote_dump.дамп_xui().get("inbounds", []):
        for клиент in inbound.get("клиенты_из_settings", []):
            итог.append({
                "inbound": inbound.get("remark") or inbound.get("id"),
                "email": клиент.get("email"),
                "истекает": клиент.get("expiryTime", 0),
                "включён": клиент.get("enable", True),
            })
    print(json.dumps(итог, ensure_ascii=False))
    return 0


def команда_add_remove(действие, остальное):
    if not остальное or not ИМЯ_RE.match(остальное[0]):
        return отказ("нужно допустимое имя (латиница/цифры/-/_, до 32 символов)")
    имя = остальное[0]
    хвост = остальное[1:]

    # Белый список хвостовых флагов — никакого passthrough произвольных строк.
    дни = "0"
    apply_ = False
    протоколы = ""
    i = 0
    while i < len(хвост):
        токен = хвост[i]
        if токен == "--apply":
            apply_ = True
            i += 1
        elif токен == "--days" and действие == "add" and i + 1 < len(хвост) and ЧИСЛО_RE.match(хвост[i + 1]):
            дни = хвост[i + 1]
            i += 2
        elif токен.startswith("--protocols=") and действие == "add":
            протоколы = токен.split("=", 1)[1]
            if not re.match(r"^[a-zA-Z0-9_,-]*$", протоколы):
                return отказ("недопустимый список протоколов")
            i += 1
        else:
            return отказ(f"неизвестный флаг '{токен}'")

    sys.argv = ["client_admin.py", действие, имя]
    if действие == "add":
        sys.argv += ["--days", дни]
        if протоколы:
            sys.argv += ["--protocols", протоколы]
    if apply_:
        sys.argv.append("--apply")

    return client_admin.main() or 0


def main():
    сырая = os.environ.get("SSH_ORIGINAL_COMMAND", "")
    try:
        части = shlex.split(сырая)
    except ValueError:
        return отказ("не разобрать команду (кавычки?)")

    if not части:
        return отказ("пустая команда")

    команда, *остальное = части

    if команда == "dump" and not остальное:
        return команда_dump()
    if команда == "list" and not остальное:
        return команда_list()
    if команда in ("add", "remove"):
        return команда_add_remove(команда, остальное)

    return отказ(f"неизвестная команда '{команда}'")


if __name__ == "__main__":
    sys.exit(main())
