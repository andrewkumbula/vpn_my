#!/usr/bin/env python3
"""ТОЛЬКО ЧТЕНИЕ. Обходит серверы из servers.json по SSH, на каждом прогоняет
remote_dump.py (пайпом через stdin — на сервере ничего не остаётся) и складывает
результат в state/registry.json.

Источник истины для ссылок и клиентской конфигурации — этот файл, не пароли/UUID,
вручную записанные где-то ещё: они разойдутся с сервером, а registry.json — нет.
"""
import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

КОРЕНЬ = Path(__file__).resolve().parent
REMOTE_DUMP = КОРЕНЬ / "remote_dump.py"
РЕЕСТР = КОРЕНЬ / "state" / "registry.json"


def загрузить_серверы():
    with open(КОРЕНЬ / "servers.json", encoding="utf-8") as f:
        данные = json.load(f)
    return данные["servers"]


def опросить(сервер, таймаут=15):
    ssh = сервер["ssh"]
    ключ = Path(ssh["ключ"]).expanduser()
    команда = [
        "ssh",
        "-i", str(ключ),
        "-p", str(ssh.get("порт", 22)),
        "-o", f"ConnectTimeout={таймаут}",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        f"{ssh['пользователь']}@{сервер['host']}",
        "python3", "-",
    ]
    try:
        r = subprocess.run(
            команда,
            stdin=open(REMOTE_DUMP, "rb"),
            capture_output=True,
            timeout=таймаут + 10,
        )
    except subprocess.TimeoutExpired:
        return {"жив": False, "ошибка": "таймаут SSH"}

    if r.returncode != 0:
        return {
            "жив": False,
            "ошибка": r.stderr.decode("utf-8", "replace").strip() or f"код {r.returncode}",
        }
    try:
        дамп = json.loads(r.stdout.decode("utf-8"))
    except json.JSONDecodeError as e:
        return {"жив": False, "ошибка": f"битый JSON от сервера: {e}"}

    return {"жив": True, **дамп}


def main():
    парсер = argparse.ArgumentParser(description="Собрать реестр состояния серверов")
    парсер.add_argument("--сервер", help="опросить только один сервер по имени")
    аргс = парсер.parse_args()

    серверы = загрузить_серверы()
    if аргс.сервер:
        серверы = [s for s in серверы if s["имя"] == аргс.сервер]
        if not серверы:
            print(f"нет сервера с именем {аргс.сервер}", file=sys.stderr)
            return 1

    реестр = {
        "собрано": datetime.now(timezone.utc).isoformat(),
        "серверы": {},
    }
    код_возврата = 0
    for сервер in серверы:
        print(f"→ {сервер['имя']} ({сервер['host']})...", file=sys.stderr)
        итог = опросить(сервер)
        итог["метаданные"] = {
            k: v for k, v in сервер.items() if k not in ("ssh",)
        }
        реестр["серверы"][сервер["имя"]] = итог
        if not итог["жив"]:
            код_возврата = 1
            print(f"  ✗ {итог.get('ошибка')}", file=sys.stderr)
        else:
            n = len(итог.get("панель_3xui", {}).get("inbounds", []))
            print(f"  ✓ живой, {n} inbound(ов)", file=sys.stderr)

    РЕЕСТР.parent.mkdir(exist_ok=True)
    РЕЕСТР.write_text(json.dumps(реестр, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"записано → {РЕЕСТР}", file=sys.stderr)
    return код_возврата


if __name__ == "__main__":
    sys.exit(main())
