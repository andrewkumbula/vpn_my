#!/usr/bin/env python3
"""Запускается на маке. Заводит/убирает человека НА ВСЕХ серверах разом — гоняет
client_admin.py по SSH (пайпом через stdin, на сервере ничего не остаётся). По
умолчанию dry-run, реально пишет только с --apply.
"""
import argparse
import subprocess
import sys
from pathlib import Path

КОРЕНЬ = Path(__file__).resolve().parent
CLIENT_ADMIN = КОРЕНЬ / "client_admin.py"


def загрузить_серверы():
    import json
    with open(КОРЕНЬ / "servers.json", encoding="utf-8") as f:
        return json.load(f)["servers"]


def на_сервере(сервер, аргументы, таймаут=20):
    ssh = сервер["ssh"]
    ключ = Path(ssh["ключ"]).expanduser()
    команда = [
        "ssh", "-i", str(ключ), "-p", str(ssh.get("порт", 22)),
        "-o", f"ConnectTimeout={таймаут}", "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        f"{ssh['пользователь']}@{сервер['host']}",
        "python3", "-", *аргументы,
    ]
    try:
        r = subprocess.run(
            команда, stdin=open(CLIENT_ADMIN, "rb"),
            capture_output=True, text=True, timeout=таймаут + 15,
        )
    except subprocess.TimeoutExpired:
        return False, "таймаут SSH"
    if r.returncode != 0:
        return False, r.stderr.strip() or f"код {r.returncode}"
    return True, r.stdout


def main():
    парсер = argparse.ArgumentParser(description="Люди — на всех серверах разом")
    подкоманды = парсер.add_subparsers(dest="действие", required=True)

    p_add = подкоманды.add_parser("добавь")
    p_add.add_argument("имя")
    p_add.add_argument("--days", type=int, default=0)
    p_add.add_argument("--apply", action="store_true")

    p_remove = подкоманды.add_parser("убери")
    p_remove.add_argument("имя")
    p_remove.add_argument("--apply", action="store_true")

    подкоманды.add_parser("список")

    аргс = парсер.parse_args()
    серверы = загрузить_серверы()

    if аргс.действие == "список":
        for с in серверы:
            print(f"{с['имя']:<12} {с['host']:<16} {с['флаг']} {', '.join(с['роли'])}")
        return 0

    if аргс.действие == "добавь":
        remote_args = ["add", аргс.имя, "--days", str(аргс.days)]
        if аргс.apply:
            remote_args.append("--apply")
    else:
        remote_args = ["remove", аргс.имя]
        if аргс.apply:
            remote_args.append("--apply")

    код_возврата = 0
    for сервер in серверы:
        print(f"\n== {сервер['имя']} ==")
        ок, вывод = на_сервере(сервер, remote_args)
        if not ок:
            код_возврата = 1
            print(f"  ✗ {вывод}", file=sys.stderr)
        else:
            print(вывод.rstrip())

    if not аргс.apply and аргс.действие in ("добавь", "убери"):
        print("\n(это был dry-run на всех серверах — добавь --apply, чтобы применить)")

    return код_возврата


if __name__ == "__main__":
    sys.exit(main())
