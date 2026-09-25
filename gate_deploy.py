#!/usr/bin/env python3
"""Выдаёт управляющей коробке урезанный доступ к серверу: копирует привратника
(remote_gate.py + client_admin.py + remote_dump.py) на сервер и заводит для новой
пары ключей отдельную запись в authorized_keys с command= на привратника, без
port forwarding/agent/pty — эти опции и есть граница: что бы коробка ни попросила,
выполнится только remote_gate.py, наружу не пробросится ни шелл, ни агент.

Обычно запускается один раз на новый сервер, руками, с полноценного root-ключа
(того, что уже есть в servers.json) — сама пара ключей коробки после этого
используется отдельно, полный ключ ей не отдаётся.

Упрощение, которое стоит знать: команда выполняется от root (у 3x-ui база —
root:600, только root её читает без танцев с ACL). Правильнее был бы отдельный
системный пользователь с точечным доступом к файлу БД, но это специфично для
конкретной установки панели — сознательно не автоматизируем здесь, чтобы не
выдумывать несуществующий контракт. Если понадобится — заводить руками.
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

КОРЕНЬ = Path(__file__).resolve().parent
GATE_DIR_НА_СЕРВЕРЕ = "/usr/local/libexec/vpnctl-gate"
ФАЙЛЫ = ["remote_gate.py", "client_admin.py", "remote_dump.py"]


def загрузить_сервер(имя):
    with open(КОРЕНЬ / "servers.json", encoding="utf-8") as f:
        серверы = json.load(f)["servers"]
    for с in серверы:
        if с["имя"] == имя:
            return с
    raise SystemExit(f"нет сервера с именем {имя}")


def ssh_команда(сервер, аргументы_после_хоста, таймаут=20):
    ssh = сервер["ssh"]
    ключ = Path(ssh["ключ"]).expanduser()
    return [
        "ssh", "-i", str(ключ), "-p", str(ssh.get("порт", 22)),
        "-o", f"ConnectTimeout={таймаут}", "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        f"{ssh['пользователь']}@{сервер['host']}", *аргументы_после_хоста,
    ]


def main():
    парсер = argparse.ArgumentParser(description=__doc__)
    парсер.add_argument("сервер", help="имя сервера из servers.json")
    парсер.add_argument("--gate-key", default=str(КОРЕНЬ / "state" / "gate_key"),
                         help="куда сгенерировать/откуда взять пару ключей коробки")
    парсер.add_argument("--apply", action="store_true")
    аргс = парсер.parse_args()

    сервер = загрузить_сервер(аргс.сервер)
    gate_key = Path(аргс.gate_key).expanduser()

    if not gate_key.exists():
        print(f"{'[apply]' if аргс.apply else '[dry-run]'} сгенерировал бы пару ключей коробки: {gate_key}")
        if аргс.apply:
            gate_key.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(
                ["ssh-keygen", "-t", "ed25519", "-f", str(gate_key), "-N", "", "-C", "vpnctl-gate"],
                check=True,
            )
    else:
        print(f"использую существующий ключ коробки: {gate_key}")

    print(f"{'[apply]' if аргс.apply else '[dry-run]'} создал бы {GATE_DIR_НА_СЕРВЕРЕ} и скопировал бы: {', '.join(ФАЙЛЫ)}")
    if аргс.apply:
        subprocess.run(ssh_команда(сервер, ["mkdir", "-p", GATE_DIR_НА_СЕРВЕРЕ]), check=True)
        for имя_файла in ФАЙЛЫ:
            with open(КОРЕНЬ / имя_файла, "rb") as f:
                subprocess.run(
                    ssh_команда(сервер, ["tee", f"{GATE_DIR_НА_СЕРВЕРЕ}/{имя_файла}"]),
                    input=f.read(), stdout=subprocess.DEVNULL, check=True,
                )
        subprocess.run(
            ssh_команда(сервер, ["chmod", "700", GATE_DIR_НА_СЕРВЕРЕ]), check=True,
        )

    публичный_ключ = (gate_key.with_suffix(".pub")).read_text().strip() if gate_key.with_suffix(".pub").exists() else "<будет после генерации>"
    строка_authorized_keys = (
        f'command="/usr/bin/python3 {GATE_DIR_НА_СЕРВЕРЕ}/remote_gate.py",'
        f"no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty,no-user-rc "
        f"{публичный_ключ}"
    )

    print(f"{'[apply]' if аргс.apply else '[dry-run]'} дописал бы в authorized_keys root на сервере:")
    print(f"  {строка_authorized_keys}")

    if аргс.apply:
        # Дописываем отдельной строкой — не трогаем существующие записи
        # (в т.ч. полный ключ, которым мы сюда же и подключаемся).
        subprocess.run(
            ssh_команда(сервер, ["bash", "-c",
                                  f"echo '{строка_authorized_keys}' >> ~/.ssh/authorized_keys"]),
            check=True,
        )
        print("готово. Проверка с коробки:")
        print(f"  ssh -i {gate_key} {сервер['ssh']['пользователь']}@{сервер['host']} dump")
    else:
        print("\n(dry-run — добавь --apply, чтобы реально применить)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
