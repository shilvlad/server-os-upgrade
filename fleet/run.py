#!/usr/bin/env python3
"""Interactive local entry point; passwords stay in Ansible's SSH/sudo prompts."""
import argparse
import datetime
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import uuid

from report import build_reports
from ssh_report import build_ssh_report

ROOT = Path(__file__).resolve().parent


def normalize_target(value):
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    # Do not reinterpret malformed numeric IPs, URLs or host:port as DNS names.
    if ":" in value or re.fullmatch(r"[0-9.]+", value):
        raise ValueError("некорректный IP или DNS-имя {!r}".format(value))
    try:
        hostname = value.encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise ValueError("некорректное DNS-имя {!r}".format(value)) from error
    labels = hostname.rstrip(".").split(".")
    if (len(hostname.rstrip(".")) > 253 or
            not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)):
        raise ValueError("некорректный IP или DNS-имя {!r}".format(value))
    if hostname.rstrip(".") == "localhost":
        raise ValueError("localhost зарезервирован для машины запуска; для SSH к ней укажите IP")
    return hostname


def load_hosts(path):
    addresses = []
    seen = set()
    for number, line in enumerate(Path(path).read_text().splitlines(), 1):
        value = line.split("#", 1)[0].strip()
        if not value:
            continue
        try:
            address = normalize_target(value)
        except ValueError as error:
            raise ValueError("{}:{}: {}".format(path, number, error)) from error
        canonical = address.rstrip(".").lower()
        if canonical not in seen:
            addresses.append(address)
            seen.add(canonical)
    if not addresses:
        raise ValueError("Список серверов пуст")
    return addresses


def write_private(path, data):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Truncate only after opening with restrictive permissions; no world-readable window.
    descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(json.dumps(data, ensure_ascii=False, indent=2) + "\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Инвентаризация и обновление Astra Linux / Debian / Ubuntu")
    parser.add_argument("action", nargs="?", choices=("inventory", "plan", "update", "check-ssh"))
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--hosts", type=Path, help="Файл IP/DNS-имён, по одному серверу на строку; по умолчанию servers.txt")
    source.add_argument("-i", "--inventory", type=Path, help="Готовый Ansible inventory")
    parser.add_argument("--user", help="SSH-пользователь; по умолчанию — текущий пользователь SSH")
    parser.add_argument("--limit", default="all", help="Ansible-паттерн отбора серверов")
    parser.add_argument("--private-key", type=Path)
    parser.add_argument("--ssh-timeout", type=int, default=10, help="Тайм-аут SSH-проверки в секундах (по умолчанию 10)")
    parser.add_argument("--ask-pass", action="store_true", help="Запросить SSH-пароль")
    parser.add_argument("-K", "--ask-become-pass", action="store_true", help="Запросить пароль sudo")
    parser.add_argument("--vars", type=Path, help="Локальный файл переменных Ansible")
    parser.add_argument("--full-upgrade", action="store_true", help="dist-upgrade вместо upgrade; удаление запрещено")
    parser.add_argument("--refresh-cache", action="store_true", help="Обновить APT-индексы при просмотре плана")
    parser.add_argument("--astra-apt", action="store_true", help="Разрешить обновление пакетов Astra через APT")
    parser.add_argument("--reboot", action="store_true", help="Перезагрузить каждый успешно обновлённый сервер")
    parser.add_argument("--yes", action="store_true", help="Подтвердить update без интерактивного вопроса")
    parser.add_argument("--check", action="store_true", help="Check mode: инвентаризация и план без установки")
    parser.add_argument("--reports", type=Path, default=ROOT / "reports", help="Родительский каталог отчётов")
    args = parser.parse_args(argv)
    os.umask(0o077)
    if not args.action:
        if not sys.stdin.isatty():
            parser.error("Укажите действие inventory, plan, update или check-ssh")
        print("1 — Инвентаризация ПО\n2 — Просмотр обновлений\n3 — Обновление системы\n4 — Проверка подключения по SSH-ключу\n0 — Выход")
        choice = input("Выбор: ").strip()
        if choice == "0":
            return 0
        args.action = {"1": "inventory", "2": "plan", "3": "update", "4": "check-ssh"}.get(choice)
        if args.action is None:
            parser.error("Неизвестный пункт меню")
    if args.reboot and (args.action != "update" or args.check):
        parser.error("--reboot применим только к реальному update")
    if args.refresh_cache and (args.action not in ("plan", "update") or args.check):
        parser.error("--refresh-cache применим к plan/update; несовместим с --check")
    if args.action == "check-ssh" and args.ask_pass:
        parser.error("check-ssh проверяет вход по ключу; уберите --ask-pass")
    if args.ssh_timeout < 1:
        parser.error("--ssh-timeout должен быть положительным числом")
    ansible = shutil.which("ansible-playbook")
    if not ansible:
        parser.error("Не найден ansible-playbook. Активируйте .venv и установите requirements.txt")
    hosts_file = args.hosts
    if not hosts_file and not args.inventory and (ROOT / "servers.txt").is_file():
        hosts_file = ROOT / "servers.txt"
    if hosts_file:
        try:
            addresses = load_hosts(hosts_file)
        except (OSError, ValueError) as error:
            parser.error(str(error))
        inventory = ROOT / "inventory/generated.json"
        data = {"all": {"children": {"linux": {"hosts": {
            address: {"ansible_host": address} for address in addresses}}}}}
        write_private(inventory, data)
    else:
        inventory = (args.inventory or ROOT / "inventory/hosts.yml").resolve()
        if not inventory.exists():
            parser.error("Передайте --hosts servers.txt или -i inventory/hosts.yml")
    playbook = ROOT / "playbooks" / (args.action + ".yml")
    selected_limit = args.limit if args.action == "check-ssh" else args.limit + ",localhost"
    command = [ansible, "-i", str(inventory), str(playbook), "--limit", selected_limit]
    if args.user:
        command += ["-u", args.user]
    if args.private_key:
        command += ["--private-key", str(args.private_key.expanduser().resolve())]
    if args.ask_pass:
        command.append("--ask-pass")
    if args.ask_become_pass and args.action != "check-ssh":
        command.append("--ask-become-pass")
    if args.vars:
        command += ["-e", "@" + str(args.vars.resolve())]
    if args.check:
        command.append("--check")
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_dir = args.reports.resolve() / (stamp + "-" + uuid.uuid4().hex[:8])
    variables = {"fleet_report_dir": str(report_dir), "fleet_confirm_update": args.action == "update",
                 "fleet_upgrade_mode": "dist" if args.full_upgrade else "safe",
                 "fleet_allow_astra_package_updates": args.astra_apt, "fleet_reboot": args.reboot,
                 "fleet_refresh_cache": args.refresh_cache}
    if args.action == "check-ssh":
        # Force key authentication and a fresh connection, independent of cached
        # ControlMaster sessions. ProxyJump/ports still work through SSH config
        # and ansible_ssh_common_args. OpenSSH uses the first value of each option.
        probe_args = ("-o BatchMode=yes -o PreferredAuthentications=publickey "
                      "-o PubkeyAuthentication=yes -o PasswordAuthentication=no "
                      "-o KbdInteractiveAuthentication=no -o StrictHostKeyChecking=yes "
                      "-o ControlMaster=no -o ControlPath=none -o ControlPersist=no "
                      "-o ConnectionAttempts=1 -o ConnectTimeout={}".format(args.ssh_timeout))
        if args.private_key:
            probe_args += " -o IdentitiesOnly=yes"
        variables.update(ansible_connection="ssh", ansible_become=False, ansible_ssh_args=probe_args,
                         ansible_ssh_password_mechanism="disable", ansible_ssh_retries=0,
                         ansible_ssh_timeout=args.ssh_timeout)
    command += ["-e", json.dumps(variables)]
    environment = dict(os.environ, ANSIBLE_CONFIG=str(ROOT / "ansible.cfg"),
                       ANSIBLE_NOCOLOR="1", FLEET_REPORT_DIR=str(report_dir), FLEET_ACTION=args.action)
    # List exact targets before approval. This does not connect to any remote host.
    listing = subprocess.run(command + ["--list-hosts"], cwd=ROOT, env=environment,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    print(listing.stdout, end="")
    if listing.returncode:
        print(listing.stderr, file=sys.stderr)
        return listing.returncode
    expected = set(re.findall(r"^      (.+)$", listing.stdout, re.MULTILINE))
    if args.action != "check-ssh":
        expected.discard("localhost")
    expected = sorted(expected)
    if not expected:
        parser.error("Выбранный inventory/--limit не содержит целевых серверов")
    if args.action == "update" and not args.check:
        print("Обновление выполняется по одному серверу. APT может перезапустить сервисы.")
        print("Режим: {}; перезагрузка: {}.".format(variables["fleet_upgrade_mode"], args.reboot))
        if not args.yes:
            if not sys.stdin.isatty():
                parser.error("Для неинтерактивного update требуется --yes")
            if input("Для установки обновлений введи UPDATE: ").strip() != "UPDATE":
                print("Обновление отменено.")
                return 0
    report_dir.mkdir(parents=True, mode=0o700)
    write_private(report_dir / "run.json", {"action": args.action, "limit": args.limit,
                  "started_at": stamp, "check_mode": args.check, "expected_hosts": expected, "status": "started"})
    print("Отчёты: {}".format(report_dir), flush=True)
    result = subprocess.run(command, cwd=ROOT, env=environment, check=False)
    summary = build_ssh_report(report_dir) if args.action == "check-ssh" else build_reports(report_dir)
    code = result.returncode
    if not summary["hosts"] and args.action != "check-ssh":
        print("Нет инвентаризаций целевых серверов; запуск не считается успешным.", file=sys.stderr)
        code = code or 2
    if not summary["complete"]:
        print("Есть недоступные/необработанные серверы или ошибки Ansible. См. summary.md.", file=sys.stderr)
        code = code or 2
    write_private(report_dir / "run.json", {"action": args.action, "limit": args.limit,
                  "started_at": stamp, "check_mode": args.check, "exit_code": code,
                  "expected_hosts": expected,
                  "status": "success" if code == 0 else "failed"})
    print("Готово: {} серверов; отчёт {}".format(len(summary["hosts"]), report_dir / "summary.md"))
    if args.action == "check-ssh":
        print("SSH: доступно {}, ошибки {}.".format(summary["reachable"], summary["failed"]))
        for host, item in summary["hosts"].items():
            print("{}: {} — {}".format(host, "OK" if item["status"] == "ok" else "ОШИБКА", item["reason"]))
        print("Подробности: {}".format(report_dir / "ssh-check.json"))
    else:
        print("Для проверки уязвимостей: {}".format(report_dir / "review.json"))
    return code


if __name__ == "__main__":
    sys.exit(main())
