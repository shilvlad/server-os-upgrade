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
from display import clean, render
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


def select_hosts(models):
    """Only select targets with a successfully displayed, complete plan."""
    names = sorted(models)
    while True:
        print("\nВыберите серверы: ALL — все; номера через запятую — отдельные; D — все пакеты; 0 — отмена.")
        choice = input("Выбор: ").strip().lower()
        if choice in ("0", "", "q"):
            return []
        if choice == "d":
            print(render(models, "plan", details=True), flush=True)
            continue
        if choice == "all":
            return names
        try:
            indices = {int(value) for value in re.split(r"[,\s]+", choice)}
            if not indices or min(indices) < 1 or max(indices) > len(names):
                raise ValueError()
        except ValueError:
            print("Введите ALL, D, 0 или номера серверов из показанного списка.")
            continue
        return [name for number, name in enumerate(names, 1) if number in indices]


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
    parser.add_argument("--details", action="store_true", help="Показать полный список изменений пакетов")
    parser.add_argument("--verbose", action="store_true", help="Показать технический вывод Ansible")
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
    real_update = args.action == "update" and not args.check
    if real_update and not args.yes and not sys.stdin.isatty():
        parser.error("Для неинтерактивного update требуется --yes")
    selected_limit = args.limit if args.action == "check-ssh" else args.limit + ",localhost"
    common = [ansible, "-i", str(inventory)]
    if args.user:
        common += ["-u", args.user]
    if args.private_key:
        common += ["--private-key", str(args.private_key.expanduser().resolve())]
    if args.ask_pass:
        common.append("--ask-pass")
    if args.ask_become_pass and args.action != "check-ssh":
        common.append("--ask-become-pass")
    if args.vars:
        common += ["-e", "@" + str(args.vars.resolve())]
    if args.check:
        common.append("--check")
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_dir = args.reports.resolve() / (stamp + "-" + uuid.uuid4().hex[:8])
    variables = {"fleet_report_dir": str(report_dir), "fleet_confirm_update": args.action == "update",
                 "fleet_upgrade_mode": "dist" if args.full_upgrade else "safe",
                 "fleet_allow_astra_package_updates": args.astra_apt, "fleet_reboot": args.reboot,
                 "fleet_refresh_cache": args.refresh_cache or real_update,
                 "fleet_preview_apply": real_update}
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
    environment = dict(os.environ, ANSIBLE_CONFIG=str(ROOT / "ansible.cfg"),
                       ANSIBLE_NOCOLOR="1", ANSIBLE_STDOUT_CALLBACK="default" if args.verbose else "fleet_console")

    def command_for(action, limit, extra):
        return common + [str(ROOT / "playbooks" / (action + ".yml")), "--limit", limit, "-e", json.dumps(extra)]

    # Resolve the initial scope without connecting to any remote host.
    first_action = "plan" if real_update else args.action
    listing = subprocess.run(command_for(first_action, selected_limit, variables) + ["--list-hosts"], cwd=ROOT, env=environment,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    if listing.returncode:
        print(listing.stderr, file=sys.stderr)
        return listing.returncode
    expected = set(re.findall(r"^      (.+)$", listing.stdout, re.MULTILINE))
    if args.action != "check-ssh":
        expected.discard("localhost")
    expected = sorted(expected)
    if not expected:
        parser.error("Выбранный inventory/--limit не содержит целевых серверов")
    print("Выбраны серверы: " + ", ".join(clean(host) for host in expected), flush=True)
    report_dir.mkdir(parents=True, mode=0o700)

    def execute(action, directory, names, limit, extra):
        directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        metadata = {"action": action, "limit": limit, "started_at": stamp, "check_mode": args.check,
                    "expected_hosts": names, "reboot_requested": args.reboot,
                    "status": "started", "upgrade_mode": variables["fleet_upgrade_mode"]}
        write_private(directory / "run.json", metadata)
        env = dict(environment, FLEET_REPORT_DIR=str(directory), FLEET_ACTION=action)
        options = dict(variables, fleet_report_dir=str(directory), **extra)
        result = subprocess.run(command_for(action, limit, options), cwd=ROOT, env=env, check=False)
        summary = build_ssh_report(directory) if action == "check-ssh" else build_reports(directory)
        code = result.returncode or (0 if summary["complete"] else 2)
        metadata.update(exit_code=code, status="success" if code == 0 else "failed")
        write_private(directory / "run.json", metadata)
        if action != "check-ssh":
            display_action = "plan" if args.check and action == "update" else action
            print(render(summary["models"], display_action, args.details), flush=True)
        return code, summary

    if real_update:
        print("Сначала рассчитывается план. Пока меняются только APT-индексы, пакеты не устанавливаются.", flush=True)
        preview_dir = report_dir / "preview"
        code, preview = execute("plan", preview_dir, expected, selected_limit, {})
        print("Краткий план: {}".format(preview_dir / "summary.md"), flush=True)
        print("Полный список пакетов: {}".format(preview_dir / "packages-plan.txt"), flush=True)
        if code or not all(model["ready"] and model["fingerprint"] for model in preview["models"].values()):
            print("Установка не запускалась: план не завершён. Исправьте ошибки или сузьте --limit.", file=sys.stderr)
            return code or 2
        selected = expected if args.yes else select_hosts(preview["models"])
        if selected:
            chosen = {host: preview["models"][host] for host in selected}
            print("\nК установке выбраны: " + ", ".join(clean(host) for host in selected))
            print("Порядок: по одному серверу; перезагрузка: {}.".format("ДА" if args.reboot else "НЕТ"))
            if args.yes:
                print("Автоматическое подтверждение: задан --yes.")
            elif input("Для установки показанных обновлений введи UPDATE: ").strip() != "UPDATE":
                selected = []
        if not selected:
            metadata = json.loads((preview_dir / "run.json").read_text())
            metadata.update(status="cancelled", installation_started=False)
            write_private(preview_dir / "run.json", metadata)
            print("Обновление отменено. Пакеты не устанавливались. План: {}".format(preview_dir / "summary.md"))
            return 0
        target = report_dir / "approved-plan.txt"
        target.write_text(render(chosen, "plan", details=True))
        target.chmod(0o600)
        approvals = {host: chosen[host]["fingerprint"] for host in selected}
        write_private(report_dir / "approved-plans.json", approvals)
        # A file avoids comma/colon joining; validate the resolved scope as well,
        # because Ansible may interpret individual inventory names as patterns.
        subset = report_dir / "selected-hosts.txt"
        subset.write_text("\n".join(selected + ["localhost"]) + "\n")
        subset.chmod(0o600)
        scope = subprocess.run(command_for("update", "@" + str(subset), variables) + ["--list-hosts"],
                               cwd=ROOT, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, check=False)
        resolved = set(re.findall(r"^      (.+)$", scope.stdout, re.MULTILINE)) - {"localhost"}
        if scope.returncode or resolved != set(selected):
            print("Установка не запускалась: фактический список Ansible не совпадает с выбранными серверами.", file=sys.stderr)
            return scope.returncode or 2
        code, summary = execute("update", report_dir, selected, "@" + str(subset),
                                {"fleet_preview_apply": False, "fleet_approved_plans": approvals,
                                 "fleet_require_approved_plan": True})
    else:
        code, summary = execute(args.action, report_dir, expected, selected_limit, {})

    if args.action == "check-ssh":
        print("SSH: доступно {}, ошибки {}.".format(summary["reachable"], summary["failed"]))
        for host, item in summary["hosts"].items():
            print("{}: {} — {}".format(host, "OK" if item["status"] == "ok" else "ОШИБКА", item["reason"]))
        print("Подробности: {}".format(report_dir / "ssh-check.json"))
    elif args.action == "inventory":
        print("Для проверки уязвимостей: {}".format(report_dir / "review.json"))
    if code:
        print("Есть ошибки или незавершённые проверки. Смотрите краткий отчёт.", file=sys.stderr)
    print("Краткий отчёт: {}".format(report_dir / "summary.md"))
    if args.action in ("plan", "update"):
        print("Все изменения пакетов: {}".format(report_dir / "packages-plan.txt"))
    return code


if __name__ == "__main__":
    sys.exit(main())
