"""Human-readable local views; raw inventories remain available for tools."""
import datetime
import json
from pathlib import Path
import re
import unicodedata


def clean(value):
    value = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", str(value))
    return " ".join("".join(char for char in value if unicodedata.category(char) not in ("Cc", "Cf")
                            or char in "\n\t\r").split())


def read_json(path, default=None):
    return json.loads(path.read_text()) if path.exists() else default


def friendly_error(message):
    labels = [
        ("APT plan changed after approval", "План APT изменился после подтверждения. Установка не начата: заново просмотрите план."),
        ("APT index refresh failed", "Не удалось полностью получить индексы APT. Проверьте доступность репозиториев."),
        ("An application HTTP check failed", "HTTP-проверка приложения не прошла. Проверьте адрес приложения и nginx."),
        ("A critical service is not active", "Одна из заданных критичных служб не работает."),
        ("Insufficient free space", "Не хватает свободного места: " + str(message)),
        ("dpkg --audit", "DPKG сообщает об ошибке или незавершённой настройке пакетов. Подробности в техническом результате."),
        ("Permission denied", "SSH-доступ отклонён. Проверьте пользователя и ключ."),
        ("Could not resolve hostname", "Не удалось разрешить DNS-имя сервера."),
        ("For Astra package updates", "Обновление Astra через APT требует явного --astra-apt."),
        ("target Python 3.9+", "Для автоматической перезагрузки нужен Python 3.9+ на сервере."),
        ("APT update failed", "Установка APT завершилась ошибкой; возможны частичные изменения. Смотрите hosts/*-update.json."),
        ("dpkg returned no installed packages", "DPKG не вернул установленных пакетов; состав ПО не собран."),
    ]
    return clean(next((label for marker, label in labels if marker in str(message)), message))


def parse_simulation(text):
    packages = []
    for match in re.finditer(r"^Inst\s+(\S+)(?:\s+\[([^\]]+)\])?\s+\((\S+)", text, re.MULTILINE):
        name, old, new = match.groups()
        packages.append({"name": name, "before": old or "", "after": new})
    match = re.search(r"(\d+) upgraded, (\d+) newly installed, (\d+) to remove and (\d+) not upgraded", text)
    counts = dict(zip(("upgrade", "install", "remove", "defer"), map(int, match.groups()))) if match else None
    deferred = []
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if "have been kept back:" in line or "have been deferred due to phasing:" in line:
            for following in lines[index + 1:]:
                if not following.startswith(" "):
                    break
                deferred.extend(following.split())
    kernels = sorted({re.sub(r"^linux-image-(?:unsigned-)?", "", p["name"].split(":")[0])
                      for p in packages if re.match(r"^linux-image-(?:unsigned-)?\d", p["name"])})
    valid = bool(counts is not None and counts["remove"] == 0 and
                 len(packages) == counts["upgrade"] + counts["install"] and
                 not re.search(r"^Remv\s", text, re.MULTILINE))
    return {"packages": packages, "counts": counts, "deferred": deferred, "kernels": kernels, "valid": valid}


def key_package(package):
    name = package["name"].split(":")[0]
    return bool(re.match(r"^(linux-image-(?:unsigned-)?\d|openssh-server$|nginx$|openssl$|libssl|"
                         r"docker(?:-ce|-ce-cli|\.io)$|containerd(?:\.io)?$|docker-compose-plugin$|"
                         r"systemd$|libc6$|postgresql-\d+$|mariadb-server|mysql-server|sudo$)", name))


def human_models(directory, inventories):
    directory = Path(directory)
    run = read_json(directory / "run.json", {})
    statuses = read_json(directory / "run-status.json", {})
    errors = read_json(directory / "run-errors.json", {})
    records = {}
    for filename in sorted((directory / "hosts").glob("*.json")):
        item = read_json(filename, {})
        kind = item.get("report_type")
        if kind in ("plan", "update", "health"):
            raw = item.get("result", {})
            try:
                payload = json.loads(raw.get("stdout", ""))
            except (ValueError, TypeError):
                payload = {}
            records.setdefault(item["host"], {})[kind] = {"rc": raw.get("rc", 1), "data": payload,
                "error": payload.get("error") or raw.get("stderr") or raw.get("msg") or ""}
    models = {}
    expected = set(run.get("expected_hosts", [])) | set(inventories) | set(records) | (set(statuses) - {"localhost"})
    for host in sorted(expected):
        item = inventories.get(host, {})
        inventory = item.get("data", {})
        record = records.get(host, {})
        plan_result = record.get("plan", {})
        plan = plan_result.get("data", {})
        parsed = parse_simulation(plan.get("simulation", ""))
        outcome = statuses.get(host, {})
        error = next((entry["error"] for entry in record.values() if entry["rc"] != 0 and entry["error"]), "")
        if not error:
            error = errors.get(host, "")
        failed = bool(error or not outcome or outcome.get("failures") or outcome.get("unreachable"))
        action = run.get("action", "inventory")
        planning = action in ("plan", "update")
        if planning and (not plan_result or plan_result.get("rc") != 0 or not parsed["valid"]):
            failed = True
            error = error or "Полный план установки не получен или его состав не распознан."
        applied = record.get("update", {})
        health_result = record.get("health", {})
        applied_ok = bool(applied and applied.get("rc") == 0)
        after = health_result.get("data", {})
        after = after.get("details", after)
        complete_update = bool(applied_ok and health_result.get("rc") == 0 and item.get("phase") == "after" and not failed)
        if action == "update" and not run.get("check_mode") and not run.get("preview_only") and not complete_update:
            failed = True
            error = error or "Обновление или итоговые проверки не завершены; автоматический откат не выполнялся."
        warnings = []
        before_health = plan.get("health", {})
        if planning and plan.get("simulation"):
            if not plan.get("cache_refreshed"):
                warnings.append("План рассчитан по локальным APT-индексам; их актуальность не подтверждена.")
            if not before_health.get("critical_services"):
                warnings.append("Критичные службы не заданы: работоспособность приложения не подтверждается.")
            if not before_health.get("http_checks"):
                warnings.append("HTTP-проверки приложений не настроены.")
            failed_units = before_health.get("failed_units", {})
            if failed_units.get("items"):
                warnings.append("Уже есть службы с ошибкой: " + ", ".join(failed_units["items"]))
            if failed_units.get("status") != "ok":
                warnings.append("Проверить службы systemd не удалось.")
            if plan.get("held_packages"):
                warnings.append("Зафиксированы apt-mark hold: " + ", ".join(plan["held_packages"]))
            codename = plan.get("os", {}).get("version_codename", "")
            policy = plan.get("apt_policy", {})
            if plan.get("os", {}).get("id") == "ubuntu" and codename:
                if policy.get("rc") != 0:
                    warnings.append("Наличие security-репозитория Ubuntu не проверено.")
                elif not re.search(r"a=" + re.escape(codename) + r"-security(?:,|\s)", policy.get("stdout", "")):
                    warnings.append("В индексах APT отсутствует " + codename + "-security.")
        components = inventory.get("components", {})
        gaps = [name for name, value in components.items() if value.get("status") == "error"]
        if gaps:
            warnings.append("Ошибки сбора ПО: " + ", ".join(gaps))
        state = "ОШИБКА" if failed else "ОБНОВЛЕНО" if complete_update else "ПЛАН ГОТОВ" if planning else "СОБРАНО"
        models[host] = {"host": host, "state": state, "error": friendly_error(error), "warnings": warnings,
            "os": inventory.get("os", plan.get("os", {})).get("pretty_name", "нет данных"),
            "kernel": inventory.get("kernel", before_health.get("kernel", "нет данных")),
            "plan": parsed, "plan_data": plan, "ready": bool(planning and not failed and parsed["valid"]),
            "fingerprint": plan.get("fingerprint", ""), "reboot": bool(run.get("reboot_requested")),
            "inventory": inventory, "applied": applied, "health": after, "phase": item.get("phase", ""),
            "action": action, "check_mode": run.get("check_mode", False), "update_complete": complete_update,
            "started_at": run.get("started_at"), "mode": run.get("upgrade_mode", "safe")}
    return models


def render(models, action, details=False):
    titles = {"inventory": "СОСТАВ ПО", "plan": "ПЛАН ОБНОВЛЕНИЯ", "update": "РЕЗУЛЬТАТ ОБНОВЛЕНИЯ"}
    lines = [titles.get(action, action), ""]
    first = next(iter(models.values()), {})
    if first.get("started_at"):
        try:
            stamp = datetime.datetime.strptime(first["started_at"], "%Y%m%dT%H%M%SZ").strftime("%d.%m.%Y %H:%M:%S UTC")
        except ValueError:
            stamp = first["started_at"]
        lines += ["Время запуска: " + stamp, ""]
    if action == "plan":
        lines += ["Режим: " + ("полное обновление пакетов (dist-upgrade), без удаления." if first.get("mode") == "dist"
                               else "обычное обновление пакетов (upgrade), без удаления."), ""]
    for number, (host, model) in enumerate(sorted(models.items()), 1):
        lines.extend(["{}. {} — {}".format(number, host, model["state"]),
                      "   ОС: {}; работающее ядро: {}".format(model["os"], model["kernel"])])
        if model["error"]:
            lines.append("   ОШИБКА: " + model["error"])
            if action == "update" and model["phase"] == "before":
                lines.append("   Состав ПО — снимок ДО обновления; текущее состояние после ошибки не подтверждено.")
        if action in ("plan", "update"):
            plan = model["plan"]
            counts = plan["counts"]
            if counts:
                lines.append("   Пакеты: обновить {upgrade}; установить новых {install}; удалить {remove}; отложено {defer}.".format(**counts))
            if plan["kernels"]:
                lines.append("   Ядро в плане: " + ", ".join(plan["kernels"]))
            if action == "plan":
                lines.append("   Перезагрузка после установки: " + ("ДА (выбрана пользователем)." if model["reboot"] else "НЕТ (не выбрана)."))
                if plan["kernels"] and not model["reboot"]:
                    lines.append("   ВНИМАНИЕ: для загрузки установленного ядра потребуется перезагрузка.")
            if model["plan_data"].get("health", {}).get("reboot_required_marker"):
                lines.append("   ОС уже сообщает о необходимости перезагрузки.")
            if plan["deferred"]:
                lines.append("   Останутся без обновления: " + ", ".join(plan["deferred"]))
            free = model["plan_data"].get("free_mb", {})
            if free:
                lines.append("   Свободно до установки: " + "; ".join("{}: {} MiB".format(k, v) for k, v in free.items()))
            packages = plan["packages"] if details else [p for p in plan["packages"] if key_package(p)]
            if packages:
                lines.append("   " + ("Все изменения пакетов:" if details else "Основные изменения пакетов:"))
                for package in packages:
                    lines.append("     {}: {} → {}".format(package["name"], package["before"] or "новый пакет", package["after"]))
            if not details and len(packages) < len(plan["packages"]):
                lines.append("   Остальные пакеты ({}) — в полном списке изменений.".format(len(plan["packages"]) - len(packages)))
            if model["applied"].get("rc") == 0:
                changed = model["applied"].get("data", {}).get("changed_packages", [])
                lines.append("   APT завершён. Фактически установлены/изменены: {} пакетов.".format(len(changed)))
            if model["health"]:
                if model["health"].get("reboot_required_marker"):
                    lines.append("   После обновления ОС сообщает: требуется перезагрузка.")
                if plan["kernels"] and model["kernel"] not in plan["kernels"]:
                    lines.append("   ВНИМАНИЕ: ядро из плана сейчас не загружено. Проверьте необходимость перезагрузки/загрузчик.")
                checks = model["health"].get("http_checks", {})
                if checks:
                    lines.append("   HTTP после обновления: " + "; ".join("{}: HTTP {} ({})".format(
                        name, value.get("status") or "нет ответа", "OK" if value.get("ok") else "ОШИБКА") for name, value in checks.items()))
                if model["health"].get("critical_services"):
                    lines.append("   Службы после обновления: " + "; ".join("{}: {}".format(k, v["state"])
                                 for k, v in model["health"]["critical_services"].items()))
        else:
            inventory = model["inventory"]
            lines.append("   Установлено DEB-пакетов: {}.".format(len(inventory.get("dpkg", []))))
            for package in inventory.get("dpkg", []):
                if key_package(package):
                    lines.append("     {}: {}".format(package["name"], package["version"]))
            applications = sorted({(p.get("name", ""), p.get("version", ""))
                                   for p in inventory.get("components", {}).get("python", {}).get("items", [])
                                   if p.get("name", "").lower().replace("_", "-") in ("matrix-synapse", "fastapi", "django")})
            for name, version in applications:
                lines.append("   Python-приложение/библиотека {}: {}".format(name, version))
            for name, component in inventory.get("components", {}).items():
                labels = {"python": "Python-библиотеки", "npm_global": "Глобальные npm-пакеты", "snap": "Snap", "flatpak": "Flatpak",
                          "docker_images": "Образы Docker", "docker_containers": "Контейнеры Docker",
                          "podman_images": "Образы Podman", "podman_containers": "Контейнеры Podman"}
                states = {"ok": str(len(component.get("items", []))), "not_available": "сборщик недоступен", "error": "ошибка сбора"}
                lines.append("   {}: {}.".format(labels.get(name, name), states.get(component.get("status"), "неизвестно")))
        for warning in model["warnings"]:
            lines.append("   ВНИМАНИЕ: " + warning)
        lines.append("")
    if action == "plan":
        lines.append("Пакеты ещё не установлены. Установка может перезапускать службы.")
        lines.append("План APT не обновляет pip/venv, npm, Snap/Flatpak и образы контейнеров.")
    lines.append("Проверка уязвимостей не выполнялась; наличие обновлений не означает подтверждённую CVE.")
    if action == "inventory":
        lines.append("Пакеты внутри контейнеров и все установки других пользователей этим сбором не охвачены.")
    return "\n".join(" " * (len(line) - len(line.lstrip())) + clean(line) if line.strip() else ""
                     for line in lines) + "\n"


def save_human_reports(directory, models, action):
    directory = Path(directory)
    text = render(models, action)
    target = directory / "summary.md"
    # Plain text in a Markdown code block preserves terminal/table readability.
    target.write_text("# " + {"plan": "План обновления", "update": "Результат обновления", "inventory": "Состав ПО"}.get(action, action)
                      + "\n\n```text\n" + text.replace("```", "'''") + "```\n")
    target.chmod(0o600)
    if action in ("plan", "update"):
        target = directory / "packages-plan.txt"
        target.write_text(render(models, action, details=True))
        target.chmod(0o600)
    return text
