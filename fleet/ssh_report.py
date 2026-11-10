"""Per-target SSH results, including unreachable and unattempted targets."""
import json
from pathlib import Path

from report import md, save_json


def failure_reason(message):
    text = message.lower()
    for markers, code, label in [
        (("host key verification failed", "host identification has changed", "no ed25519 host key is known",
          "no rsa host key is known", "no ecdsa host key is known"), "host_key", "Ключ сервера отсутствует в known_hosts или не совпадает"),
        (("could not resolve hostname", "name or service not known", "nodename nor servname", "temporary failure in name resolution"),
         "dns", "Не удалось разрешить DNS-имя"),
        (("permission denied", "authentication failed", "no supported authentication methods", "no such identity"),
         "authentication", "SSH-ключ не принят или недоступен"),
        (("connection refused",), "refused", "SSH-порт отклоняет соединение"),
        (("timed out", "operation timeout"), "timeout", "Истёк тайм-аут подключения"),
        (("no route to host", "network is unreachable"), "network", "Нет сетевого маршрута к серверу"),
    ]:
        if any(marker in text for marker in markers):
            return code, label
    return "ssh_error", "Ошибка SSH или выполнения проверочной команды"


def build_ssh_report(directory):
    directory = Path(directory)
    metadata = json.loads((directory / "run.json").read_text())
    result_file = directory / "ssh-results.json"
    results = json.loads(result_file.read_text()) if result_file.exists() else {}
    status_file = directory / "run-status.json"
    stats = json.loads(status_file.read_text()) if status_file.exists() else {}
    hosts = {}
    for host in metadata["expected_hosts"]:
        result = dict(results.get(host, {"status": "not_checked", "rc": None, "message": "Нет результата Ansible"}))
        if result["status"] == "ok":
            result.update(reason_code="ok", reason="Вход по SSH-ключу и выполнение команды успешны")
        elif result["status"] == "not_checked":
            result.update(reason_code="not_checked", reason="Проверка не выполнена")
        else:
            code, reason = failure_reason(result["message"])
            result.update(reason_code=code, reason=reason)
        hosts[host] = result
    reachable = sum(result["status"] == "ok" for result in hosts.values())
    failed = len(hosts) - reachable
    complete = bool(hosts and stats and not failed and not any(
        result.get("failures", 0) or result.get("unreachable", 0) for result in stats.values()))
    save_json(directory / "ssh-check.json", {"hosts": hosts, "reachable": reachable,
              "failed": failed, "all_reachable": complete})
    rows = ["# Проверка SSH-доступа", "", "| Сервер | Результат | Причина |", "|---|---|---|"]
    for host, result in hosts.items():
        rows.append("| {} | {} | {} |".format(md(host), "OK" if result["status"] == "ok" else "ОШИБКА", md(result["reason"])))
    rows += ["", "Доступно: {}; ошибки/нет результата: {}.".format(reachable, failed),
             "", "Проверены SSH-вход по ключу и команда /bin/true. Подробности: ssh-check.json."]
    target = directory / "summary.md"
    target.write_text("\n".join(rows) + "\n")
    target.chmod(0o600)
    return {"hosts": hosts, "reachable": reachable, "failed": failed, "complete": complete}
