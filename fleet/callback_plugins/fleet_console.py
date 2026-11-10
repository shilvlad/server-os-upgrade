"""Concise progress in the terminal; credentials still use Ansible's prompts."""
import os
import re

from ansible import context
from ansible.plugins.callback import CallbackBase


DOCUMENTATION = r'''
name: fleet_console
type: stdout
short_description: Compact progress for the fleet launcher
description:
  - Displays long-running stages and failures, without dumping result dictionaries.
requirements:
  - Set ANSIBLE_STDOUT_CALLBACK=fleet_console, as done by run.py.
'''


def safe(value):
    return re.sub(r"[\x00-\x1f\x7f]", " ", str(value))


class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = "stdout"
    CALLBACK_NAME = "fleet_console"

    def v2_playbook_on_play_start(self, play):
        self.action = os.environ.get("FLEET_ACTION") or play.get_vars().get("fleet_action")
        self._display.display("\n" + safe(play.get_name()))

    def v2_runner_on_start(self, host, task):
        if task.action.rsplit(".", 1)[-1] == "script":
            operation = re.match(r"fleet_agent\.py (\w+)", task.args.get("cmd", ""))
            if not operation:
                return
            if operation[1] in ("update", "health") and (self.action != "update" or context.CLIARGS.get("check")):
                return
            self._display.display("  {}: {}…".format(safe(host.get_name()), safe(task.get_name())))

    def v2_runner_on_ok(self, result):
        if result._task.action.rsplit(".", 1)[-1] == "reboot":
            self._display.display("  {}: перезагрузка завершена".format(safe(result._host.get_name())))

    def v2_runner_on_failed(self, result, ignore_errors=False):
        raw = result._result
        message = "подробности в локальном отчёте" if raw.get("_ansible_no_log") else raw.get("msg", "ошибка задачи")
        self._display.display("  {}: ОШИБКА — {}".format(safe(result._host.get_name()), safe(message)))

    def v2_runner_on_unreachable(self, result):
        self._display.display("  {}: НЕДОСТУПЕН — {}".format(safe(result._host.get_name()), safe(result._result.get("msg", "SSH"))))

    def v2_playbook_on_stats(self, stats):
        for host in sorted(stats.processed):
            if host == "localhost":
                continue
            result = stats.summarize(host)
            state = "ОШИБКА" if result.get("failures") or result.get("unreachable") else "этап завершён"
            self._display.display("  {}: {}".format(safe(host), state))
