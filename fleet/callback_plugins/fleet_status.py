"""Write Ansible's real per-host outcome, including unreachable hosts."""
import json
import os
from pathlib import Path

from ansible.plugins.callback import CallbackBase


class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = "aggregate"
    CALLBACK_NAME = "fleet_status"
    CALLBACK_NEEDS_ENABLED = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ssh_results = {}

    def record_ssh_result(self, result, state):
        if "fleet_ssh_probe" not in result._task.tags:
            return
        data = result._result
        self.ssh_results[result._host.get_name()] = {
            "status": state, "rc": data.get("rc"),
            "message": str(data.get("msg") or data.get("stderr") or "")[:4000],
        }

    def v2_runner_on_ok(self, result):
        self.record_ssh_result(result, "ok")

    def v2_runner_on_failed(self, result, ignore_errors=False):
        self.record_ssh_result(result, "error")

    def v2_runner_on_unreachable(self, result):
        self.record_ssh_result(result, "error")

    def v2_playbook_on_stats(self, stats):
        directory = os.environ.get("FLEET_REPORT_DIR")
        if not directory:
            return
        try:
            result = {host: stats.summarize(host) for host in sorted(stats.processed)}
            target = Path(directory) / "run-status.json"
            target.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
            target.chmod(0o600)
            if os.environ.get("FLEET_ACTION") == "check-ssh" or self.ssh_results:
                target = Path(directory) / "ssh-results.json"
                target.write_text(json.dumps(self.ssh_results, ensure_ascii=False, indent=2) + "\n")
                target.chmod(0o600)
        except OSError as error:
            self._display.warning("Не удалось сохранить результаты Ansible: {}".format(error))
