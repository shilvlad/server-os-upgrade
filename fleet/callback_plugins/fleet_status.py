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

    def v2_playbook_on_stats(self, stats):
        directory = os.environ.get("FLEET_REPORT_DIR")
        if not directory:
            return
        try:
            result = {host: stats.summarize(host) for host in sorted(stats.processed)}
            target = Path(directory) / "run-status.json"
            target.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
            target.chmod(0o600)
        except OSError as error:
            self._display.warning("Не удалось сохранить run-status.json: {}".format(error))
