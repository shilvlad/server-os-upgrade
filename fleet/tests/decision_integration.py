"""Exercise real Ansible and selection/approval with inert target-side workers.

No real APT operation or reboot is performed, including when a test fails.
"""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import run as launcher


WORKER = r'''
import base64, json, pathlib, sys
options = json.loads(base64.b64decode(sys.argv[sys.argv.index('--options') + 1]))
action = sys.argv[2]
simulation = ('1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n'
              'Inst nginx [1.24-1] (1.24-2 Ubuntu:24.04/noble-security [amd64])\n')
health = {'kernel': 'test-kernel', 'critical_services': {}, 'http_checks': {},
          'failed_units': {'status': 'ok', 'items': []}, 'reboot_required_marker': False}
components = {name: {'status': 'not_available', 'items': []} for name in
              ('python', 'npm_global', 'snap', 'flatpak', 'docker_images', 'podman_images')}
inventory = {'os': {'id': 'ubuntu', 'version_id': '24.04', 'version_codename': 'noble',
                   'pretty_name': 'Ubuntu fixture'},
             'kernel': 'test-kernel', 'architecture': 'x86_64', 'collected_at': '2026-11-10T00:00:00Z',
             'dpkg': [{'name': 'nginx', 'version': '1.24-2' if marker.exists() else '1.24-1',
                       'architecture': 'amd64', 'source_name': 'nginx', 'source_version': '1.24-1'}],
             'components': components, 'unmanaged_candidates': {'status': 'ok', 'items': []},
             'version_probes': [], 'coverage_notes': []}
if action == 'inventory':
    result = inventory
elif action == 'plan':
    assert options['refresh_cache'] and options['apply_requested']
    result = {'os': inventory['os'], 'health': health, 'free_mb': {'/': 10000}, 'held_packages': [],
              'simulation': simulation, 'fingerprint': 'fixture-approval-v1', 'cache_refreshed': True,
              'apt_policy': {'rc': 0, 'stdout': 'release a=noble-security,n=noble'}}
elif action == 'update':
    assert options['confirmed'] and options['approved_plan_fingerprint'] == 'fixture-approval-v1'
    marker.write_text('fixture package update requested')
    result = {'packages_changed': True, 'changed_packages': inventory['dpkg']}
elif action == 'health':
    result = health
else:
    raise RuntimeError('unexpected worker action: ' + action)
print(json.dumps(result))
'''


def main():
    with tempfile.TemporaryDirectory(prefix="fleet-decision-integration-") as temp:
        directory = Path(temp)
        hosts = {}
        for host in ("node-a", "node-b"):
            worker = directory / (host + "-python")
            marker = directory / (host + "-installed")
            worker.write_text("#!" + sys.executable + "\nmarker = __import__('pathlib').Path(" + repr(str(marker)) + ")\n" + WORKER)
            worker.chmod(0o700)
            hosts[host] = {"ansible_connection": "local", "ansible_become": False,
                           "fleet_remote_python": str(worker)}
        inventory = directory / "inventory.json"
        inventory.write_text(json.dumps({"all": {"hosts": hosts}}))
        overrides = directory / "stale-vars.json"
        overrides.write_text(json.dumps({"fleet_action": "update"}))
        output = io.StringIO()
        with contextlib.redirect_stdout(output), patch.object(sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", side_effect=["d", "2", "UPDATE"]):
            code = launcher.main(["update", "-i", str(inventory), "--vars", str(overrides),
                                  "--full-upgrade", "--reports", str(directory / "reports")])
        if code:
            print(output.getvalue())
        assert code == 0, "launcher failed"
        assert not (directory / "node-a-installed").exists(), "unselected node was changed"
        assert (directory / "node-b-installed").exists(), "selected node did not reach the update worker"
        runs = list((directory / "reports").glob("*/run.json"))
        assert len(runs) == 1
        run = json.loads(runs[0].read_text())
        assert run["expected_hosts"] == ["node-b"] and run["status"] == "success"
        summary = (runs[0].parent / "summary.md").read_text()
        assert "node-b" in summary and "ОБНОВЛЕНО" in summary
        assert "node-a" not in summary
        assert "обновить 1" in output.getvalue()
        assert (runs[0].parent / "approved-plan.txt").exists()
        print("Real Ansible preview/selection/approval passed; target workers were inert.")


if __name__ == "__main__":
    main()
