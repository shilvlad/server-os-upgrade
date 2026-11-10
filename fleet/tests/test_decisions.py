import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

import test_fleet as legacy
from display import parse_simulation, render
from report import build_reports
import run as launcher

agent = legacy.agent
SIMULATION = """The following upgrades have been deferred due to phasing:
  distro-info python3-distro-info
2 upgraded, 1 newly installed, 0 to remove and 2 not upgraded.
Inst openssh-server [1:9.6-1] (1:9.6-2 Ubuntu:24.04/noble-security [amd64])
Inst nginx [1.24-1] (1.24-2 Ubuntu:24.04/noble-security [amd64])
Inst linux-image-6.8.0-149-generic (6.8.0-149.149 Ubuntu:24.04/noble-security [amd64])
Conf nginx (1.24-2 Ubuntu:24.04/noble-security [amd64])
"""


def plan_data(text=SIMULATION):
    return {"os": {"id": "ubuntu", "version_codename": "noble", "pretty_name": "Ubuntu 24.04"},
            "simulation": text, "fingerprint": agent.plan_fingerprint(text, {"upgrade_mode": "dist"}),
            "cache_refreshed": True, "free_mb": {"/": 7000},
            "health": {"kernel": "6.8.0-85-generic", "critical_services": {},
                       "failed_units": {"status": "ok", "items": []}},
            "apt_policy": {"rc": 0, "stdout": "release a=noble-security,n=noble"}}


def write_host(directory, host, phase="before", updating=False, malformed=False):
    folder = directory / "hosts"
    folder.mkdir(exist_ok=True)
    inv = legacy.ReportTests().fixture()
    inv.update(host=host, phase=phase)
    inv["data"]["kernel"] = "6.8.0-149-generic" if phase == "after" else "6.8.0-85-generic"
    (folder / (host + "-" + phase + ".json")).write_text(json.dumps(inv))
    plan = plan_data("not an APT plan" if malformed else SIMULATION)
    (folder / (host + "-plan.json")).write_text(json.dumps({"host": host, "report_type": "plan",
        "result": {"rc": 0, "stdout": json.dumps(plan)}}))
    if updating:
        for kind, data in (("update", {"changed_packages": [{"name": "nginx", "version": "1.24-2"}]}),
                           ("health", {"critical_services": {}, "failed_units": {"items": []},
                                       "kernel": "6.8.0-149-generic", "http_checks": {"web": {"ok": True, "status": 200}}})):
            (folder / (host + "-" + kind + ".json")).write_text(json.dumps({"host": host,
                "report_type": kind, "result": {"rc": 0, "stdout": json.dumps(data)}}))


class PresentationTests(unittest.TestCase):
    def test_counts_versions_new_kernel_and_phasing_are_shown(self):
        parsed = parse_simulation(SIMULATION)
        self.assertTrue(parsed["valid"])
        self.assertEqual(parsed["counts"], {"upgrade": 2, "install": 1, "remove": 0, "defer": 2})
        self.assertEqual(parsed["deferred"], ["distro-info", "python3-distro-info"])
        self.assertEqual(parsed["packages"][0]["before"], "1:9.6-1")
        self.assertEqual(parsed["kernels"], ["6.8.0-149-generic"])

    def test_unknown_or_inconsistent_plan_and_removals_cannot_be_approved(self):
        for text in ("not a plan", SIMULATION.replace("2 upgraded", "3 upgraded"),
                     SIMULATION + "Remv nginx [1.24-1]\n"):
            with self.subTest(text=text):
                self.assertFalse(parse_simulation(text)["valid"])

    def test_human_plan_is_saved_instead_of_an_inventory_only_summary(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            (directory / "run.json").write_text(json.dumps({"action": "plan", "expected_hosts": ["app"], "reboot_requested": True}))
            (directory / "run-status.json").write_text(json.dumps({"app": {"failures": 0}}))
            write_host(directory, "app")
            summary = build_reports(directory)
            self.assertTrue(summary["complete"])
            text = (directory / "summary.md").read_text()
            self.assertIn("обновить 2", text)
            self.assertIn("1:9.6-1 → 1:9.6-2", text)
            self.assertIn("Перезагрузка после установки: ДА", text)
            self.assertIn("HTTP-проверки приложений не настроены", text)
            self.assertNotIn("отсутствует noble-security", text)
            self.assertEqual((directory / "packages-plan.txt").stat().st_mode & 0o777, 0o600)
            self.assertIn("Проверка уязвимостей не выполнялась", text)

    def test_missing_and_unattempted_hosts_are_not_successful_updates(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            (directory / "run.json").write_text(json.dumps({"action": "update", "expected_hosts": ["app", "missing"]}))
            (directory / "run-status.json").write_text(json.dumps({"app": {"failures": 0}}))
            write_host(directory, "app")
            result = build_reports(directory)
            self.assertFalse(result["complete"])
            self.assertEqual(result["models"]["app"]["state"], "ОШИБКА")
            self.assertEqual(result["models"]["missing"]["state"], "ОШИБКА")
            self.assertNotIn("ОБНОВЛЕНО", result["text"])

    def test_successful_apt_with_http_502_is_reported_as_an_application_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            (directory / "run.json").write_text(json.dumps({"action": "update", "expected_hosts": ["app"]}))
            (directory / "run-status.json").write_text(json.dumps({"app": {"failures": 1}}))
            write_host(directory, "app", updating=True)
            failure = {"status": "failed", "error": "An application HTTP check failed",
                       "details": {"http_checks": {"web": {"status": 502, "ok": False}}}}
            (directory / "hosts/app-health.json").write_text(json.dumps({"host": "app", "report_type": "health",
                "result": {"rc": 1, "stdout": json.dumps(failure)}}))
            result = build_reports(directory)
            self.assertFalse(result["complete"])
            self.assertIn("APT завершён", result["text"])
            self.assertIn("HTTP 502 (ОШИБКА)", result["text"])
            self.assertIn("снимок ДО обновления", result["text"])
            self.assertNotIn("ОБНОВЛЕНО", result["text"])


class ApprovalTests(unittest.TestCase):
    def launcher_run(self, answers, yes=False, malformed=False, wrong_scope=False):
        calls, messages = [], []
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "servers.txt").write_text("a.example\nb.example\n")

            def execute(command, **kwargs):
                if "--list-hosts" in command:
                    names = ["a.example", "b.example"]
                    limit = command[command.index("--limit") + 1]
                    if limit.startswith("@"):
                        names = Path(limit[1:]).read_text().splitlines()
                        if wrong_scope:
                            names.append("extra.example")
                    return legacy.subprocess_result("".join("      " + name + "\n" for name in names))
                action = kwargs["env"]["FLEET_ACTION"]
                directory = Path(kwargs["env"]["FLEET_REPORT_DIR"])
                meta = json.loads((directory / "run.json").read_text())
                names = meta["expected_hosts"]
                options = json.loads(command[-1])
                if action == "update":
                    self.assertTrue(any("обновить 2" in m for m in messages))
                calls.append((action, names, options))
                for host in names:
                    write_host(directory, host, phase="after" if action == "update" else "before",
                               updating=action == "update", malformed=malformed)
                (directory / "run-status.json").write_text(json.dumps({name: {"failures": 0} for name in names}))
                return legacy.subprocess_result("")

            def answer(prompt):
                self.assertTrue(any("обновить 2" in message for message in messages))
                return next(answers)

            with patch.object(launcher, "ROOT", root), patch.object(launcher.sys.stdin, "isatty", return_value=True), \
                 patch.object(launcher.shutil, "which", return_value="ansible-playbook"), \
                 patch.object(launcher.subprocess, "run", side_effect=execute), \
                 patch("builtins.input", side_effect=answer) as prompt, \
                 patch("builtins.print", side_effect=lambda *a, **kw: messages.append(" ".join(map(str, a)))):
                code = launcher.main(["update", "--hosts", str(root / "servers.txt"), "--full-upgrade",
                                      "--reports", str(root / "reports")] + (["--yes"] if yes else []))
                if yes or malformed:
                    prompt.assert_not_called()
            return code, calls, messages

    def test_preview_precedes_confirmation_and_only_selected_server_is_updated(self):
        code, calls, messages = self.launcher_run(iter(["d", "2", "UPDATE"]))
        self.assertEqual(code, 0)
        self.assertEqual([entry[:2] for entry in calls], [("plan", ["a.example", "b.example"]), ("update", ["b.example"])])
        approved = calls[1][2]
        self.assertEqual(set(approved["fleet_approved_plans"]), {"b.example"})
        self.assertTrue(approved["fleet_require_approved_plan"])
        self.assertTrue(any("ОБНОВЛЕНО" in m for m in messages))

    def test_cancel_and_wrong_confirmation_never_install(self):
        for answers in (["0"], ["all", "NO"]):
            with self.subTest(answers=answers):
                code, calls, _ = self.launcher_run(iter(answers))
                self.assertEqual(code, 0)
                self.assertEqual([entry[0] for entry in calls], ["plan"])

    def test_unrecognized_plan_blocks_yes_and_never_installs(self):
        code, calls, _ = self.launcher_run(iter([]), yes=True, malformed=True)
        self.assertEqual(code, 2)
        self.assertEqual([entry[0] for entry in calls], ["plan"])

    def test_yes_still_displays_and_validates_preview(self):
        code, calls, _ = self.launcher_run(iter([]), yes=True)
        self.assertEqual(code, 0)
        self.assertEqual(calls[-1][1], ["a.example", "b.example"])

    def test_broadened_ansible_scope_never_installs(self):
        code, calls, _ = self.launcher_run(iter(["2", "UPDATE"]), wrong_scope=True)
        self.assertEqual(code, 2)
        self.assertEqual([entry[0] for entry in calls], ["plan"])


class ApplyGuardTests(unittest.TestCase):
    def test_changed_candidate_is_rejected_before_apt_transaction(self):
        options = {"confirmed": True, "upgrade_mode": "dist",
                   "approved_plan_fingerprint": agent.plan_fingerprint(SIMULATION, {"upgrade_mode": "dist"})}
        changed = SIMULATION.replace("1:9.6-2", "1:9.6-3")
        with patch.object(agent, "preflight", return_value={}), patch.object(agent, "dpkg_packages", return_value=[]), \
             patch.object(agent, "required", return_value=changed), patch.object(agent, "run") as transaction:
            with self.assertRaisesRegex(agent.AgentError, "plan changed after approval"):
                agent.update(options)
            transaction.assert_not_called()

    def test_warning_text_and_order_do_not_change_approved_package_operations(self):
        reordered = "different warning\n" + "\n".join(reversed(SIMULATION.splitlines()))
        self.assertEqual(agent.plan_fingerprint(SIMULATION, {}), agent.plan_fingerprint(reordered, {}))
        self.assertNotEqual(agent.plan_fingerprint(SIMULATION, {}), agent.plan_fingerprint(SIMULATION, {"upgrade_mode": "dist"}))

    def test_http_502_is_an_application_failure_even_with_no_failed_units(self):
        error = urllib.error.HTTPError("http://127.0.0.1/health", 502, "Bad Gateway", {}, io.BytesIO())
        with patch.object(agent, "optional", return_value={"status": "ok", "items": []}), \
             patch.object(agent.urllib.request, "urlopen", side_effect=error):
            with self.assertRaisesRegex(agent.AgentError, "HTTP check failed") as failure:
                agent.health({"http_checks": [{"name": "web", "url": "http://127.0.0.1/health"}]})
        self.assertEqual(failure.exception.details["http_checks"]["web"]["status"], 502)


if __name__ == "__main__":
    unittest.main()
