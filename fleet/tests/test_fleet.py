import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from report import build_reports, cell
import run as launcher
from run import load_hosts
from ssh_report import build_ssh_report

spec = importlib.util.spec_from_file_location("fleet_agent", ROOT / "roles/fleet/files/fleet_agent.py")
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)


class InventoryTests(unittest.TestCase):
    def test_installed_and_held_packages_keep_epoch_source_and_arch(self):
        # db:Status-Status remains installed even when dpkg's selection is hold.
        output = ("installed\tlibssl3:amd64\t3:3.0.11-1~deb12u2\tamd64\topenssl\t3:3.0.11-1~deb12u2\n"
                  "config-files\tremoved\t1\tall\tremoved\t1\n"
                  "installed\theld\t2.0-1\tall\theld-source\t2.0-1\n")
        with patch.object(agent, "required", return_value=output):
            packages = agent.dpkg_packages()
        self.assertEqual(len(packages), 2)
        self.assertEqual(packages[1]["source_name"], "openssl")
        self.assertEqual(packages[1]["version"], "3:3.0.11-1~deb12u2")
        self.assertEqual(packages[0]["name"], "held")

    def test_malformed_dpkg_data_does_not_become_a_clean_empty_report(self):
        with patch.object(agent, "required", return_value="invalid data\n"):
            with self.assertRaises(agent.AgentError):
                agent.dpkg_packages()

    def test_python_metadata_read_does_not_import_application_code(self):
        with tempfile.TemporaryDirectory() as temp:
            package = Path(temp) / "venv/lib/python3.11/site-packages/example-1.2.dist-info"
            package.mkdir(parents=True)
            (package / "METADATA").write_text("Name: example\nVersion: 1.2\n")
            marker = Path(temp) / "executed"
            (package.parent / "sitecustomize.py").write_text("raise RuntimeError('must not execute')")
            result = agent.python_packages([str(Path(temp) / "venv")])
            match = [item for item in result["items"] if item["location"] == str(package.parent)]
            self.assertEqual(match, [{"name": "example", "version": "1.2", "location": str(package.parent)}])
            self.assertFalse(marker.exists())

    def test_ip_validation_duplicates_ipv6_comments(self):
        with tempfile.TemporaryDirectory() as temp:
            filename = Path(temp) / "ips"
            filename.write_text("# comment\n192.0.2.1 # node\n192.0.2.1\n2001:db8::1\n")
            self.assertEqual(load_hosts(filename), ["192.0.2.1", "2001:db8::1"])
            filename.write_text("192.0.2.1; touch bad\n")
            with self.assertRaises(ValueError):
                load_hosts(filename)

    def test_ip_dns_short_names_and_idna_without_network_lookups(self):
        with tempfile.TemporaryDirectory() as temp:
            filename = Path(temp) / "servers.txt"
            filename.write_text("192.0.2.1\n2001:0db8::1\nAPP01.example.com\napp01.example.com.\n"
                                "db01 # short DNS name\nсервер.рф\n")
            self.assertEqual(load_hosts(filename), ["192.0.2.1", "2001:db8::1", "app01.example.com",
                                                   "db01", "xn--b1afb6bcb.xn--p1ai"])

    def test_invalid_targets_are_not_reinterpreted_as_hostnames(self):
        for value in ("999.0.2.1", "2001:db8:::1", "https://host.example", "user@host.example",
                      "host.example:22", "-bad.example", "bad..example", "bad_.example", "host;id",
                      "a" * 64 + ".example", "localhost", "localhost."):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as temp:
                filename = Path(temp) / "servers.txt"
                filename.write_text(value + "\n")
                with self.assertRaises(ValueError):
                    load_hosts(filename)


class SshTests(unittest.TestCase):
    def test_summary_includes_success_failure_and_unattempted_hosts(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            expected = ["up.example", "bad.example", "unattempted.example"]
            (directory / "run.json").write_text(json.dumps({"expected_hosts": expected}))
            (directory / "ssh-results.json").write_text(json.dumps({
                "up.example": {"status": "ok", "rc": 0, "message": ""},
                "bad.example": {"status": "error", "rc": None,
                                "message": "ssh: Could not resolve hostname bad.example: Name or service not known"}}))
            (directory / "run-status.json").write_text(json.dumps({"up.example": {"failures": 0},
                                                                   "bad.example": {"unreachable": 1}}))
            result = build_ssh_report(directory)
            self.assertEqual(result["reachable"], 1)
            self.assertEqual(result["failed"], 2)
            self.assertFalse(result["complete"])
            self.assertEqual(result["hosts"]["bad.example"]["reason_code"], "dns")
            self.assertEqual(result["hosts"]["unattempted.example"]["status"], "not_checked")
            self.assertFalse((directory / "review.json").exists())
            self.assertEqual((directory / "ssh-check.json").stat().st_mode & 0o777, 0o600)

    def test_menu_selects_key_only_ssh_and_does_not_request_sudo(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "servers.txt").write_text("up.example\n")
            calls = []
            def execute(command, **kwargs):
                calls.append(command)
                if "--list-hosts" in command:
                    return subprocess_result("      up.example\n")
                directory = Path(kwargs["env"]["FLEET_REPORT_DIR"])
                (directory / "run-status.json").write_text(json.dumps({"up.example": {"ok": 1}}))
                (directory / "ssh-results.json").write_text(json.dumps({
                    "up.example": {"status": "ok", "rc": 0, "message": ""}}))
                return subprocess_result("")
            with patch.object(launcher, "ROOT", root), patch.object(launcher.sys.stdin, "isatty", return_value=True), \
                 patch("builtins.input", return_value="4"), patch.object(launcher.shutil, "which", return_value="ansible-playbook"), \
                 patch.object(launcher.subprocess, "run", side_effect=execute), \
                 patch("builtins.print"):
                code = launcher.main(["--private-key", "/test/key", "-K", "--reports", str(root / "reports")])
            self.assertEqual(code, 0)
            command = calls[-1]
            self.assertIn(str(root / "playbooks/check-ssh.yml"), command)
            self.assertNotIn("--ask-become-pass", command)
            options = json.loads(command[command.index("-e") + 1])
            self.assertEqual(options["ansible_connection"], "ssh")
            self.assertFalse(options["ansible_become"])
            self.assertIn("PreferredAuthentications=publickey", options["ansible_ssh_args"])
            self.assertIn("BatchMode=yes", options["ansible_ssh_args"])
            self.assertIn("ControlPath=none", options["ansible_ssh_args"])
            self.assertIn("StrictHostKeyChecking=yes", options["ansible_ssh_args"])
            self.assertIn("IdentitiesOnly=yes", options["ansible_ssh_args"])
            generated = json.loads((root / "inventory/generated.json").read_text())
            self.assertIn("up.example", generated["all"]["children"]["linux"]["hosts"])


def subprocess_result(stdout, code=0):
    from types import SimpleNamespace
    return SimpleNamespace(stdout=stdout, stderr="", returncode=code)


class UpdateTests(unittest.TestCase):
    def test_update_requires_confirmation_before_running_package_commands(self):
        with patch.object(agent, "os_info", return_value={"id": "debian", "astra_version": ""}), \
             patch.object(agent, "required") as commands:
            with self.assertRaisesRegex(agent.AgentError, "confirmation"):
                agent.preflight({}, installing=True)
            commands.assert_not_called()

    def test_astra_explicit_acknowledgment_is_required_before_any_package_command(self):
        with patch.object(agent, "os_info", return_value={"id": "astra", "astra_version": "1.8.3"}), \
             patch.object(agent.os, "geteuid", return_value=0), \
             patch.object(agent, "required") as commands:
            with self.assertRaisesRegex(agent.AgentError, "astra-apt"):
                agent.preflight({"confirmed": True}, installing=True)
            commands.assert_not_called()

    def test_no_removal_no_untrusted_packages_in_both_upgrade_modes(self):
        for mode in ("safe", "dist"):
            for simulate in (False, True):
                command = agent.apt_argv({"upgrade_mode": mode}, simulate)
                self.assertIn("--no-remove", command)
                for forbidden in ("--force-yes", "--allow-unauthenticated", "--allow-downgrades",
                                  "--allow-change-held-packages", "autoremove", "--force"):
                    self.assertNotIn(forbidden, command)
                self.assertEqual("--simulate" in command, simulate)

    def test_plan_does_not_refresh_cache_by_default(self):
        with patch.object(agent, "preflight", return_value={}), \
             patch.object(agent, "required", return_value="0 upgraded") as commands:
            result = agent.plan({})
        self.assertFalse(result["cache_refreshed"])
        self.assertEqual(commands.call_count, 1)
        self.assertIn("--simulate", commands.call_args.args[0])

    def test_old_apt_partial_refresh_exit_zero_still_blocks_install(self):
        with patch.object(agent, "preflight", return_value={}), \
             patch.object(agent, "run", return_value={"rc": 0, "stdout": "", "stderr": "W: Failed to fetch index"}), \
             patch.object(agent, "required") as commands:
            with self.assertRaisesRegex(agent.AgentError, "index refresh failed"):
                agent.plan({"refresh_cache": True})
            commands.assert_not_called()

    def test_failed_apt_preserves_transaction_and_returns_failure(self):
        transaction = {"rc": 100, "stdout": "failed package", "stderr": "dpkg error"}
        with patch.object(agent, "preflight", return_value={}), \
             patch.object(agent, "dpkg_packages", return_value=[{"name": "test"}]), \
             patch.object(agent, "required", return_value="simulation"), \
             patch.object(agent, "run", return_value=transaction) as command:
            with self.assertRaises(agent.AgentError) as failure:
                agent.update({"confirmed": True})
        self.assertEqual(failure.exception.details["transaction"], transaction)
        self.assertIsNone(command.call_args.kwargs["timeout"])

    def test_new_failed_units_fail_an_otherwise_successful_transaction(self):
        old = {"failed_units": {"items": ["old.service"]}}
        new = {"failed_units": {"items": ["old.service", "new.service"]}}
        with patch.object(agent, "preflight", return_value={"health": old}), \
             patch.object(agent, "dpkg_packages", return_value=[{"name": "test"}]), \
             patch.object(agent, "required", side_effect=["simulation", ""]), \
             patch.object(agent, "run", return_value={"rc": 0, "stdout": "ok", "stderr": ""}), \
             patch.object(agent, "health", return_value=new):
            with self.assertRaisesRegex(agent.AgentError, "new.service"):
                agent.update({"confirmed": True})


class ReportTests(unittest.TestCase):
    def fixture(self):
        components = {name: {"status": "not_available", "items": []} for name in
                      ("python", "npm_global", "snap", "flatpak", "docker_images", "podman_images")}
        components["python"] = {"status": "ok", "items": [{"name": "library", "version": "1.0", "location": "/private/app"}]}
        components["docker_images"] = {"status": "ok", "items": [{"ID": "sha256:123", "Repository": "private.registry/app", "Digest": "sha256:456"}]}
        return {"report_type": "inventory", "phase": "before", "host": "secret-host", "address": "10.21.31.41",
                "data": {"os": {"id": "debian", "version_id": "12", "pretty_name": "Debian"},
                         "kernel": "6.1", "architecture": "x86_64", "collected_at": "2026-11-10T00:00:00Z",
                         "dpkg": [{"name": "curl", "version": "1:8.0-1", "architecture": "amd64",
                                   "source_name": "curl", "source_version": "1:8.0-1"}],
                         "components": components, "version_probes": [], "coverage_notes": ["incomplete coverage"],
                         "unmanaged_candidates": {"status": "ok", "items": []}}}

    def test_review_drops_host_addresses_paths_and_private_image_names_but_keeps_versions(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            (directory / "hosts").mkdir()
            (directory / "hosts/one.json").write_text(json.dumps(self.fixture()))
            (directory / "run.json").write_text(json.dumps({"expected_hosts": ["secret-host", "unattempted-host"]}))
            (directory / "run-status.json").write_text(json.dumps({"secret-host": {"failures": 1, "unreachable": 0}}))
            summary = build_reports(directory)
            text = (directory / "review.json").read_text()
            review = json.loads(text)
            for secret in ("secret-host", "10.21.31.41", "/private/app", "private.registry"):
                self.assertNotIn(secret, text)
            self.assertIn("1:8.0-1", text)
            self.assertEqual(review["hosts"][0]["host_id"], "host-0001")
            self.assertEqual(review["missing_host_count"], 1)
            self.assertTrue(review["run_incomplete"])
            self.assertFalse(summary["complete"])
            self.assertEqual(summary["missing_hosts"], ["unattempted-host"])
            self.assertEqual((directory / "review.json").stat().st_mode & 0o777, 0o600)

    def test_csv_cannot_execute_a_host_supplied_formula(self):
        self.assertEqual(cell("=HYPERLINK('x')"), "'=HYPERLINK('x')")
        self.assertEqual(cell("1:2.0-1"), "1:2.0-1")


if __name__ == "__main__":
    unittest.main()
