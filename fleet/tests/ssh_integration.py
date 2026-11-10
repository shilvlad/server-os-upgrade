"""CI-only SSH integration against an ephemeral loopback sshd; no user servers."""
import getpass
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def command(args):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def exercise(directory, name, hosts, key, variables, expected_code):
    hosts_file = directory / (name + ".txt")
    hosts_file.write_text(hosts)
    result = subprocess.run([sys.executable, "run.py", "check-ssh", "--hosts", str(hosts_file),
        "--user", getpass.getuser(), "--private-key", str(key), "--vars", str(variables),
        "--ssh-timeout", "5", "-K", "--reports", str(directory / name)],
        cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    if bool(result.returncode) != bool(expected_code):
        raise AssertionError(result.stdout + "\n" + result.stderr)
    reports = list((directory / name).glob("*/ssh-check.json"))
    assert len(reports) == 1, result.stdout + result.stderr
    return json.loads(reports[0].read_text())


def main():
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise RuntimeError("This SSH fixture is intended only for disposable GitHub CI runners")
    with tempfile.TemporaryDirectory(prefix="fleet-ssh-ci-") as temp:
        directory = Path(temp)
        for name in ("host", "client", "wrong"):
            command(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(directory / name)])
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        known_hosts = directory / "known_hosts"
        known_hosts.write_text("[127.0.0.1]:{} {}".format(port, (directory / "host.pub").read_text()))
        config = directory / "sshd_config"
        config.write_text("\n".join([
            "Port {}".format(port), "ListenAddress 127.0.0.1",
            "HostKey {}".format(directory / "host"), "PidFile {}".format(directory / "sshd.pid"),
            "AuthorizedKeysFile {}".format(directory / "client.pub"), "StrictModes no",
            "PasswordAuthentication no", "KbdInteractiveAuthentication no", "PubkeyAuthentication yes",
            "UsePAM yes", "AllowUsers {}".format(getpass.getuser()), "LogLevel ERROR", ""]))
        command(["sudo", "-n", "mkdir", "-p", "/run/sshd"])
        variables = directory / "variables.json"
        variables.write_text(json.dumps({"ansible_port": port,
            "ansible_ssh_common_args": "-o UserKnownHostsFile={}".format(known_hosts),
            "ansible_become": True, "ansible_become_exe": "/no-such-sudo",
            "ansible_python_interpreter": "/no-such-python"}))
        with (directory / "sshd.log").open("w+") as log:
            server = subprocess.Popen(["sudo", "-n", "/usr/sbin/sshd", "-D", "-e", "-f", str(config)],
                                      stdout=subprocess.DEVNULL, stderr=log)
            try:
                for _ in range(50):
                    if server.poll() is not None:
                        log.seek(0)
                        raise RuntimeError("sshd failed: " + log.read())
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                            break
                    except OSError:
                        time.sleep(0.1)
                else:
                    raise RuntimeError("sshd did not start")
                ok = exercise(directory, "success", "127.0.0.1\n", directory / "client", variables, 0)
                assert ok["all_reachable"] and ok["reachable"] == 1
                mixed = exercise(directory, "mixed", "missing-host.fleet.invalid\n127.0.0.1\n",
                                 directory / "client", variables, 1)
                assert len(mixed["hosts"]) == 2 and mixed["reachable"] == 1 and mixed["failed"] == 1
                assert mixed["hosts"]["missing-host.fleet.invalid"]["reason_code"] == "dns"
                wrong = exercise(directory, "wrong-key", "127.0.0.1\n", directory / "wrong", variables, 1)
                assert wrong["hosts"]["127.0.0.1"]["reason_code"] == "authentication"
                assert not wrong["all_reachable"]
                # A new key check must not quietly accept an unknown host key.
                known_hosts.write_text("")
                unknown = exercise(directory, "unknown-host-key", "127.0.0.1\n",
                                   directory / "client", variables, 1)
                assert unknown["hosts"]["127.0.0.1"]["reason_code"] == "host_key"
            finally:
                server.terminate()
                server.wait(timeout=10)
    print("SSH integration passed: key login, all-target reporting, wrong key, unknown host key")


if __name__ == "__main__":
    main()
