#!/usr/bin/env python3
"""Local-only Linux collector and APT worker; Python 3.7+, standard library.

Executed by Ansible's script action so old target Python versions do not need
to execute Ansible modules or import python3-apt. Never runs a shell command.
"""
import argparse
import base64
import datetime
from email.parser import Parser
import glob
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import sysconfig
import urllib.error
import urllib.parse
import urllib.request


class AgentError(Exception):
    def __init__(self, message, details=None):
        super().__init__(message)
        self.details = details or {}


def redact(value):
    if isinstance(value, str):
        return re.sub(r"(https?://)[^\s/@]+:[^\s/@]+@", r"\1<redacted>@", value)
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, dict):
        return {key: redact(item) for key, item in value.items()}
    return value


def run(argv, timeout=60):
    environment = dict(os.environ, LC_ALL="C", LANG="C", PIP_DISABLE_PIP_VERSION_CHECK="1")
    environment["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    environment.update(DEBIAN_FRONTEND="noninteractive", NEEDRESTART_MODE="l")
    try:
        process = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 universal_newlines=True, errors="replace",
                                 env=environment, timeout=timeout, check=False)
        return {"rc": process.returncode, "stdout": process.stdout, "stderr": process.stderr}
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"rc": 127 if isinstance(error, FileNotFoundError) else 124,
                "stdout": "", "stderr": str(error)}


def required(argv, timeout=60):
    result = run(argv, timeout)
    if result["rc"]:
        raise AgentError("Command failed: {}: {}".format(argv[0], result["stderr"]), result)
    return result["stdout"]


def os_info():
    release = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            release[key.lower()] = value.strip().strip('"').strip("'")
    result = {key: release.get(key, "") for key in
              ("id", "id_like", "version_id", "version_codename", "pretty_name")}
    astra = Path("/etc/astra_version")
    result["astra_version"] = astra.read_text().strip() if astra.exists() else ""
    if result["id"] not in ("debian", "ubuntu", "astra", "astralinux") and not result["astra_version"]:
        raise AgentError("Supported operating systems: Astra Linux, Debian, Ubuntu")
    return result


def dpkg_packages():
    fields = ["${db:Status-Status}", "${binary:Package}", "${Version}",
              "${Architecture}", "${source:Package}", "${source:Version}"]
    output = required(["dpkg-query", "-W", "-f=" + "\t".join(fields) + "\n"])
    packages = []
    for line in output.splitlines():
        row = line.split("\t")
        if len(row) != 6:
            raise AgentError("Unexpected dpkg-query output; refusing an incomplete inventory")
        if row[0] != "installed":
            continue
        packages.append(dict(zip(("name", "version", "architecture", "source_name", "source_version"), row[1:])))
    if not packages:
        raise AgentError("dpkg returned no installed packages")
    return sorted(packages, key=lambda package: (package["name"], package["architecture"]))


def optional(argv, parser, timeout=60):
    if not shutil.which(argv[0]):
        return {"status": "not_available", "items": []}
    result = run(argv, timeout)
    try:
        items = parser(result["stdout"]) if result["stdout"].strip() else []
        return {"status": "ok" if result["rc"] == 0 else "partial" if items else "error",
                "items": items, "error": result["stderr"].strip() if result["rc"] else ""}
    except (ValueError, KeyError, TypeError, IndexError) as error:
        return {"status": "error", "items": [], "error": str(error)}


def discover(roots, maximum=500, depth=3):
    entries, environments, errors = [], [], []
    for root in roots:
        if not Path(root).is_dir():
            continue
        def onerror(error):
            errors.append(str(error))
        for current, directories, files in os.walk(root, followlinks=False, onerror=onerror):
            relative = Path(current).relative_to(root)
            level = len(relative.parts)
            directories[:] = sorted(directory for directory in directories if directory not in
                                     ("node_modules", ".git", "__pycache__", "site-packages", "dist-packages"))
            if "pyvenv.cfg" in files:
                environments.append(current)
            if level > 0:
                entries.append({"path": current, "type": "directory", "version_known": False})
            for name in sorted(files):
                file = Path(current) / name
                if file.is_file() and os.access(str(file), os.X_OK):
                    entries.append({"path": str(file), "type": "executable", "version_known": False})
                if len(entries) >= maximum:
                    return {"status": "partial", "items": entries[:maximum],
                            "errors": errors + ["Discovery limit reached"], "max_depth": depth}, environments
            if len(entries) >= maximum:
                return {"status": "partial", "items": entries[:maximum],
                        "errors": errors + ["Discovery limit reached"], "max_depth": depth}, environments
            if level >= depth:
                directories[:] = []
    return {"status": "partial" if errors else "ok", "items": entries,
            "errors": errors, "max_depth": depth}, environments


def python_packages(venvs):
    locations = set(["/usr/lib/python3/dist-packages"])
    locations.update(value for key, value in sysconfig.get_paths().items() if key in ("purelib", "platlib"))
    locations.update(glob.glob("/usr/local/lib/python*/site-packages"))
    locations.update(glob.glob("/usr/local/lib/python*/dist-packages"))
    errors, packages = [], []
    for venv in sorted(set(venvs)):
        libraries = glob.glob(str(Path(venv) / "lib/python*/site-packages"))
        libraries += glob.glob(str(Path(venv) / "lib64/python*/site-packages"))
        if not libraries:
            errors.append("No site-packages found: " + venv)
        locations.update(libraries)
    for location in sorted(locations):
        directory = Path(location)
        if not directory.exists():
            continue
        try:
            metadata = sorted(directory.glob("*.dist-info/METADATA"))
            for egg in directory.glob("*.egg-info"):
                metadata.append(egg / "PKG-INFO" if egg.is_dir() else egg)
            for filename in metadata:
                parsed = Parser().parsestr(filename.read_text(errors="replace"), headersonly=True)
                if parsed.get("Name") and parsed.get("Version"):
                    packages.append({"name": parsed["Name"], "version": parsed["Version"], "location": location})
                else:
                    errors.append("Missing package name/version: " + str(filename))
        except OSError as error:
            errors.append(str(error))
    return {"status": "partial" if errors else "ok", "items": packages,
            "errors": errors, "searched_locations": sorted(locations)}


def table(text, columns, skip_header=False):
    lines = text.splitlines()[1:] if skip_header else text.splitlines()
    return [dict(zip(columns, line.split(None, len(columns) - 1))) for line in lines if line.strip()]


def json_lines(text):
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def npm_packages(text):
    data = json.loads(text)
    return [{"name": name, "version": item.get("version", "unknown")}
            for name, item in sorted(data.get("dependencies", {}).items())]


def inventory(options):
    discovery, detected_venvs = discover(options.get("discovery_roots", ["/opt", "/usr/local", "/srv"]))
    timeout = int(options.get("command_timeout", 60))
    docker = ["docker", "--host", "unix:///var/run/docker.sock"]
    components = {
        "python": python_packages(options.get("venv_paths", []) + detected_venvs),
        "npm_global": optional(["npm", "ls", "-g", "--depth=0", "--json"], npm_packages, timeout),
        "snap": optional(["snap", "list"], lambda text: table(text,
            ["name", "version", "revision", "tracking", "publisher", "notes"], True), timeout),
        "flatpak": optional(["flatpak", "list", "--columns=application,version,branch,arch"],
            lambda text: [dict(zip(["name", "version", "branch", "architecture"], line.split("\t")))
                          for line in text.splitlines() if line.strip()], timeout),
        "docker_images": optional(docker + ["image", "ls", "--no-trunc", "--digests", "--format", "{{json .}}"], json_lines, timeout),
        "docker_containers": optional(docker + ["ps", "-a", "--no-trunc", "--format",
            '{"id":{{json .ID}},"image":{{json .Image}},"name":{{json .Names}},"state":{{json .State}}}'], json_lines, timeout),
        "podman_images": optional(["podman", "--remote=false", "images", "--no-trunc", "--digests", "--format", "json"],
            lambda text: [{key: item.get(key) for key in ("Id", "Names", "Digest", "RepoDigests")}
                          for item in json.loads(text)], timeout),
        "podman_containers": optional(["podman", "--remote=false", "ps", "-a", "--no-trunc", "--format", "json"],
            lambda text: [{key: item.get(key) for key in ("Id", "Image", "ImageID", "Names", "State")}
                          for item in json.loads(text)], timeout),
    }
    probes = [{"name": name, "argv": argv} for name, argv in [
        ("python3", ["python3", "--version"]), ("openssl", ["openssl", "version"]),
        ("java", ["java", "-version"]), ("node", ["node", "--version"]),
        ("go", ["go", "version"]), ("docker", ["docker", "--version"]),
        ("podman", ["podman", "--version"])]]
    probes += options.get("custom_probes", [])
    versions = []
    for probe in probes:
        argv = probe.get("argv")
        if not isinstance(argv, list) or not argv or not all(isinstance(arg, str) for arg in argv):
            raise AgentError("Every custom probe requires a nonempty argv list of strings")
        result = run(argv, timeout)
        versions.append({"name": probe["name"], "argv": argv,
                         "status": "ok" if result["rc"] == 0 else "not_available" if result["rc"] == 127 else "error",
                         "version_raw": (result["stdout"] + result["stderr"]).strip()})
    return {"schema_version": 1, "collected_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "os": os_info(), "kernel": platform.release(), "architecture": platform.machine(),
            "dpkg": dpkg_packages(), "components": components, "version_probes": versions,
            "unmanaged_candidates": discovery,
            "coverage_notes": [
                "DPKG includes installed packages, including held packages, exact binary and source versions.",
                "Language dependencies: visible Python metadata, configured/discovered venvs and global npm only.",
                "User-specific/rootless installs require a separate run as their owning user.",
                "Container images are references/digests; packages INSIDE images are NOT scanned.",
                "Executable discovery is bounded and does not prove a complete unmanaged-software inventory.",
                "No vulnerability verdict is generated from package versions alone."]}


def health(options):
    services = {}
    for service in options.get("critical_services", []):
        if not isinstance(service, str) or not re.fullmatch(r"[A-Za-z0-9_@.:-]+", service):
            raise AgentError("Invalid service name")
        result = run(["systemctl", "is-active", "--", service])
        services[service] = {"active": result["rc"] == 0, "state": result["stdout"].strip()}
    failed = optional(["systemctl", "--failed", "--no-legend", "--plain", "--no-pager"],
                      lambda text: [line.split()[0] for line in text.splitlines() if line.strip()])
    checks = {}
    for check in options.get("http_checks", []):
        url = check.get("url", "")
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
            raise AgentError("HTTP checks require an http(s) URL without embedded credentials")
        name = check.get("name") or parsed.hostname + parsed.path
        expected = int(check.get("expected_status", 200))
        timeout = max(1, min(int(check.get("timeout", 10)), 60))
        try:
            with urllib.request.urlopen(url, timeout=timeout) as response:
                code = response.status
            checks[name] = {"ok": code == expected, "status": code, "expected": expected}
        except urllib.error.HTTPError as error:
            checks[name] = {"ok": error.code == expected, "status": error.code, "expected": expected}
        except (OSError, urllib.error.URLError, ValueError):
            # URLs and exception messages can contain secrets; retain the check name only.
            checks[name] = {"ok": False, "status": None, "expected": expected}
    result = {"critical_services": services, "failed_units": failed, "http_checks": checks,
              "reboot_required_marker": Path("/var/run/reboot-required").exists(), "kernel": platform.release()}
    if any(not item["active"] for item in services.values()):
        raise AgentError("A critical service is not active", result)
    if any(not item["ok"] for item in checks.values()):
        raise AgentError("An application HTTP check failed", result)
    return result


def apt_argv(options, simulate=False):
    mode = options.get("upgrade_mode", "safe")
    if mode not in ("safe", "dist"):
        raise AgentError("upgrade_mode must be safe or dist")
    command = ["apt-get", "-o", "DPkg::Lock::Timeout={}".format(int(options.get("lock_timeout", 300))),
               "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold",
               "--no-remove", "--simulate" if simulate else "--yes"]
    return command + ["upgrade" if mode == "safe" else "dist-upgrade"]


def preflight(options, installing=False):
    info = os_info()
    if installing and not options.get("confirmed", False):
        raise AgentError("Explicit update confirmation is required")
    if installing and os.geteuid() != 0:
        raise AgentError("Updates require root privileges (sudo/become)")
    if installing and options.get("reboot_requested", False) and sys.version_info < (3, 9):
        raise AgentError("Automatic reboot with this ansible-core requires target Python 3.9+; omit --reboot and reboot manually")
    is_astra = bool(info["astra_version"]) or info["id"] in ("astra", "astralinux")
    if installing and is_astra and not options.get("allow_astra_package_updates", False):
        raise AgentError("For Astra package updates explicitly select --astra-apt; release migrations require a separate vendor procedure")
    audit = required(["dpkg", "--audit"])
    if audit.strip():
        raise AgentError("dpkg --audit is not clean", {"audit": audit})
    disks = {}
    for path, minimum in (("/", options.get("min_root_free_mb", 2048)),
                          ("/var", options.get("min_root_free_mb", 2048)),
                          ("/boot", options.get("min_boot_free_mb", 200))):
        if Path(path).exists():
            free = shutil.disk_usage(path).free // (1024 * 1024)
            disks[path] = free
            if free < int(minimum):
                raise AgentError("Insufficient free space on {}: {} MiB".format(path, free))
    return {"os": info, "free_mb": disks, "health": health(options),
            "held_packages": required(["apt-mark", "showhold"]).splitlines()}


def plan(options):
    result = preflight(options, installing=options.get("apply_requested", False))
    if options.get("refresh_cache", False):
        refreshed = run(["apt-get", "-o", "APT::Update::Error-Mode=any", "update"], timeout=None)
        # Old APT may ignore Error-Mode and still exit 0 after a failed download.
        warnings = refreshed["stderr"] + refreshed["stdout"]
        if refreshed["rc"] or re.search(r"(?:Failed to fetch|Some index files failed|Could not resolve|Temporary failure resolving)", warnings):
            raise AgentError("APT index refresh failed; refusing to use partially refreshed indexes", refreshed)
        result["cache_refresh"] = refreshed
    result["simulation"] = required(apt_argv(options, simulate=True), timeout=None)
    result["cache_refreshed"] = bool(options.get("refresh_cache", False))
    result["fingerprint"] = plan_fingerprint(result["simulation"], options)
    result["apt_policy"] = run(["apt-cache", "policy"])
    return result


def plan_fingerprint(simulation, options):
    operations = sorted(line.strip() for line in simulation.splitlines()
                        if line.startswith(("Inst ", "Conf ", "Remv ")))
    payload = {"mode": options.get("upgrade_mode", "safe"), "operations": operations}
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


def update(options):
    before = preflight(options, installing=True)
    packages_before = dpkg_packages()
    # Recalculate immediately before apply; fail on a removal request or resolver error.
    simulation = required(apt_argv(options, simulate=True), timeout=None)
    approved = options.get("approved_plan_fingerprint")
    if approved and plan_fingerprint(simulation, options) != approved:
        raise AgentError("APT plan changed after approval; run the preview again and approve the new plan",
                         {"simulation": simulation})
    # Do not kill apt/dpkg by a timeout in the middle of a transaction.
    transaction = run(apt_argv(options), timeout=None)
    result = {"before": before, "simulation": simulation, "transaction": transaction}
    if transaction["rc"]:
        raise AgentError("APT update failed; inspect the transaction log and dpkg --audit", result)
    packages_after = dpkg_packages()
    result["packages_changed"] = packages_before != packages_after
    result["changed_packages"] = [package for package in packages_after if package not in packages_before]
    result["audit"] = required(["dpkg", "--audit"])
    if result["audit"].strip():
        raise AgentError("dpkg --audit reported a problem after update", result)
    try:
        result["after"] = health(options)
    except AgentError as error:
        result["after"] = error.details
        raise AgentError(str(error), result)
    old_failed = set(before["health"]["failed_units"]["items"])
    new_failed = set(result["after"]["failed_units"]["items"]) - old_failed
    if new_failed:
        raise AgentError("New failed systemd units: " + ", ".join(sorted(new_failed)), result)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("inventory", "plan", "update", "health"))
    parser.add_argument("--options", required=True)
    args = parser.parse_args()
    try:
        options = json.loads(base64.b64decode(args.options).decode("utf-8"))
        result = {"inventory": inventory, "plan": plan, "update": update, "health": health}[args.action](options)
        print(json.dumps(redact(result), ensure_ascii=True))
    except Exception as error:
        result = {"status": "failed", "error": str(error), "details": getattr(error, "details", {})}
        print(json.dumps(redact(result), ensure_ascii=True))
        print(redact(str(error)), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
