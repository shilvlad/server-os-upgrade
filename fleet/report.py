"""Aggregate local inventories and export a deliberately small review dataset."""
import csv
import json
import os
from pathlib import Path

from display import human_models, save_human_reports


def save_json(path, data):
    with path.open("w") as stream:
        os.fchmod(stream.fileno(), 0o600)
        json.dump(data, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def cell(value):
    # Spreadsheet formula protection for package/probe names controlled by a host.
    text = str(value)
    return "'" + text if text.lstrip().startswith(("=", "+", "-", "@")) else text


def md(value):
    return str(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def build_reports(directory):
    directory = Path(directory)
    hosts = {}
    phases = {"before": 0, "inventory": 1, "after": 2}
    for filename in sorted((directory / "hosts").glob("*.json")):
        item = json.loads(filename.read_text())
        if item.get("report_type") != "inventory":
            continue
        host = item["host"]
        if host not in hosts or phases[item["phase"]] > phases[hosts[host]["phase"]]:
            hosts[host] = item
    status_file = directory / "run-status.json"
    status = json.loads(status_file.read_text()) if status_file.exists() else {}
    run_file = directory / "run.json"
    expected = json.loads(run_file.read_text()).get("expected_hosts", []) if run_file.exists() else []
    save_json(directory / "inventory.json", {"hosts": hosts, "ansible_status": status})
    review = {"schema_version": 1, "assessment": "not_performed", "hosts": [], "limitations": [
        "Use vendor advisories and exact distribution/source versions; upstream-version matches are not proof.",
        "Missing collectors/hosts do not mean absence of software or vulnerabilities.",
        "Container digests identify images; their internal packages need separate SBOM/image scans.",
        "Review custom probe output before sharing. No data is uploaded automatically."]}
    with (directory / "packages.csv").open("w", newline="") as stream:
        os.fchmod(stream.fileno(), 0o600)
        writer = csv.writer(stream)
        writer.writerow(["host", "os", "os_version", "name", "version", "architecture", "source_name", "source_version"])
        for number, (host, item) in enumerate(sorted(hosts.items()), 1):
            data = item["data"]
            for package in data["dpkg"]:
                writer.writerow([cell(value) for value in [host, data["os"]["id"], data["os"]["version_id"],
                    package["name"], package["version"], package["architecture"], package["source_name"], package["source_version"]]])
            gaps = [name + ": " + component["status"] for name, component in data["components"].items()
                    if component["status"] != "ok"]
            if data["unmanaged_candidates"]["status"] != "ok":
                gaps.append("unmanaged_candidates: partial")
            outcome = status.get(host, {})
            state = "ошибка" if outcome.get("failures", 0) or outcome.get("unreachable", 0) else "OK" if outcome else "нет статуса"
            components = {}
            for name in ("python", "npm_global", "snap", "flatpak"):
                component = data["components"][name]
                components[name] = {"status": component["status"], "items": [
                    {key: package.get(key, "") for key in ("name", "version")}
                    for package in component["items"]]}
            images = []
            for name in ("docker_images", "podman_images"):
                for image in data["components"][name]["items"]:
                    digest = image.get("Digest") or image.get("digest") or ""
                    images.append({"collector": name, "image_id": image.get("ID") or image.get("Id"),
                                   "digest": digest.rsplit("@", 1)[-1]})
            review["hosts"].append({"host_id": "host-{:04d}".format(number), "os": data["os"],
                "kernel": data["kernel"], "architecture": data["architecture"], "collected_at": data["collected_at"],
                "dpkg": data["dpkg"], "components": components, "container_images": images,
                "version_probes": [{"name": probe["name"], "status": probe["status"], "version_raw": probe["version_raw"]}
                                   for probe in data["version_probes"]], "coverage_notes": data["coverage_notes"],
                "unmanaged_versions_unknown": len(data["unmanaged_candidates"]["items"]),
                "collection_gaps": gaps, "snapshot_phase": item["phase"], "run_status": state})
    missing = sorted((set(expected) | set(status)) - {"localhost"} - set(hosts))
    review["missing_host_count"] = len(missing)
    review["run_incomplete"] = bool(missing or not status or any(
        value.get("failures", 0) or value.get("unreachable", 0) for value in status.values()))
    metadata = json.loads(run_file.read_text()) if run_file.exists() else {}
    action = metadata.get("action", "inventory")
    if metadata.get("check_mode") and action == "update":
        action = "plan"
    models = human_models(directory, hosts)
    review["run_incomplete"] = review["run_incomplete"] or any(model["state"] == "ОШИБКА" for model in models.values())
    save_json(directory / "review.json", review)
    text = save_human_reports(directory, models, action)
    return {"hosts": hosts, "missing_hosts": missing, "complete": not review["run_incomplete"] and
            bool(models) and all(model["state"] != "ОШИБКА" for model in models.values()),
            "models": models, "text": text}
