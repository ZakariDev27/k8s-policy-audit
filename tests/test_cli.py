import json
import os
import stat
from pathlib import Path

import pytest

from kpaudit.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, main
from kpaudit.loader import LoadError, load_cluster, load_paths

DEMO = Path(__file__).resolve().parent.parent / "demo"
INSECURE = str(DEMO / "insecure")
HARDENED = str(DEMO / "hardened")


def test_exit_codes(capsys):
    assert main(["scan", INSECURE]) == EXIT_FINDINGS
    assert main(["scan", HARDENED]) == EXIT_OK
    assert main(["scan", INSECURE, "--fail-on", "never"]) == EXIT_OK
    assert main(["scan", "does-not-exist"]) == EXIT_ERROR
    capsys.readouterr()


def test_json_output_and_filters(capsys):
    main(["scan", INSECURE, "-f", "json", "-c", "network", "--min-severity", "high"])
    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["total"] == len(report["findings"]) > 0
    assert {f["category"] for f in report["findings"]} == {"network"}
    assert {f["severity"] for f in report["findings"]} <= {"high", "critical"}


def test_namespace_filter(capsys):
    main(["scan", INSECURE, "-f", "json", "-n", "billing-insecure"])
    findings = json.loads(capsys.readouterr().out)["findings"]
    assert findings
    for f in findings:
        assert f["namespace"] == "billing-insecure" or f["name"] == "billing-insecure"


def test_markdown_report_to_file(tmp_path, capsys):
    out = tmp_path / "report.md"
    main(["scan", INSECURE, "-f", "markdown", "-o", str(out)])
    text = out.read_text()
    assert text.startswith("# Kubernetes policy audit")
    assert "## Network firewall" in text
    capsys.readouterr()


def test_checks_command(capsys):
    assert main(["checks"]) == EXIT_OK
    assert "NET001" in capsys.readouterr().out


def test_loader_expands_lists_and_ignores_non_objects(tmp_path):
    (tmp_path / "list.json").write_text(
        json.dumps(
            {
                "apiVersion": "v1",
                "kind": "List",
                "items": [
                    {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "a"}},
                    {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "b"}},
                ],
            }
        )
    )
    (tmp_path / "values.yaml").write_text("replicas: 3\n")
    (tmp_path / "notes.txt").write_text("not a manifest")
    assert [o["metadata"]["name"] for o in load_paths([str(tmp_path)])] == ["a", "b"]


def _fake_kubectl(tmp_path: Path, script: str) -> str:
    path = tmp_path / "kubectl"
    path.write_text("#!/bin/sh\n" + script)
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return str(path)


def test_live_scan_reads_through_kubectl(tmp_path, monkeypatch, capsys):
    """A stand-in kubectl proves the live path only runs `get` and survives denials."""
    log = tmp_path / "calls.log"
    kubectl = _fake_kubectl(
        tmp_path,
        f"""echo "$@" >> {log}
case "$*" in
  *"get pods "*)
    echo '{{"kind":"List","apiVersion":"v1","items":[{{"apiVersion":"v1","kind":"Pod",
      "metadata":{{"name":"p","namespace":"team"}},
      "spec":{{"containers":[{{"name":"c","image":"x"}}]}}}}]}}' ;;
  *"get clusterroles"*)
    echo 'Error from server (Forbidden): clusterroles is forbidden' >&2; exit 1 ;;
  *)
    echo '{{"kind":"List","apiVersion":"v1","items":[]}}' ;;
esac
""",
    )
    objects, warnings = load_cluster(kubectl=kubectl)
    assert [o["kind"] for o in objects] == ["Pod"]
    assert len(warnings) == 1 and "Forbidden" in warnings[0]
    calls = log.read_text().splitlines()
    assert calls and all(call.startswith("get ") for call in calls)

    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")
    assert main(["scan", "-f", "json", "--fail-on", "never"]) == EXIT_OK
    captured = capsys.readouterr()
    assert "NET001" in {f["check_id"] for f in json.loads(captured.out)["findings"]}
    assert "warning: could not read clusterroles" in captured.err


def test_live_scan_without_kubectl_fails_clearly():
    with pytest.raises(LoadError, match="not found on PATH"):
        load_cluster(kubectl="kubectl-definitely-missing")


def test_ignore_flag(capsys):
    main(["scan", INSECURE, "-f", "json", "--ignore", "STO008,api008", "--ignore", "NET002"])
    report = json.loads(capsys.readouterr().out)
    assert not {"STO008", "API008", "NET002"} & {f["check_id"] for f in report["findings"]}
    assert report["suppressed"] == 9

    with pytest.raises(SystemExit):
        main(["scan", INSECURE, "--ignore", "NOPE01"])
    assert "unknown check ID" in capsys.readouterr().err
