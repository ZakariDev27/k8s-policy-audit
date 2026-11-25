"""The demos shown in the README must stay true as the tool changes."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from kpaudit.cli import main

ROOT = Path(__file__).resolve().parent.parent

# (file, api, storage, network): the table in the README's walkthrough demo.
WALKTHROUGH = [
    ("0-insecure.yaml", 4, 4, 2),
    ("1-network.yaml", 4, 4, 0),
    ("2-storage.yaml", 4, 0, 0),
    ("3-api.yaml", 0, 0, 0),
]


@pytest.fixture(autouse=True)
def in_repo_root(monkeypatch):
    # Reports print the path they were given, so use the paths the README uses.
    monkeypatch.chdir(ROOT)


def scan_text(capsys, *args: str) -> str:
    main(["scan", *args, "--fail-on", "never"])
    return capsys.readouterr().out


@pytest.mark.parametrize("name,api,storage,network", WALKTHROUGH)
def test_walkthrough_counts(capsys, name, api, storage, network):
    report = json.loads(scan_text(capsys, f"demo/walkthrough/{name}", "-f", "json"))
    assert report["summary"]["by_category"] == {
        "api": api, "storage": storage, "network": network
    }


def test_walkthrough_gate_exit_codes(capsys):
    assert main(["scan", "demo/walkthrough/0-insecure.yaml"]) == 2
    assert main(["scan", "demo/walkthrough/2-storage.yaml"]) == 0
    assert main(["scan", "demo/walkthrough/2-storage.yaml", "--fail-on", "medium"]) == 2
    assert main(["scan", "demo/walkthrough/3-api.yaml", "--fail-on", "low"]) == 0
    capsys.readouterr()


def test_sample_report_is_current(capsys):
    expected = scan_text(capsys, "demo/insecure", "-f", "markdown")
    assert (ROOT / "docs" / "sample-report.md").read_text() == expected, (
        "regenerate with: kpaudit scan demo/insecure -f markdown --fail-on never "
        "-o docs/sample-report.md"
    )


def render(command: str, text: str) -> str:
    return subprocess.run(
        [sys.executable, "scripts/render_terminal_svg.py", command],
        input=text, capture_output=True, text=True, check=True,
    ).stdout


def test_screenshots_are_current(capsys):
    insecure = scan_text(capsys, "demo/insecure", "--min-severity", "high")
    hardened = scan_text(capsys, "demo/hardened")
    images = ROOT / "docs" / "images"
    assert (images / "scan-insecure.svg").read_text() == render(
        "kpaudit scan demo/insecure --min-severity high", insecure
    )
    assert (images / "scan-hardened.svg").read_text() == render(
        "kpaudit scan demo/hardened", hardened
    )

    transcript = []
    for index, (name, *_counts) in enumerate(WALKTHROUGH):
        if index:
            transcript += ["", f"$ kpaudit scan demo/walkthrough/{name} | tail -1"]
        output = scan_text(capsys, f"demo/walkthrough/{name}")
        transcript.append(output.rstrip("\n").split("\n")[-1])
    assert (images / "walkthrough.svg").read_text() == render(
        "kpaudit scan demo/walkthrough/0-insecure.yaml | tail -1", "\n".join(transcript) + "\n"
    )
