"""Keep documented CLI examples runnable without external collection."""

from pathlib import Path
import shlex

import pytest
from typer.testing import CliRunner

from mailrecon.cli.app import app
from tests.test_cli import FakeInvestigationService, FakeReconService, FakeRefinementStateService


@pytest.mark.parametrize("filename", ["README.md", "READMEeng.md"])
def test_readme_cli_examples_are_valid(filename, monkeypatch, tmp_path):
    root = Path(__file__).resolve().parents[1]
    source = (root / filename).read_text(encoding="utf-8")
    monkeypatch.setattr("mailrecon.cli.app._build_recon_service", lambda use_hibp: FakeReconService())
    monkeypatch.setattr("mailrecon.cli.app._build_investigation_service", lambda use_hibp: FakeInvestigationService())
    monkeypatch.setattr("mailrecon.cli.app._build_refinement_state_service", lambda: FakeRefinementStateService())
    runner = CliRunner()
    examples = [line for line in source.splitlines() if line.startswith("mailrecon ") or line.startswith(".\\.venv\\Scripts\\mailrecon.exe ")]
    assert len(examples) >= 10
    with runner.isolated_filesystem(temp_dir=tmp_path):
        for example in examples:
            arguments = shlex.split(example)[1:]
            answers = "\n".join(["", "person@example.com", "", "", "", "", "", "n", "n", "n"]) + "\n"
            result = runner.invoke(app, arguments, input=answers)
            assert result.exit_code == 0, (example, result.stdout, result.stderr, result.exception)
    other = "READMEeng.md" if filename == "README.md" else "README.md"
    assert f"]({other})" in source
