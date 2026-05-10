import json

from mailrecon.core.models import DnsLookupResult, HibpResult, ReconResult
from mailrecon.reporting.exporters import export_json, export_markdown


def build_result() -> ReconResult:
    return ReconResult(
        email="user@example.com",
        domain="example.com",
        is_valid=True,
        dns=DnsLookupResult(
            resolves=True,
            a_records=["93.184.216.34"],
            mx_records=["mx.example.com"],
        ),
        hibp=HibpResult(
            queried=False,
            status="missing_api_key",
        ),
    )


def test_export_json_writes_file(tmp_path) -> None:
    output = tmp_path / "report.json"

    export_json(build_result(), output)

    content = json.loads(output.read_text(encoding="utf-8"))
    assert content["email"] == "user@example.com"
    assert content["dns"]["resolves"] is True


def test_export_markdown_writes_file(tmp_path) -> None:
    output = tmp_path / "report.md"

    export_markdown(build_result(), output)

    content = output.read_text(encoding="utf-8")
    assert "# MailRecon Report" in content
    assert "- Email: user@example.com" in content
    assert "- HIBP queried: no" in content
