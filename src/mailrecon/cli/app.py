"""Typer application definitions."""

from pathlib import Path

import typer

from mailrecon.core.config import load_settings
from mailrecon.reporting.console import render_summary
from mailrecon.reporting.exporters import export_json, export_markdown
from mailrecon.services.dns_service import DnsService
from mailrecon.services.hibp_service import HibpService
from mailrecon.services.recon_service import ReconService

app = typer.Typer(
    help="Educational CLI for email recon and validation.",
    no_args_is_help=True,
)


def _build_recon_service(use_hibp: bool) -> ReconService:
    """Compose the services required by the main CLI command."""
    settings = load_settings()
    dns_service = DnsService(timeout=settings.dns_timeout)
    hibp_service = HibpService(
        api_key=settings.hibp_api_key,
        timeout=settings.http_timeout,
        enabled=use_hibp,
    )
    return ReconService(dns_service=dns_service, hibp_service=hibp_service)


@app.command("analyze")
def analyze(
    email: str = typer.Argument(..., help="Email address to analyze."),
    json_out: Path | None = typer.Option(
        None,
        "--json-out",
        help="Write the full result as JSON.",
    ),
    md_out: Path | None = typer.Option(
        None,
        "--md-out",
        help="Write the full result as Markdown.",
    ),
    use_hibp: bool = typer.Option(
        True,
        "--hibp/--no-hibp",
        help="Enable or disable Have I Been Pwned lookups.",
    ),
) -> None:
    """Analyze an email address using public and permitted data sources."""
    recon_service = _build_recon_service(use_hibp=use_hibp)

    try:
        result = recon_service.analyze_email(email)
    except ValueError as exc:
        typer.secho(f"Invalid input: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc
    except Exception as exc:
        typer.secho(f"Analysis failed: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc

    typer.echo(render_summary(result))

    if json_out is not None:
        export_path = export_json(result, json_out)
        typer.secho(f"JSON report saved to: {export_path}", fg=typer.colors.GREEN)

    if md_out is not None:
        export_path = export_markdown(result, md_out)
        typer.secho(f"Markdown report saved to: {export_path}", fg=typer.colors.GREEN)
