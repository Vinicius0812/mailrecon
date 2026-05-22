"""Typer application definitions."""

from pathlib import Path

import typer

from mailrecon.core.config import load_settings
from mailrecon.core.models import InvestigationInput
from mailrecon.reporting.console import render_investigation_summary, render_summary
from mailrecon.reporting.exporters import (
    export_investigation_markdown,
    export_json,
    export_markdown,
)
from mailrecon.services.dns_service import DnsService
from mailrecon.services.hibp_service import HibpService
from mailrecon.services.investigation_service import InvestigationService
from mailrecon.services.recon_service import ReconService

app = typer.Typer(
    help="Educational CLI for email recon and validation.",
    no_args_is_help=False,
    invoke_without_command=True,
)


@app.callback()
def main(ctx: typer.Context) -> None:
    """MailRecon command group."""
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit()


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


def _build_investigation_service(use_hibp: bool) -> InvestigationService:
    """Compose the services required by the investigation command."""
    settings = load_settings()
    dns_service = DnsService(timeout=settings.dns_timeout)
    hibp_service = HibpService(
        api_key=settings.hibp_api_key,
        timeout=settings.http_timeout,
        enabled=use_hibp,
    )
    recon_service = ReconService(dns_service=dns_service, hibp_service=hibp_service)
    return InvestigationService(recon_service=recon_service, dns_service=dns_service)


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


@app.command("investigate")
def investigate(
    name: list[str] | None = typer.Option(
        None,
        "--name",
        help="Name seed for the investigation. Repeat the option when needed.",
    ),
    email: list[str] | None = typer.Option(
        None,
        "--email",
        help="Email seed for the investigation. Repeat the option when needed.",
    ),
    username: list[str] | None = typer.Option(
        None,
        "--username",
        help="Username seed for the investigation. Repeat the option when needed.",
    ),
    domain: list[str] | None = typer.Option(
        None,
        "--domain",
        help="Domain seed for the investigation. Repeat the option when needed.",
    ),
    organization: list[str] | None = typer.Option(
        None,
        "--organization",
        help="Organization seed for the investigation. Repeat the option when needed.",
    ),
    context: list[str] | None = typer.Option(
        None,
        "--context",
        help="Context note that explains why the investigation is being opened.",
    ),
    candidate_email: list[str] | None = typer.Option(
        None,
        "--candidate-email",
        help="Explicit candidate email to retain during the investigation.",
    ),
    json_out: Path | None = typer.Option(
        None,
        "--json-out",
        help="Write the structured investigation result as JSON.",
    ),
    md_out: Path | None = typer.Option(
        None,
        "--md-out",
        help="Write the investigation report as Markdown.",
    ),
    markdown_language: str = typer.Option(
        "en",
        "--markdown-language",
        help="Markdown report language: en or pt-br.",
    ),
    reveal_emails: bool = typer.Option(
        False,
        "--reveal-emails",
        help="Show full email addresses in terminal summaries and Markdown reports.",
    ),
    use_hibp: bool = typer.Option(
        True,
        "--hibp/--no-hibp",
        help="Enable or disable Have I Been Pwned lookups.",
    ),
) -> None:
    """Run a reusable OSINT investigation focused on email pivots and evidence."""
    investigation_service = _build_investigation_service(use_hibp=use_hibp)
    query = InvestigationInput(
        names=name or [],
        emails=email or [],
        usernames=username or [],
        domains=domain or [],
        organizations=organization or [],
        contexts=context or [],
        candidate_emails=candidate_email or [],
    )

    try:
        result = investigation_service.investigate(query)
    except ValueError as exc:
        typer.secho(f"Invalid investigation input: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc
    except Exception as exc:
        typer.secho(f"Investigation failed: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc

    typer.echo(render_investigation_summary(result, mask_sensitive=not reveal_emails))

    if json_out is not None:
        export_path = export_json(result, json_out)
        typer.secho(f"JSON report saved to: {export_path}", fg=typer.colors.GREEN)

    if md_out is not None:
        export_path = export_investigation_markdown(
            result,
            md_out,
            mask_sensitive=not reveal_emails,
            language=markdown_language.lower(),
        )
        typer.secho(f"Markdown report saved to: {export_path}", fg=typer.colors.GREEN)
