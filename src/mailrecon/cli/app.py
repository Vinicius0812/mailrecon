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
from mailrecon.services.profile_check_service import ProfileCheckService
from mailrecon.services.refinement_state_service import RefinementStateService
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
    profile_check_service = ProfileCheckService(timeout=settings.http_timeout)
    hibp_service = HibpService(
        api_key=settings.hibp_api_key,
        timeout=settings.http_timeout,
        enabled=use_hibp,
    )
    recon_service = ReconService(dns_service=dns_service, hibp_service=hibp_service)
    return InvestigationService(
        recon_service=recon_service,
        dns_service=dns_service,
        profile_check_service=profile_check_service,
    )


def _build_refinement_state_service() -> RefinementStateService:
    """Compose the helper that stores temporary refinement data."""
    return RefinementStateService()


def _run_investigation(
    query: InvestigationInput,
    use_hibp: bool,
    check_public_profiles: bool,
    lab_profile_scenario: str | None,
    json_out: Path | None,
    md_out: Path | None,
    reveal_emails: bool,
    markdown_language: str,
) -> None:
    """Execute the investigation flow shared by CLI and interactive mode."""
    investigation_service = _build_investigation_service(use_hibp=use_hibp)
    refinement_state_service = _build_refinement_state_service()

    try:
        result = investigation_service.investigate(
            query,
            check_public_profiles=check_public_profiles,
            lab_profile_scenario=lab_profile_scenario,
            progress_callback=_show_progress,
        )
        result = refinement_state_service.apply_and_store(
            query,
            result,
            run_options={
                "use_hibp": use_hibp,
                "check_public_profiles": check_public_profiles,
                "lab_profile_scenario": lab_profile_scenario,
            },
        )
    except ValueError as exc:
        typer.secho(f"Invalid investigation input: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc
    except Exception as exc:
        typer.secho(f"Investigation failed: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc

    typer.echo(render_investigation_summary(result, mask_sensitive=not reveal_emails))
    typer.secho(
        f"Refinement file ready at: {result.refinement_file_path}",
        fg=typer.colors.BLUE,
    )
    if result.refinement_excluded_links:
        typer.secho(
            f"Applied refinement exclusions: {len(result.refinement_excluded_links)} link(s).",
            fg=typer.colors.YELLOW,
        )

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
        result = recon_service.analyze_email(email, progress_callback=_show_progress)
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
    check_public_profiles: bool = typer.Option(
        False,
        "--check-public-profiles",
        help="Resolve only public profile URLs already generated by the investigation.",
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
    query = InvestigationInput(
        names=name or [],
        emails=email or [],
        usernames=username or [],
        domains=domain or [],
        organizations=organization or [],
        contexts=context or [],
        candidate_emails=candidate_email or [],
    )
    _run_investigation(
        query=query,
        use_hibp=use_hibp,
        check_public_profiles=check_public_profiles,
        lab_profile_scenario=None,
        json_out=json_out,
        md_out=md_out,
        reveal_emails=reveal_emails,
        markdown_language=markdown_language,
    )


@app.command("interactive")
def interactive(
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
    """Guide an investigation step by step with interactive prompts."""
    typer.secho("MailRecon interactive investigation", fg=typer.colors.CYAN)
    typer.echo("Press Enter to skip any optional field.")

    names = _prompt_list("Name")
    emails = _prompt_list("Email")
    usernames = _prompt_list("Username")
    domains = _prompt_list("Domain")
    organizations = _prompt_list("Organization")
    contexts = _prompt_list("Context")
    candidate_emails = _prompt_list("Candidate email")

    query = InvestigationInput(
        names=names,
        emails=emails,
        usernames=usernames,
        domains=domains,
        organizations=organizations,
        contexts=contexts,
        candidate_emails=candidate_emails,
    )

    chosen_json_out = json_out
    chosen_md_out = md_out
    chosen_markdown_language = markdown_language

    if chosen_json_out is None and typer.confirm("Save the investigation as JSON?", default=False):
        chosen_json_out = Path(
            typer.prompt(
                "JSON output path",
                default="reports/investigation.json",
                show_default=True,
            )
        )

    if chosen_md_out is None and typer.confirm("Save the investigation as Markdown?", default=True):
        chosen_md_out = Path(
            typer.prompt(
                "Markdown output path",
                default="reports/investigation.md",
                show_default=True,
            )
        )
        chosen_markdown_language = typer.prompt(
            "Markdown language (en or pt-br)",
            default=markdown_language,
            show_default=True,
        )

    _run_investigation(
        query=query,
        use_hibp=use_hibp,
        check_public_profiles=typer.confirm(
            "Resolve generated public profile URLs with safe public-only checks?",
            default=False,
        ),
        lab_profile_scenario=None,
        json_out=chosen_json_out,
        md_out=chosen_md_out,
        reveal_emails=reveal_emails,
        markdown_language=chosen_markdown_language,
    )


@app.command("lab-admin")
def lab_admin(
    handle: str = typer.Option(..., "--handle", help="Username or handle seed."),
    domain: str = typer.Option("", "--domain", help="Optional domain seed."),
    email: str = typer.Option("", "--email", help="Optional email seed."),
    scenario: str = typer.Option(
        "found",
        "--scenario",
        help="Lab-only profile scenario: found, not-found, ambiguous, blocked, or rate-limited.",
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
) -> None:
    """Run a lab-only simulation of public profile resolution states.

    This command exists for academic practice in a controlled environment.
    In real use, keep automation limited to public pages or official APIs and
    avoid login, recovery, or credential-related flows.
    """
    query = InvestigationInput(
        usernames=[handle],
        domains=[domain] if domain else [],
        emails=[email] if email else [],
        contexts=["lab-only public profile simulation"],
    )
    _run_investigation(
        query=query,
        use_hibp=False,
        check_public_profiles=True,
        lab_profile_scenario=scenario,
        json_out=json_out,
        md_out=md_out,
        reveal_emails=reveal_emails,
        markdown_language=markdown_language,
    )


@app.command("rerun-last")
def rerun_last(
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
) -> None:
    """Repeat the latest saved investigation using the refinement file state."""
    refinement_state_service = _build_refinement_state_service()

    try:
        query, run_options = refinement_state_service.load_last_investigation()
    except ValueError as exc:
        typer.secho(f"Unable to rerun the last investigation: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc

    typer.secho("Reloading the latest saved investigation parameters...", fg=typer.colors.CYAN)
    _run_investigation(
        query=query,
        use_hibp=bool(run_options.get("use_hibp", True)),
        check_public_profiles=bool(run_options.get("check_public_profiles", False)),
        lab_profile_scenario=_coerce_optional_string(run_options.get("lab_profile_scenario")),
        json_out=json_out,
        md_out=md_out,
        reveal_emails=reveal_emails,
        markdown_language=markdown_language,
    )


def _prompt_list(label: str) -> list[str]:
    """Prompt the user for a comma-separated list."""
    raw_value = typer.prompt(f"{label}(s)", default="", show_default=False)
    return [item.strip() for item in raw_value.split(",") if item.strip()]


def _show_progress(message: str) -> None:
    """Show a simple progress marker so the terminal does not look stuck."""
    typer.secho(f"[...] {message}", fg=typer.colors.BLUE)


def _coerce_optional_string(value: object) -> str | None:
    """Convert persisted JSON values back into optional strings safely."""
    if isinstance(value, str) and value.strip():
        return value
    return None
