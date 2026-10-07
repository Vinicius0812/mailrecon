"""Typer application definitions."""

from pathlib import Path

import click
import typer

from mailrecon.cli.localization import (
    LocalizedCommand, LocalizedGroup, confirm, language,
    markdown_language as resolve_markdown_language, text,
)
from mailrecon.core.i18n import Language, msg, translate

from mailrecon.core.config import load_settings
from mailrecon.core.models import InvestigationInput
from mailrecon.reporting.console import (
    _mask_text,
    render_investigation_summary,
    render_smtp_lab_summary,
    render_summary,
)
from mailrecon.reporting.exporters import (
    export_investigation_markdown,
    export_json,
    export_markdown,
    export_smtp_lab_markdown,
)
from mailrecon.services.dns_service import DnsService
from mailrecon.services.hibp_service import HibpService
from mailrecon.services.investigation_service import InvestigationService
from mailrecon.services.profile_check_service import ProfileCheckService
from mailrecon.services.refinement_state_service import RefinementStateService
from mailrecon.services.recon_service import ReconService
from mailrecon.services.smtp_lab_service import SmtpLabValidationService

app = typer.Typer(
    cls=LocalizedGroup,
    help="Educational CLI for email recon and validation.",
    no_args_is_help=False,
    invoke_without_command=True,
)


@app.callback()
def main(
    ctx: typer.Context,
    language: Language = typer.Option(Language.PT_BR, "--language", help="Interface language: pt-br or en."),
) -> None:
    """MailRecon command group."""
    ctx.meta["language"] = language.value
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
    return RefinementStateService(language=language())


def _build_smtp_lab_validation_service() -> SmtpLabValidationService:
    """Compose the lab-only SMTP validation service."""
    settings = load_settings()
    return SmtpLabValidationService(
        enable_lab_smtp=settings.enable_lab_smtp,
        allow_hosts=settings.lab_smtp_allow_hosts,
        timeout=settings.lab_smtp_timeout,
    )


def _run_investigation(
    query: InvestigationInput,
    use_hibp: bool,
    check_public_profiles: bool,
    lab_profile_scenario: str | None,
    json_out: Path | None,
    md_out: Path | None,
    reveal_emails: bool,
    markdown_language: str | Language | None,
) -> None:
    """Execute the investigation flow shared by CLI and interactive mode."""
    resolve_markdown_language(markdown_language)
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
        typer.secho(text("cli.invalid_investigation", error=_error_detail(exc)), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc
    except Exception as exc:
        typer.secho(text("cli.investigation_failed", error=_error_detail(exc)), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc

    typer.echo(render_investigation_summary(result, mask_sensitive=not reveal_emails, language=language()))
    typer.secho(
        text("cli.refinement_ready", path=result.refinement_file_path),
        fg=typer.colors.BLUE,
    )
    if result.refinement_excluded_links:
        typer.secho(
            text("cli.exclusions", count=len(result.refinement_excluded_links)),
            fg=typer.colors.YELLOW,
        )

    if json_out is not None:
        export_path = _save_report(export_json, result, json_out, language=language())
        typer.secho(text("cli.json_saved", path=export_path), fg=typer.colors.GREEN)

    if md_out is not None:
        export_path = _save_report(
            export_investigation_markdown, result,
            md_out,
            mask_sensitive=not reveal_emails,
            language=resolve_markdown_language(markdown_language),
        )
        typer.secho(text("cli.markdown_saved", path=export_path), fg=typer.colors.GREEN)


@app.command("analyze", cls=LocalizedCommand)
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
    markdown_language: Language | None = typer.Option(
        None, "--markdown-language", help="Markdown report language: en or pt-br.",
    ),
) -> None:
    """Analyze an email address using public and permitted data sources."""
    recon_service = _build_recon_service(use_hibp=use_hibp)

    try:
        result = recon_service.analyze_email(email, progress_callback=_show_progress)
    except ValueError as exc:
        typer.secho(text("cli.invalid_input", error=_error_detail(exc)), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc
    except Exception as exc:
        typer.secho(text("cli.analysis_failed", error=_error_detail(exc)), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc

    typer.echo(render_summary(result, mask_sensitive=not reveal_emails, language=language()))

    if json_out is not None:
        export_path = _save_report(export_json, result, json_out, language=language())
        typer.secho(text("cli.json_saved", path=export_path), fg=typer.colors.GREEN)

    if md_out is not None:
        export_path = _save_report(
            export_markdown, result,
            md_out,
            mask_sensitive=not reveal_emails,
            language=resolve_markdown_language(markdown_language),
        )
        typer.secho(text("cli.markdown_saved", path=export_path), fg=typer.colors.GREEN)


@app.command("investigate", cls=LocalizedCommand)
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
    markdown_language: Language | None = typer.Option(
        None,
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


@app.command("interactive", cls=LocalizedCommand)
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
    markdown_language: Language | None = typer.Option(
        None,
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
    typer.secho(text("cli.interactive_title"), fg=typer.colors.CYAN)
    typer.echo(text("cli.skip"))

    names = _prompt_list("cli.name")
    emails = _prompt_list("cli.email")
    usernames = _prompt_list("cli.username")
    domains = _prompt_list("cli.domain")
    organizations = _prompt_list("cli.organization")
    contexts = _prompt_list("cli.context")
    candidate_emails = _prompt_list("cli.candidate_email")

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

    if chosen_json_out is None and confirm("cli.save_json", default=False):
        chosen_json_out = Path(
            typer.prompt(
                text("cli.json_path"),
                default="reports/investigation.json",
                show_default=True,
            )
        )

    if chosen_md_out is None and confirm("cli.save_markdown", default=True):
        chosen_md_out = Path(
            typer.prompt(
                text("cli.markdown_path"),
                default="reports/investigation.md",
                show_default=True,
            )
        )
        chosen_markdown_language = resolve_markdown_language(typer.prompt(
            text("cli.markdown_prompt"),
            default=resolve_markdown_language(markdown_language),
            show_default=True,
        ))

    _run_investigation(
        query=query,
        use_hibp=use_hibp,
        check_public_profiles=confirm(
            "cli.check_profiles",
            default=False,
        ),
        lab_profile_scenario=None,
        json_out=chosen_json_out,
        md_out=chosen_md_out,
        reveal_emails=reveal_emails,
        markdown_language=chosen_markdown_language,
    )


@app.command("lab-admin", cls=LocalizedCommand)
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
    markdown_language: Language | None = typer.Option(
        None,
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
        contexts=[msg("cli.lab_context")],
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


@app.command("lab-smtp-validate", cls=LocalizedCommand)
def lab_smtp_validate(
    email: str = typer.Argument(..., help="Lab email address to validate."),
    lab_domain: str = typer.Option(
        ...,
        "--lab-domain",
        help="Explicit lab domain that must match the email domain.",
    ),
    host: str = typer.Option(
        "127.0.0.1",
        "--host",
        help="Explicit lab SMTP host. MX discovery is intentionally not supported.",
    ),
    port: int = typer.Option(
        2525,
        "--port",
        min=1,
        max=65535,
        help="Explicit lab SMTP port.",
    ),
    transport: str = typer.Option(
        "mock",
        "--transport",
        help="Lab transport: mock, localhost, or private-lab.",
    ),
    check: list[str] | None = typer.Option(
        None,
        "--check",
        help="Lab SMTP check to run: vrfy, rcpt, or expn. Repeat up to --max-probes.",
    ),
    confirm_lab_only: bool = typer.Option(
        False,
        "--confirm-lab-only",
        help="Required for networked lab SMTP checks.",
    ),
    no_network: bool = typer.Option(
        False,
        "--no-network",
        help="Force mock-only execution and block networked transports.",
    ),
    max_probes: int = typer.Option(
        3,
        "--max-probes",
        min=1,
        max=3,
        help="Hard limit for requested lab SMTP probes.",
    ),
    json_out: Path | None = typer.Option(
        None,
        "--json-out",
        help="Write the lab SMTP result as JSON.",
    ),
    md_out: Path | None = typer.Option(
        None,
        "--md-out",
        help="Write the lab SMTP result as Markdown.",
    ),
    markdown_language: Language | None = typer.Option(
        None, "--markdown-language", help="Markdown report language: en or pt-br.",
    ),
) -> None:
    """Run lab-only SMTP validation with strict safety gates.

    This command is intentionally isolated from the normal recon workflow.
    Networked checks require MAILRECON_ENABLE_LAB_SMTP=1, --confirm-lab-only,
    an explicit lab host, and a matching --lab-domain.
    """
    service = _build_smtp_lab_validation_service()
    requested_checks = check or ["vrfy"]

    try:
        result = service.validate(
            email=email,
            lab_domain=lab_domain,
            host=host,
            port=port,
            transport=transport.lower(),
            checks=requested_checks,
            confirm_lab_only=confirm_lab_only,
            no_network=no_network,
            max_probes=max_probes,
        )
    except ValueError as exc:
        typer.secho(text("cli.invalid_smtp", error=_error_detail(exc)), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc
    except Exception as exc:
        typer.secho(text("cli.smtp_failed", error=_error_detail(exc)), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc

    typer.echo(render_smtp_lab_summary(result, language=language()))

    if json_out is not None:
        export_path = _save_report(export_json, result, json_out, language=language())
        typer.secho(text("cli.json_saved", path=export_path), fg=typer.colors.GREEN)

    if md_out is not None:
        export_path = _save_report(export_smtp_lab_markdown, result, md_out, language=resolve_markdown_language(markdown_language))
        typer.secho(text("cli.markdown_saved", path=export_path), fg=typer.colors.GREEN)

    if not result.safety_decision.allowed:
        raise typer.Exit(code=2)


@app.command("rerun-last", cls=LocalizedCommand)
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
    markdown_language: Language | None = typer.Option(
        None,
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
        typer.secho(text("cli.rerun_failed", error=_error_detail(exc)), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc

    typer.secho(text("cli.reload"), fg=typer.colors.CYAN)
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
    raw_value = typer.prompt(text("cli.list_prompt", label=text(label)), default="", show_default=False)
    return [item.strip() for item in raw_value.split(",") if item.strip()]


def _show_progress(message: str) -> None:
    """Show a simple progress marker so the terminal does not look stuck."""
    rendered = translate(message, language=language())
    typer.secho(f"[...] {_mask_for_display(rendered)}", fg=typer.colors.BLUE)


def _coerce_optional_string(value: object) -> str | None:
    """Convert persisted JSON values back into optional strings safely."""
    if isinstance(value, str) and value.strip():
        return value
    return None


def _error_detail(error: Exception) -> str:
    """Keep authored message metadata when an exception wraps it."""
    detail = error.args[0] if len(error.args) == 1 and isinstance(error.args[0], str) else str(error)
    return _mask_for_display(translate(detail, language=language()))


def _mask_for_display(value: str) -> str:
    ctx = click.get_current_context(silent=True)
    if ctx is not None and ctx.params.get("reveal_emails", False):
        return value
    return _mask_text(value)


def _save_report(exporter, result, output: Path, **options) -> Path:
    """Report filesystem failures without rerunning the investigation."""
    try:
        return exporter(result, output, **options)
    except (OSError, ValueError) as exc:
        message = text("cli.export_failed", path=output, error=_error_detail(exc))
        typer.secho(_mask_for_display(message), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc
