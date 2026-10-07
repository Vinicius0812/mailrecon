"""CLI commands that never compose live services."""

from pathlib import Path

import typer

from mailrecon.cli.localization import LocalizedCommand, language, text
from mailrecon.core.i18n import translate
from mailrecon.core.platform_catalog import PLATFORMS
from mailrecon.reporting.console import _mask_text, _sanitize_terminal_text
from mailrecon.services.demo_service import generate_demo
from mailrecon.services.search_links_service import build_search_links


def register_offline_commands(app: typer.Typer) -> None:
    @app.command('sources', cls=LocalizedCommand)
    def sources() -> None:
        """List the owned source catalog without network requests."""
        typer.echo(text('cli.sources_notice'))
        typer.echo(text('cli.sources_columns'))
        for spec in PLATFORMS:
            mode = text('cli.source_api' if spec.api_template else 'cli.source_manual')
            typer.echo(f'{spec.name}\t{mode}\t{spec.rule_id}/{spec.rule_version}\t{spec.documentation_url or spec.profile_template}')

    @app.command('demo', cls=LocalizedCommand)
    def demo(
        output_dir: Path = typer.Option(Path('reports'), '--output-dir', help='Output directory for synthetic demo artifacts.'),
    ) -> None:
        """Generate synthetic JSON, Markdown and HTML without network or refinement."""
        try:
            paths = generate_demo(output_dir, language())
        except (OSError, ValueError) as exc:
            detail = translate(exc.args[0], language()) if exc.args else str(exc)
            typer.secho(text('cli.offline_failed', error=_sanitize_terminal_text(_mask_text(str(detail)))), fg=typer.colors.RED, err=True)
            raise typer.Exit(1) from exc
        typer.echo(text('cli.demo_notice'))
        for path in paths:
            typer.echo(_sanitize_terminal_text(_mask_text(str(path))))

    @app.command('search-links', cls=LocalizedCommand)
    def search_links(
        query: str = typer.Argument(..., help='Literal term for manual search links.'),
        organization: list[str] | None = typer.Option(None, '--organization', help='Organization seed for the investigation. Repeat the option when needed.'),
        domain: list[str] | None = typer.Option(None, '--domain', help='Domain seed for the investigation. Repeat the option when needed.'),
        context: list[str] | None = typer.Option(None, '--context', help='Context note that explains why the investigation is being opened.'),
        after: str | None = typer.Option(None, '--after', help='Initial search date (YYYY-MM-DD).'),
        before: str | None = typer.Option(None, '--before', help='Final search date (YYYY-MM-DD).'),
        file_type: str | None = typer.Option(None, '--file-type', help='Manual search file type: pdf, docx, xlsx, pptx or txt.'),
        reveal_emails: bool = typer.Option(False, '--reveal-emails', help='Show full email addresses in terminal summaries and Markdown reports.'),
    ) -> None:
        """Compose manual search links offline; links are not findings."""
        try:
            links = build_search_links(query, organizations=organization, domains=domain, contexts=context,
                                       after=after, before=before, file_type=file_type)
        except ValueError as exc:
            typer.secho(text('cli.offline_failed', error=translate(exc.args[0], language())), fg=typer.colors.RED, err=True)
            raise typer.Exit(1) from exc
        typer.echo(text('cli.search_notice'))
        for site, url in links:
            if not reveal_emails:
                # Rebuild with masked input instead of hiding full emails in encoded URLs.
                from urllib.parse import parse_qs, urlencode, urlsplit
                parsed = urlsplit(url)
                expression = parse_qs(parsed.query)['q'][0]
                url = 'https://www.google.com/search?' + urlencode({'q': _mask_text(expression)})
            typer.echo(_sanitize_terminal_text(f'{site}\t{url}'))
