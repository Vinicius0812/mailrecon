"""Per-invocation CLI localization, including Click help and parser errors."""

import re

import click
from typer.core import TyperCommand, TyperGroup

from mailrecon.core.catalog_cli import CATALOG
from mailrecon.core.i18n import Language, localize_message, t
from mailrecon.reporting.console import _mask_text


def language(ctx: click.Context | None = None) -> str:
    ctx = ctx or click.get_current_context(silent=True)
    if ctx is None:
        return "pt-br"
    return ctx.find_root().meta.get("language", "pt-br")


def text(key: str, **parameters: object) -> str:
    return t(key, language=language(), **parameters)


def help_text(value: str, locale: str) -> str:
    for key, copy in CATALOG.items():
        if value == copy["en"]:
            return t(key, language=locale)
    return value


def markdown_language(value: str | Language | None) -> str:
    if value is None:
        return language()
    selected = value.value if isinstance(value, Language) else value
    if selected not in {"pt-br", "en"}:
        raise click.BadParameter(text("cli.invalid_language"), param_hint="--markdown-language")
    return selected


def confirm(key: str, default: bool = False) -> bool:
    locale = language()
    positive = {"s", "sim"} if locale == "pt-br" else {"y", "yes"}
    negative = {"n", "não", "nao"} if locale == "pt-br" else {"n", "no"}
    hint = text("cli.confirm_hint_yes" if default else "cli.confirm_hint_no")
    while True:
        answer = click.prompt(f"{text(key)} [{hint}]", default="", show_default=False).strip().casefold()
        if not answer:
            return default
        if answer in positive:
            return True
        if answer in negative:
            return False
        click.echo(text("cli.confirm_invalid"))


class LocalizedHelp:
    def format_help(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        locale = language(ctx)
        formatter.write_usage(ctx.command_path, " ".join(self.collect_usage_pieces(ctx)), prefix=t("cli.usage", language=locale) + " ")
        if self.help:
            formatter.write_paragraph()
            formatter.write_text(help_text(self.help.strip().split("\n\n")[0], locale))
        arguments, options = [], []
        for parameter in self.get_params(ctx):
            record = parameter.get_help_record(ctx)
            if record is None:
                continue
            label, description = record
            for key, copy in sorted(CATALOG.items(), key=lambda item: len(item[1]["en"]), reverse=True):
                if description.startswith(copy["en"]):
                    description = t(key, language=locale) + description[len(copy["en"]):]
                    break
            if locale == "pt-br":
                description = description.replace("[required]", "[obrigatório]").replace("default:", "padrão:")
            (arguments if isinstance(parameter, click.Argument) else options).append((label, description))
        for key, rows in [("cli.arguments", arguments), ("cli.options", options)]:
            if rows:
                with formatter.section(t(key, language=locale)):
                    formatter.write_dl(rows)
        if isinstance(self, click.Group):
            rows = []
            for name in self.list_commands(ctx):
                command = self.get_command(ctx, name)
                if command and not command.hidden:
                    description = (command.help or "").strip().split("\n\n")[0]
                    rows.append((name, help_text(description, locale)))
            if rows:
                with formatter.section(t("cli.commands", language=locale)):
                    formatter.write_dl(rows)


class LocalizedCommand(LocalizedHelp, TyperCommand):
    pass


class LocalizedGroup(LocalizedHelp, TyperGroup):
    def parse_args(self, ctx: click.Context, args: list[str]) -> list[str]:
        # Eager help can run before the callback, so capture the global option first.
        selected = "pt-br"
        for index, argument in enumerate(args):
            if argument == "--language" and index + 1 < len(args):
                selected = args[index + 1]
                break
            if argument.startswith("--language="):
                selected = argument.partition("=")[2]
                break
            if argument in self.commands:
                break
        ctx.meta["language"] = selected if selected in {"pt-br", "en"} else "pt-br"
        self._invocation_language = ctx.meta["language"]
        return super().parse_args(ctx, args)

    def main(self, *args, **kwargs):
        standalone = kwargs.pop("standalone_mode", True)
        try:
            result = super().main(*args, standalone_mode=False, **kwargs)
            if standalone and isinstance(result, int):
                raise SystemExit(result)
            return result
        except click.ClickException as exc:
            if not standalone:
                raise
            locale = language(exc.ctx) if isinstance(exc, click.UsageError) else "pt-br"
            error = _mask_text(parser_error(exc, locale), preserve_cli_syntax=True)
            click.echo(t("cli.error", language=locale, error=error), err=True)
            raise SystemExit(exc.exit_code) from exc
        except click.Abort as exc:
            if not standalone:
                raise
            click.echo(t("cli.abort", language=getattr(self, "_invocation_language", "pt-br")), err=True)
            raise SystemExit(1) from exc


def parser_error(exc: click.ClickException, locale: str) -> str:
    if isinstance(exc, click.MissingParameter):
        kind = "cli.argument_kind" if isinstance(exc.param, click.Argument) else "cli.option_kind"
        return t("cli.missing", language=locale, kind=t(kind, language=locale), option=exc.param.get_error_hint(exc.ctx) if exc.param else exc.param_hint)
    if isinstance(exc, click.NoSuchOption):
        return t("cli.no_option", language=locale, option=exc.option_name)
    detail = localize_message(exc.message, language=locale)
    choice = re.fullmatch(r"'(.+)' is not one of (.+)\.", detail)
    if choice:
        detail = t("cli.choice", language=locale, value=choice[1], choices=choice[2])
    command = re.fullmatch(r"No such command '(.+)'\.", detail)
    if command:
        return t("cli.no_command", language=locale, command=command[1])
    if isinstance(exc, click.BadParameter):
        option = exc.param_hint or (exc.param.get_error_hint(exc.ctx) if exc.param else "")
        return t("cli.bad_value", language=locale, option=option, error=detail)
    return detail
