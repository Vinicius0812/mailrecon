"""Application entrypoint."""

from mailrecon.cli.app import app


def run() -> None:
    """Run the MailRecon CLI."""
    app()
