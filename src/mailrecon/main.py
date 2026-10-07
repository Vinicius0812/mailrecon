"""Application entrypoint."""

import sys

from mailrecon.cli.app import app


def run() -> None:
    """Run the MailRecon CLI."""
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    app()
