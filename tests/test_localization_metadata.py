"""Edited localization metadata must not break legacy result/state reading."""

import pytest

from mailrecon.core.i18n import restore_messages, translate


@pytest.mark.parametrize("key", [[], {}, 42, None, "unknown.key"])
def test_malformed_metadata_key_preserves_existing_text(key):
    payload = {"summary": "Preserve external text", "localization": {"/summary": {"key": key, "parameters": {}}}}
    assert translate(payload, "pt-br")["summary"] == payload["summary"]
    assert restore_messages(payload)["summary"] == payload["summary"]
