"""Localize authored prose without changing canonical service data.

Optional presentation/confidence catalogs expose the same CATALOG shape as
catalog_services. Metadata uses RFC 6901 JSON Pointers rooted at the result.
"""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import fields, is_dataclass, replace
from enum import Enum
from functools import lru_cache
from importlib import import_module
import re
from string import Formatter
from typing import Any

from mailrecon.core.catalog_services import CATALOG as SERVICE_CATALOG

__all__ = [
    "Language", "Message", "msg", "t", "translate", "serialize_localized",
    "localize_message", "authored", "restore_messages", "get_catalog", "catalog_keys", "CATALOG",
]


class Language(str, Enum):
    PT_BR = "pt-br"
    EN = "en"


def get_catalog() -> dict[str, dict[str, str]]:
    """Load optional presentation catalogs only when messages are requested."""
    catalog = dict(SERVICE_CATALOG)
    for name in ("catalog_cli", "catalog_reporting", "catalog_confidence"):
        module_name = f"mailrecon.core.{name}"
        try:
            module = import_module(module_name)
        except ModuleNotFoundError as exc:
            if exc.name != module_name:
                raise
            continue
        for key, entry in module.CATALOG.items():
            if key in catalog and catalog[key] != entry:
                raise ValueError(f"Conflicting localization catalog key: {key}")
            catalog[key] = entry
    return catalog


class _Catalog(Mapping):
    def __getitem__(self, key):
        return get_catalog()[key]

    def __iter__(self):
        return iter(get_catalog())

    def __len__(self):
        return len(get_catalog())


CATALOG = _Catalog()


def catalog_keys() -> tuple[str, ...]:
    """Return the sorted registry, including available presentation catalogs."""
    return tuple(sorted(get_catalog()))


def _language(value: Language | str) -> Language:
    try:
        return Language(value)
    except (ValueError, TypeError) as exc:
        raise ValueError(msg("i18n.error.language", requested_language=str(value))) from exc


class Message(str):
    """A canonical English string retaining its authored key and parameters."""

    def __new__(cls, key: str, parameters: Mapping[str, Any] | None = None):
        parameters = deepcopy(dict(parameters or {}))
        value = get_catalog()[key]["en"].format(**parameters)
        instance = super().__new__(cls, value)
        instance.key = key
        instance.parameters = parameters
        return instance

    def __reduce__(self):
        # asdict deep-copies leaves; reconstruct from provenance, not str(value).
        return type(self), (self.key, self.parameters)


def msg(key: str, **params: Any) -> Message:
    """Create authored prose for services; its string value is always English."""
    return Message(key, params)


def t(key: str, language: Language | str = Language.PT_BR, **params: Any) -> str:
    """Render a catalog key directly at a presentation boundary."""
    language = _language(language)
    template = get_catalog()[key][language.value]
    return template.format(**{name: translate(value, language) for name, value in params.items()})


@lru_cache(maxsize=1024)
def _template_pattern(template: str):
    parts = []
    names = set()
    for literal, name, spec, conversion in Formatter().parse(template):
        parts.append(re.escape(literal))
        if name is None:
            continue
        if not name.isidentifier() or spec or conversion:
            return None
        if name in names:
            parts.append(f"(?P={name})")
        else:
            parts.append(f"(?P<{name}>.*?)")
            names.add(name)
    # Parameter-only and punctuation-only joins cannot identify authored prose.
    if not any(
        any(character.isalpha() for character in literal)
        for literal, _, _, _ in Formatter().parse(template)
    ):
        return None
    return re.compile("".join(parts), re.DOTALL)


def authored(text: str) -> str | Message:
    """Recover known English authored templates; leave unknown strings intact.

    Call only on fields owned by MailRecon, never on arbitrary user/upstream data.
    Prefer msg at the producer so recovery is unnecessary.
    """
    if isinstance(text, Message):
        return text
    catalog = get_catalog()
    for key, entry in catalog.items():
        if text == entry["en"] and not any(name is not None for _, name, _, _ in Formatter().parse(entry["en"])):
            return msg(key)
    for key, entry in catalog.items():
        pattern = _template_pattern(entry["en"])
        if pattern is not None and (match := pattern.fullmatch(text)):
            return msg(key, **match.groupdict())
    return text


def localize_message(text: str, language: Language | str = Language.PT_BR) -> str:
    """Render explicitly known legacy prose without general-purpose translation."""
    return translate(authored(text), language)


def translate(value: Any, language: Language | str = Language.PT_BR) -> Any:
    """Recursively render Messages or saved metadata without mutating input.

    Dataclasses retain their type. Dictionary keys and ordinary strings remain
    unchanged. Saved localization metadata is retained for later re-rendering.
    """
    language = _language(language)
    if isinstance(value, Message):
        return t(value.key, language, **value.parameters)
    if is_dataclass(value) and not isinstance(value, type):
        translated = replace(value, **{
            field.name: translate(getattr(value, field.name), language)
            for field in fields(value) if field.init
        })
        for field in fields(value):
            if not field.init:
                object.__setattr__(translated, field.name, translate(getattr(value, field.name), language))
        return translated
    if isinstance(value, dict):
        output = {key: translate(item, language) for key, item in value.items() if key != "localization"}
        if "localization" in value:
            output["localization"] = deepcopy(value["localization"])
            _apply_metadata(output, value["localization"], language)
        return output
    if isinstance(value, list):
        return [translate(item, language) for item in value]
    if isinstance(value, tuple):
        items = [translate(item, language) for item in value]
        return type(value)(*items) if hasattr(value, "_fields") else tuple(items)
    return value


def _pointer_part(value: object) -> str:
    return str(value).replace("~", "~0").replace("/", "~1")


def serialize_localized(
    value: Any,
    language: Language | str = Language.PT_BR,
    *,
    include_localization: bool = True,
) -> dict:
    """Return asdict-shaped plain data plus optional original Message metadata.

    A mapping is also accepted for refinement state. Metadata entries have
    {'key': str, 'parameters': dict}; no language is coupled to saved provenance.
    """
    language = _language(language)
    metadata = {}

    def walk(item, path):
        if isinstance(item, Message):
            metadata[path] = {"key": item.key, "parameters": walk_parameters(item.parameters)}
            return t(item.key, language, **item.parameters)
        if is_dataclass(item) and not isinstance(item, type):
            return {field.name: walk(getattr(item, field.name), f"{path}/{_pointer_part(field.name)}") for field in fields(item)}
        if isinstance(item, dict):
            return {key: walk(child, f"{path}/{_pointer_part(key)}") for key, child in item.items()}
        if isinstance(item, (list, tuple)):
            children = [walk(child, f"{path}/{index}") for index, child in enumerate(item)]
            return children if isinstance(item, list) else tuple(children)
        return deepcopy(item)

    def walk_parameters(parameters):
        # Keep parameter values canonical; raw external details are never translated.
        return {name: _plain_parameter(item) for name, item in parameters.items()}

    output = walk(value, "")
    if not isinstance(output, dict):
        raise TypeError("serialize_localized requires a dataclass instance or dictionary")
    if include_localization and metadata:
        if "localization" in output:
            raise ValueError("localization is reserved for message metadata")
        output["localization"] = metadata
    return output


def _plain_parameter(value):
    if isinstance(value, Message):
        return {"__message__": {"key": value.key, "parameters": {name: _plain_parameter(item) for name, item in value.parameters.items()}}}
    if isinstance(value, dict):
        return {key: _plain_parameter(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain_parameter(item) for item in value]
    return deepcopy(value)


def _restore_parameter(value):
    if isinstance(value, dict):
        if set(value) == {"__message__"}:
            entry = value["__message__"]
            return msg(entry["key"], **_restore_parameter(entry["parameters"]))
        return {key: _restore_parameter(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_restore_parameter(item) for item in value]
    return value


def restore_messages(value: dict) -> dict:
    """Restore authored leaves so saved execution inputs retain canonical identity."""
    output = deepcopy(value)
    _apply_metadata(output, value.get("localization"), None)
    return output


def _apply_metadata(output: dict, metadata: Any, language: Language | None) -> None:
    if not isinstance(metadata, dict):
        return
    for path, entry in metadata.items():
        if not isinstance(path, str) or not path.startswith("/") or not isinstance(entry, dict):
            continue
        if not isinstance(entry.get("key"), str) or entry["key"] not in get_catalog() or not isinstance(entry.get("parameters"), dict):
            continue
        parts = [part.replace("~1", "/").replace("~0", "~") for part in path[1:].split("/")]
        if not parts or parts[0] == "localization":
            continue
        try:
            parent = output
            for part in parts[:-1]:
                parent = parent[int(part)] if isinstance(parent, list) and part.isdecimal() else parent[part]
            leaf = int(parts[-1]) if isinstance(parent, list) and parts[-1].isdecimal() else parts[-1]
            if not isinstance(parent[leaf], str):
                continue
            parameters = _restore_parameter(entry["parameters"])
            parent[leaf] = msg(entry["key"], **parameters) if language is None else t(entry["key"], language, **parameters)
        except (KeyError, IndexError, TypeError, ValueError):
            # Older or partially edited exports still render their existing text.
            continue
