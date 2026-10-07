import ast
from dataclasses import asdict, fields, is_dataclass
import json
from pathlib import Path
from string import Formatter
from types import SimpleNamespace

import dns.exception
import dns.resolver
import httpx
import pytest

from mailrecon.core.catalog_confidence import CATALOG
from mailrecon.core.i18n import Message, get_catalog, msg, serialize_localized, t, translate
from mailrecon.core.models import InvestigationInput
from mailrecon.services.dns_service import DnsService
from mailrecon.services.hibp_service import HibpService
from mailrecon.services.investigation_service import InvestigationService
from mailrecon.services.profile_check_service import ProfileCheckService
from mailrecon.services.recon_service import ReconService


RAW_ERROR = "Vendor said: Domain publishes SPF. raw {token}"
RAW_BREACH = {"Name": "ExampleBreach", "Title": "Domain publishes SPF.", "Description": RAW_ERROR}


@pytest.fixture
def offline_service(monkeypatch):
    calls = []

    class Resolver:
        def resolve(self, domain, record_type):
            calls.append((domain, record_type))
            if record_type == "A":
                return ["192.0.2.1"]
            if record_type == "MX":
                return [SimpleNamespace(exchange="mx.example.com.")]
            if record_type == "TXT":
                return ["v=DMARC1; p=reject" if domain.startswith("_dmarc.") else "v=spf1 -all"]
            raise dns.resolver.NoAnswer

    class Client:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def get(self, url, **kwargs):
            calls.append(url)
            if "haveibeenpwned.com" in url:
                return httpx.Response(200, json=[RAW_BREACH], request=httpx.Request("GET", url))
            if "x.com" in url:
                raise httpx.ConnectError(RAW_ERROR)
            if "gravatar.com" in url:
                raise httpx.TimeoutException(RAW_ERROR)
            status = 200
            if "linkedin.com" in url:
                url = "https://www.linkedin.com/login"
            elif "instagram.com" in url:
                status = 403
            elif "facebook.com" in url:
                status = 404
            elif "t.me" in url:
                status = 429
            return httpx.Response(status, request=httpx.Request("GET", url))

    monkeypatch.setattr(DnsService, "_build_resolver", lambda self: Resolver())
    monkeypatch.setattr(httpx, "Client", Client)
    dns_service = DnsService()
    return InvestigationService(
        ReconService(dns_service, HibpService(api_key="test-key")),
        dns_service,
        ProfileCheckService(),
    ), calls


def messages(value):
    if isinstance(value, Message):
        yield value
    elif is_dataclass(value):
        for field in fields(value):
            yield from messages(getattr(value, field.name))
    elif isinstance(value, dict):
        for item in value.values():
            yield from messages(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from messages(item)


@pytest.mark.parametrize("mode", ["public", "synthetic"])
@pytest.mark.parametrize("language", ["en", "pt-br"])
def test_full_real_result_localizes_without_repeating_collection(offline_service, mode, language):
    service, calls = offline_service
    progress = []
    query = InvestigationInput(
        names=["Alice"],
        emails=["alice@example.com"],
        candidate_emails=["alice@example.com"],
        usernames=["alice"],
        domains=["example.com"],
        organizations=["Domain publishes SPF."],
        contexts=[RAW_ERROR],
    )
    result = service.investigate(
        query,
        check_public_profiles=True,
        lab_profile_scenario="found" if mode == "synthetic" else None,
        progress_callback=progress.append,
    )
    call_count = len(calls)
    canonical = asdict(result)
    localized = translate(result, language)
    serialized = serialize_localized(result, language)
    saved = json.loads(json.dumps(serialized, ensure_ascii=False))
    rerendered = translate(saved, "pt-br")
    restored_english = translate(saved, "en")

    assert len(calls) == call_count
    assert asdict(result) == canonical
    assert {key: value for key, value in restored_english.items() if key != "localization"} == (
        serialize_localized(result, "en", include_localization=False)
    )
    assert all(isinstance(item, Message) for item in progress)
    assert progress[0] == "Preparing investigation seeds..."
    assert translate(progress[0], "pt-br") == "Preparando os dados iniciais da investigação..."
    assert all(str(item) == get_catalog()[item.key]["en"].format(**item.parameters) for item in messages(result))
    authored_items = result.findings + result.risks + result.pivot_suggestions + result.limitations
    for candidate in result.candidate_emails:
        authored_items.extend(candidate.notes + candidate.decision_reasons + candidate.limitations)
    for pivot in result.profile_pivots:
        authored_items.extend(pivot.notes + pivot.decision_reasons + pivot.limitations)
    for evidence in result.evidences:
        authored_items.extend([evidence.title, evidence.summary] + evidence.decision_reasons + evidence.limitations)
    assert all(isinstance(item, Message) for item in authored_items)
    assert localized.candidate_emails[0].decision_reasons[0] == t("investigation.reason.direct_seed", language)
    assert localized.candidate_emails[0].decision_reasons[1] == t("investigation.reason.syntax", language)
    assert "caixa de correio não está confirmada" in rerendered["candidate_emails"][0]["decision_reasons"][1]
    assert rerendered["profile_pivots"][0]["decision_reasons"][0] == "Gerado como padrão de URL pública para revisão manual."
    assert rerendered["findings"][0] == "alice@example.com apareceu em 1 registro(s) público(s) de vazamento."
    assert all(item == t(original.key, language, **original.parameters)
               for item, original in zip(localized.limitations, result.limitations))
    assert localized.query == query
    assert saved["query"]["organizations"] == ["Domain publishes SPF."]
    assert saved["query"]["contexts"] == [RAW_ERROR]
    assert localized.candidate_emails[0].analysis.hibp.breaches == [RAW_BREACH]
    assert localized.candidate_emails[0].sources == [
        "seed_email", "provided_candidate", "username_domain_inference", "name_domain_inference",
    ]
    assert localized.candidate_emails[0].confidence == "medium"
    assert localized.candidate_emails[0].confidence_scope == "input_seed"
    assert localized.confidence_breakdown["identity_correlation_confidence"] == 0
    assert serialized["confidence_breakdown"]["identity_correlation_confidence"] == 0
    domain_evidence = next(item for item in localized.evidences if item.category == "domain")
    assert domain_evidence.observations == (
        "Nenhum registro AAAA encontrado.; Nenhum registro NS encontrado." if language == "pt-br"
        else "No AAAA records found.; No NS records found."
    )
    assert domain_evidence.limitations[0] == t("confidence.dns.limitation", language)
    assert any("não comprovam a titularidade" in item["limitations"][0]
               for item in rerendered["evidences"] if item["category"] == "domain")
    assert all(pivot.profile_url == original.profile_url for pivot, original in zip(localized.profile_pivots, result.profile_pivots))
    if mode == "synthetic":
        assert all(pivot.confidence_scope == "synthetic_http_reachability" for pivot in localized.profile_pivots)
        assert all(pivot.limitations[-1] == t("confidence.profile.synthetic_limitation", language)
                   for pivot in localized.profile_pivots)
        assert result.confidence_breakdown["profile_existence_confidence"] == 0
        assert all("Simulated" in str(item.summary) for item in result.evidences if item.category == "public_profile")
    else:
        assert {pivot.resolution_status for pivot in localized.profile_pivots} == {
            "public_match_possible", "ambiguous", "blocked_by_platform", "not_found",
            "rate_limited", "request_error", "timeout",
        }
        error_pivot = next(item for item in localized.profile_pivots if item.resolution_status == "request_error")
        assert error_pivot.notes[-1] == t("profile.error.request", language, error=RAW_ERROR)
        assert error_pivot.confidence == "low"
        reachable = next(item for item in localized.profile_pivots if item.resolution_status == "public_match_possible")
        assert reachable.confidence == "medium"
        assert reachable.confidence_scope == "http_reachability"
        assert t("profile.limitation.ownership", language) in reachable.limitations


@pytest.mark.parametrize("key,entry", CATALOG.items())
def test_confidence_catalog_is_loaded_and_uses_matching_parameters(key, entry):
    assert get_catalog()[key] == entry
    assert set(entry) == {"en", "pt-br"}
    placeholders = {
        language: {name for _, name, _, _ in Formatter().parse(template) if name is not None}
        for language, template in entry.items()
    }
    assert placeholders["en"] == placeholders["pt-br"]
    params = {name: "raw {value}" for name in placeholders["en"]}
    assert msg(key, **params) == entry["en"].format(**params)
    assert translate(msg(key, **params), "pt-br") == entry["pt-br"].format(**params)


@pytest.mark.parametrize("source", ["seed_email", "provided_candidate", "username_domain_inference", "name_domain_inference", "unknown"])
def test_all_candidate_origin_reasons_retain_message_metadata(offline_service, source):
    service, _ = offline_service
    candidate = service._make_candidate("alice@example.com", source, "low")

    assert all(isinstance(item, Message) for item in candidate.decision_reasons + candidate.limitations)
    assert translate(candidate.decision_reasons[0], "pt-br") != candidate.decision_reasons[0]


def test_raw_dns_errors_are_not_claimed_as_authored_messages(offline_service, monkeypatch):
    service, _ = offline_service
    raw = ["Domain publishes SPF.", RAW_ERROR]
    original = service.dns_service.lookup_domain("example.com")
    original.errors = raw
    monkeypatch.setattr(service.dns_service, "lookup_domain", lambda domain: original)

    evidence = service._build_domain_evidence("example.com")

    assert translate(evidence, "pt-br").observations == "; ".join(raw)
    assert original.errors == raw


def test_dns_timeout_observations_keep_messages_and_raw_errors_offline(offline_service, monkeypatch):
    service, _ = offline_service

    class TimeoutResolver:
        def resolve(self, domain, record_type):
            raise dns.exception.Timeout

    monkeypatch.setattr(service.dns_service, "_build_resolver", lambda: TimeoutResolver())
    dns_result = service.dns_service.lookup_domain("example.com")
    dns_result.errors.extend([RAW_ERROR, "Domain publishes SPF."])
    monkeypatch.setattr(service.dns_service, "lookup_domain", lambda domain: dns_result)

    evidence = service._build_domain_evidence("example.com")
    localized = translate(evidence, "pt-br")
    saved = json.loads(json.dumps(serialize_localized({"evidence": evidence}, "en")))

    expected = "; ".join([
        t("dns.error.timeout", "pt-br", record_type=record_type)
        for record_type in ["A", "AAAA", "MX", "TXT", "NS"]
    ] + [RAW_ERROR, "Domain publishes SPF."])
    assert isinstance(evidence.observations, Message)
    assert localized.observations == expected
    assert "A consulta DNS de MX atingiu o tempo limite." in localized.observations
    assert translate(saved, "pt-br")["evidence"]["observations"] == expected
    assert "DNS lookup for MX timed out." in evidence.observations
    assert dns_result.errors[-2:] == [RAW_ERROR, "Domain publishes SPF."]


def test_empty_query_error_retains_localization_key(offline_service):
    service, _ = offline_service
    with pytest.raises(ValueError) as captured:
        service.investigate(InvestigationInput())

    assert isinstance(captured.value.args[0], Message)
    assert translate(captured.value.args[0], "pt-br").startswith("Forneça pelo menos um dado inicial")


@pytest.mark.parametrize("module", ["investigation_service", "profile_check_service"])
def test_services_have_no_unwrapped_authored_prose_literals(module):
    source_path = Path(__file__).resolve().parents[1] / "src" / "mailrecon" / "services" / f"{module}.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    docstrings = {
        id(node.body[0].value)
        for node in ast.walk(tree)
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef))
        and node.body and isinstance(node.body[0], ast.Expr)
        and isinstance(node.body[0].value, ast.Constant)
    }
    unwrapped = [
        node.value for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
        and " " in node.value.strip() and id(node) not in docstrings
        and node.value != "Have I Been Pwned"
    ]
    assert unwrapped == []
