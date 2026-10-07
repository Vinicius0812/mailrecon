from copy import deepcopy
from dataclasses import asdict, dataclass, field
import json
import pickle
from string import Formatter
from types import SimpleNamespace

import dns.exception
import dns.resolver
import httpx
import pytest

from mailrecon.core import i18n
from mailrecon.core.catalog_services import CATALOG as SERVICE_CATALOG
from mailrecon.core.i18n import (
    Language, Message, authored, catalog_keys, get_catalog, localize_message,
    msg, serialize_localized, t, translate,
)
from mailrecon.core.models import DnsLookupResult, HibpResult, ReconResult
from mailrecon.core.validators import validate_email_input
from mailrecon.services.dns_service import DnsService
from mailrecon.services.hibp_service import HibpService
from mailrecon.services.recon_service import ReconService
from mailrecon.services.refinement_state_service import RefinementStateService
from mailrecon.services.smtp_lab_service import SmtpLabValidationService


def test_message_is_canonical_english_with_provenance():
    message = msg("dns.error.timeout", record_type="MX")
    assert isinstance(message, str)
    assert message == "DNS lookup for MX timed out."
    assert "timed out" in message
    assert message.key == "dns.error.timeout"
    assert message.parameters == {"record_type": "MX"}
    assert t(message.key, **message.parameters) == "A consulta DNS de MX atingiu o tempo limite."
    assert translate(message, Language.EN) == message
    assert type(translate(message)) is str


def test_message_deepcopy_asdict_and_pickle_preserve_provenance():
    @dataclass
    class Example:
        notes: list[str]

    message = msg("hibp.error.request", error="raw upstream detail")
    for cloned in (deepcopy(message), pickle.loads(pickle.dumps(message)), asdict(Example([message]))["notes"][0]):
        assert isinstance(cloned, Message)
        assert cloned == message
        assert cloned.key == message.key
        assert cloned.parameters == message.parameters
        assert cloned.parameters is not message.parameters


def test_message_copies_parameters():
    parameters = {"error": ["external"]}
    message = Message("hibp.error.request", parameters)
    parameters["error"].append("changed")
    assert message.parameters == {"error": ["external"]}


def test_recursive_translation_preserves_structure_raw_text_and_keys():
    @dataclass(frozen=True, slots=True)
    class Example:
        notes: list
        raw: str
        derived: str = field(default="raw", init=False)

    original = Example([
        msg("recon.reason.valid_syntax"),
        {"Domain publishes SPF.": (msg("recon.reason.spf"), "Domain publishes SPF.")},
    ], "public upstream title")
    translated = translate(original)
    assert isinstance(translated, Example)
    assert translated.notes[0] == "A sintaxe do e-mail é válida."
    assert translated.notes[1] == {"Domain publishes SPF.": ("O domínio publica SPF.", "Domain publishes SPF.")}
    assert translated.raw == original.raw
    assert translated.derived == original.derived
    assert isinstance(original.notes[0], Message)
    assert translate({"query": ["Domain publishes SPF."]}) == {"query": ["Domain publishes SPF."]}


def test_serialization_has_plain_asdict_shape_and_json_pointer_metadata():
    result = ReconResult(
        email="user@example.com", domain="example.com", is_valid=True,
        dns=DnsLookupResult(resolves=False, errors=[msg("dns.error.no_records", record_type="MX")]),
        hibp=HibpResult(queried=True, status="breaches_found", breaches=[{"Title": "Domain publishes SPF.", "Description": "upstream English"}]),
    )
    exported = serialize_localized(result)
    assert set(exported) == set(asdict(result)) | {"localization"}
    assert exported["dns"]["errors"] == ["Nenhum registro MX encontrado."]
    assert type(exported["dns"]["errors"][0]) is str
    assert exported["localization"] == {"/dns/errors/0": {"key": "dns.error.no_records", "parameters": {"record_type": "MX"}}}
    assert exported["hibp"]["status"] == "breaches_found"
    assert exported["hibp"]["breaches"] == result.hibp.breaches
    assert json.loads(json.dumps(exported, ensure_ascii=False)) == exported
    assert serialize_localized(result, "en", include_localization=False) == asdict(result)


def test_saved_result_renders_both_languages_offline_without_mutation(monkeypatch):
    result = {"errors": [msg("hibp.error.request", error="raw {vendor} detail")], "email": "user@example.com"}
    saved = json.loads(json.dumps(serialize_localized(result)))
    original = deepcopy(saved)

    def forbidden(*args, **kwargs):
        pytest.fail("Rendering must not query the network")

    monkeypatch.setattr(httpx.Client, "get", forbidden)
    monkeypatch.setattr(dns.resolver.Resolver, "resolve", forbidden)
    english = translate(saved, "en")
    assert english["errors"] == ["HIBP request failed: raw {vendor} detail"]
    assert translate(english, "pt-br")["errors"] == saved["errors"]
    assert saved == original
    assert english["localization"] == saved["localization"]


def test_empty_metadata_is_optional():
    assert serialize_localized({"email": "user@example.com"}) == {"email": "user@example.com"}
    assert "localization" not in serialize_localized({"note": msg("recon.reason.spf")}, include_localization=False)
    with pytest.raises(TypeError):
        serialize_localized([msg("recon.reason.spf")])


def test_pointer_escaping_and_list_indexes():
    saved = serialize_localized({"a/b~c": {"": ["raw", msg("recon.reason.spf")]}})
    assert "/a~1b~0c//1" in saved["localization"]
    assert translate(json.loads(json.dumps(saved)), "en")["a/b~c"][""][1] == "Domain publishes SPF."


def test_nested_message_parameters_survive_json_roundtrip():
    outer = msg("hibp.error.request", error=msg("dns.error.timeout", record_type="A"))
    saved = json.loads(json.dumps(serialize_localized({"error": outer})))
    assert saved["error"] == "A consulta ao HIBP falhou: A consulta DNS de A atingiu o tempo limite."
    assert translate(saved, "en")["error"] == "HIBP request failed: DNS lookup for A timed out."


@pytest.mark.parametrize("metadata", [None, [], {"/text": None}, {"/text": {"key": []}}, {"/text": {"key": "missing", "parameters": {}}}, {"/absent": {"key": "recon.reason.spf", "parameters": {}}}, {"/text": {"key": "dns.error.no_records", "parameters": {}}}, {"/number": {"key": "recon.reason.spf", "parameters": {}}}])
def test_unknown_or_invalid_metadata_keeps_existing_text(metadata):
    saved = {"text": "raw", "number": 1, "localization": metadata}
    assert translate(saved) == saved


def test_authored_recovers_only_known_literal_or_template():
    fixed = authored("Domain publishes SPF.")
    dynamic = authored("Checking DNS and MX records for example.com...")
    assert isinstance(fixed, Message)
    assert dynamic.key == "recon.progress.dns"
    assert dynamic.parameters == {"domain": "example.com"}
    assert authored(dynamic) is dynamic
    assert localize_message("Checking DNS and MX records for example.com...", "pt-br") == "Consultando registros DNS e MX de example.com..."
    assert authored("Unknown user-authored prose") == "Unknown user-authored prose"
    assert type(authored("Unknown user-authored prose")) is str
    assert authored("arbitrary upstream text") == "arbitrary upstream text"
    assert localize_message("arbitrary upstream text", "pt-br") == "arbitrary upstream text"
    assert authored("{detail}") == "{detail}"
    assert type(authored("unknown external note; another external note")) is str


def test_legacy_investigation_and_profile_templates_are_registered():
    samples = [
        "Seed username",
        "The investigation started with username: alice",
        "alice@example.com appeared in 2 public breach record(s).",
        "Domain example.com resolves publicly with 1 A record(s) and 2 MX host(s).",
        "Public profile check for GitHub/alice returned status public_match_possible.",
        "HTTP success alone is retained only as weak public evidence.",
    ]
    for sample in samples:
        recovered = authored(sample)
        assert isinstance(recovered, Message), sample
        assert str(recovered) == sample
        assert translate(recovered) != sample


@pytest.mark.parametrize("language", ["es", "pt", "PT-BR", "", None])
def test_language_validation(language):
    for call in (lambda: t("recon.reason.spf", language), lambda: translate("raw", language), lambda: serialize_localized({}, language), lambda: localize_message("raw", language)):
        with pytest.raises(ValueError) as captured:
            call()
        assert isinstance(captured.value.args[0], Message)
        assert "pt-br or en" in str(captured.value)
        assert "Escolha pt-br ou en" in translate(captured.value.args[0])
    assert Language.PT_BR.value == "pt-br"
    assert Language.EN == "en"


def test_unknown_keys_and_missing_parameters_fail_clearly():
    with pytest.raises(KeyError):
        msg("does.not.exist")
    with pytest.raises(KeyError):
        t("does.not.exist")
    with pytest.raises(KeyError):
        msg("dns.error.timeout")


def test_optional_catalogs_are_loaded_lazily(monkeypatch):
    seen = []
    def load(name):
        seen.append(name)
        if name.endswith("catalog_confidence"):
            return SimpleNamespace(CATALOG={"confidence.test": {"en": "Example {count}", "pt-br": "Exemplo {count}"}})
        raise ModuleNotFoundError(name=name)
    monkeypatch.setattr(i18n, "import_module", load)
    assert t("confidence.test", count=2) == "Exemplo 2"
    assert "confidence.test" in catalog_keys()
    assert all(f"mailrecon.core.catalog_{name}" in seen for name in ("cli", "reporting", "confidence"))
    assert i18n.CATALOG["confidence.test"]["en"] == "Example {count}"


def test_catalog_import_errors_and_conflicts_are_not_hidden(monkeypatch):
    def broken(name):
        raise ModuleNotFoundError(name="missing_dependency")
    monkeypatch.setattr(i18n, "import_module", broken)
    with pytest.raises(ModuleNotFoundError):
        get_catalog()
    monkeypatch.setattr(i18n, "import_module", lambda name: SimpleNamespace(CATALOG={"recon.reason.spf": {"en": "conflict", "pt-br": "conflito"}}))
    with pytest.raises(ValueError, match="Conflicting"):
        get_catalog()


@pytest.mark.parametrize("key,entry", SERVICE_CATALOG.items())
def test_service_catalog_has_matching_parameters_and_valid_utf8(key, entry):
    assert set(entry) == {"en", "pt-br"}
    fields = {language: {name for _, name, _, _ in Formatter().parse(template) if name is not None} for language, template in entry.items()}
    assert fields["en"] == fields["pt-br"]
    parameters = {name: "example" for name in fields["en"]}
    assert msg(key, **parameters) == entry["en"].format(**parameters)
    assert t(key, **parameters) == entry["pt-br"].format(**parameters)
    assert entry["pt-br"].encode("utf-8").decode("utf-8") == entry["pt-br"]


@pytest.mark.parametrize("error,domain_status,mail_status", [(dns.resolver.NXDOMAIN, "nxdomain", "domain_unresolved"), (dns.resolver.NoAnswer, "no_public_resolution", "no_mail_signal"), (dns.exception.Timeout, "inconclusive", "inconclusive")])
def test_dns_classifiers_keep_canonical_english_messages(monkeypatch, error, domain_status, mail_status):
    def resolve(*args):
        raise error
    service = DnsService()
    monkeypatch.setattr(service, "_build_resolver", lambda: SimpleNamespace(resolve=resolve))
    result = service.lookup_domain("example.com")
    assert result.domain_status == domain_status
    assert result.email_acceptance_status == mail_status
    assert all(isinstance(note, Message) for note in result.errors)
    translated = translate(result)
    assert translated.domain_status == domain_status
    assert translated.email_acceptance_status == mail_status
    assert translated.errors != result.errors


def test_recon_prose_and_progress_are_messages():
    service = ReconService(
        SimpleNamespace(lookup_domain=lambda domain: DnsLookupResult(resolves=True, domain_status="resolves", email_acceptance_status="mx_present", spf_status="present", dmarc_status="present")),
        SimpleNamespace(query_breaches=lambda email: HibpResult(queried=False, status="disabled")),
    )
    progress = []
    result = service.analyze_email("admin@example.com", progress.append)
    assert all(isinstance(note, Message) for note in progress)
    assert all(isinstance(note, Message) for note in result.technical_assessment.decision_reasons + result.technical_assessment.limitations)
    assert result.technical_assessment.review_priority_score == 35
    assert translate(result).email == "admin@example.com"
    assert translate(result).technical_assessment.role_account_status == "role_account"


@pytest.mark.parametrize("status_code,key", [(401, "hibp.error.unauthorized"), (403, "hibp.error.forbidden"), (429, "hibp.error.rate_limited"), (500, "hibp.error.http")])
def test_hibp_errors_carry_localization_without_changing_status(monkeypatch, status_code, key):
    class Client:
        def __init__(self, **kwargs): pass
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def get(self, url, **kwargs): return httpx.Response(status_code)
    monkeypatch.setattr(httpx, "Client", Client)
    result = HibpService("key").query_breaches("user@example.com")
    assert result.error.key == key
    assert translate(result).status == result.status
    assert translate(result).error != result.error


def test_validation_error_provenance_survives_valueerror():
    valid, error, domain = validate_email_input("invalid-email")
    assert valid is False and domain is None
    assert isinstance(error, Message)
    assert str(error) == "An email address must have an @-sign."
    assert translate(ValueError(error).args[0]) == "Um endereço de e-mail deve conter o sinal @."


def test_refinement_locale_property_and_utf8_state(tmp_path):
    service = RefinementStateService(tmp_path / "state.json")
    from mailrecon.core.models import InvestigationInput
    query = InvestigationInput(usernames=["usuário"])
    def write():
        service._write_state("fingerprint", query, {}, [], set())
        return json.loads(service.state_path.read_text(encoding="utf-8"))
    portuguese = write()
    assert portuguese["instructions"] == t("refinement.instructions")
    assert "Adicione" in service.state_path.read_text(encoding="utf-8")
    assert "usuário" in service.state_path.read_text(encoding="utf-8")
    assert portuguese["localization"]["/instructions"]["key"] == "refinement.instructions"
    service.language = "en"
    english = write()
    assert english["instructions"] == str(msg("refinement.instructions"))
    assert translate(portuguese, "en")["instructions"] == english["instructions"]
    assert service.load_last_investigation()[0].usernames == ["usuário"]


def test_smtp_safety_prose_localizes_without_behavior_change(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Blocked SMTP validation must not connect")
    monkeypatch.setattr("smtplib.SMTP", forbidden)
    result = SmtpLabValidationService().validate("user@lab.local", "lab.local", "127.0.0.1", 2525, "localhost", ["vrfy"])
    assert not result.network_used and not result.safety_decision.allowed
    assert all(isinstance(note, Message) for note in result.safety_decision.reasons + result.limitations)
    translated = translate(result)
    assert translated.safety_decision.status == "blocked_by_safety_policy"
    assert translated.checks_run[0].message == "Bloqueado antes de qualquer interação SMTP."


def test_smtp_upstream_reply_remains_raw(monkeypatch):
    class Smtp:
        def __init__(self, **kwargs): pass
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def helo(self, name): pass
        def verify(self, email): return 250, b"Domain publishes SPF."
    monkeypatch.setattr("smtplib.SMTP", Smtp)
    result = SmtpLabValidationService(enable_lab_smtp=True).validate("user@lab.local", "lab.local", "127.0.0.1", 2525, "localhost", ["vrfy"], confirm_lab_only=True)
    assert type(result.checks_run[0].message) is str
    assert translate(result).checks_run[0].message == "Domain publishes SPF."
    assert result.checks_run[0].status == "accepted_by_lab_server"
