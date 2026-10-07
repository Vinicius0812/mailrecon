"""Bounded, unauthenticated exact-username public API observations."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import json
import math
import time
from typing import Callable

import httpx

from mailrecon.core.config import bounded_int
from mailrecon.core.i18n import msg
from mailrecon.core.models import EvidenceRecord, ProfilePivot
from mailrecon.core.platform_catalog import PLATFORM_BY_NAME, PlatformSpec


@dataclass(frozen=True, slots=True)
class _Observation:
    status: str
    reason: str
    checked_at: str | None = None
    http_status: int | None = None
    final_url: str | None = None


class ProfileCheckService:
    """No login, retries, redirects, email search, or manual-source requests."""

    def __init__(
        self, timeout: float = 10.0, *, total_budget: int = 20,
        source_budget: int = 10, max_response_bytes: int = 65536,
        cache_ttl: int = 60, cache_entries: int = 128,
        transport: httpx.BaseTransport | None = None,
        clock: Callable[[], float] = time.monotonic,
        utcnow: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self.timeout = timeout if math.isfinite(timeout) and 0 < timeout <= 60 else 10.0
        self.total_budget = bounded_int(total_budget, 20, 0, 100)
        self.source_budget = bounded_int(source_budget, 10, 0, 50)
        self.max_response_bytes = bounded_int(max_response_bytes, 65536, 1024, 1048576)
        self.cache_ttl = bounded_int(cache_ttl, 60, 0, 300)
        self.cache_entries = bounded_int(cache_entries, 128, 0, 512)
        self._transport = transport
        self._clock = clock
        self._utcnow = utcnow
        self._cache: OrderedDict[tuple[str, str, str], tuple[float, _Observation]] = OrderedDict()
        self.begin_execution()

    def begin_execution(self) -> None:
        """Reset request budgets and source circuit breakers, not the bounded TTL cache."""
        self._requests = 0
        self._source_requests: dict[str, int] = {}
        self._disabled_sources: dict[str, str] = {}
        now = self._clock()
        self._cache = OrderedDict((key, entry) for key, entry in self._cache.items() if entry[0] > now)

    def check_public_profile(self, pivot: ProfilePivot) -> tuple[ProfilePivot, EvidenceRecord]:
        spec = PLATFORM_BY_NAME.get(pivot.platform)
        if (spec is None or pivot.source != "public_profile_pivot"
                or not spec.accepts_handle(pivot.handle)
                or pivot.profile_url != spec.profile_url(pivot.handle)):
            return self._result(pivot, _Observation("ambiguous", "invalid_pivot"), spec)
        if spec.rule_id == "manual_only":
            return self._result(pivot, _Observation("not_checked", "manual_only"), spec)
        if spec.name in self._disabled_sources:
            status = self._disabled_sources[spec.name]
            return self._result(pivot, _Observation(status, "source_disabled"), spec)

        key = (spec.rule_id, spec.rule_version, pivot.handle.casefold())
        cached = self._cache.get(key)
        if cached is not None:
            if cached[0] > self._clock():
                self._cache.move_to_end(key)
                return self._result(pivot, cached[1], spec, cache_hit=True)
            del self._cache[key]
        if (self._requests >= self.total_budget
                or self._source_requests.get(spec.name, 0) >= self.source_budget):
            return self._result(pivot, _Observation("not_checked", "budget_exhausted"), spec)

        self._requests += 1
        self._source_requests[spec.name] = self._source_requests.get(spec.name, 0) + 1
        observation = self._request(spec, pivot.handle)
        if observation.status in {"blocked_by_platform", "rate_limited"}:
            self._disabled_sources[spec.name] = observation.status
        if (observation.status in {"public_match_possible", "not_found"}
                and self.cache_ttl and self.cache_entries):
            self._cache[key] = (self._clock() + self.cache_ttl, observation)
            while len(self._cache) > self.cache_entries:
                self._cache.popitem(last=False)
        return self._result(pivot, observation, spec)

    def _request(self, spec: PlatformSpec, handle: str) -> _Observation:
        endpoint = spec.api_url(handle)
        deadline = self._clock() + self.timeout
        headers = {"User-Agent": "MailRecon/0.1", "Accept": "application/json", "Accept-Encoding": "identity"}
        if spec.rule_id == "github_user":
            headers.update({"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2026-03-10"})
        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=False, trust_env=False,
                              headers=headers, transport=self._transport) as client:
                with client.stream("GET", endpoint) as response:
                    checked_at = self._utcnow().isoformat()
                    code = response.status_code
                    if self._clock() >= deadline:
                        return _Observation("timeout", "timeout", checked_at, code)
                    if str(response.url) != endpoint:
                        return _Observation("ambiguous", "unexpected_response_url", checked_at, code)
                    if code in {401, 403, 429}:
                        status = "rate_limited" if code == 429 else "blocked_by_platform"
                        return _Observation(status, status, checked_at, code)
                    if code == 404 and spec.rule_id == "github_user":
                        return _Observation("not_found", "not_found", checked_at, code)
                    if code != 200:
                        return _Observation("ambiguous", "unexpected_http_status", checked_at, code)
                    if response.headers.get("content-encoding", "identity").lower() != "identity":
                        return _Observation("ambiguous", "invalid_payload", checked_at, code)
                    if (response.headers.get("x-next-page", "").strip()
                            or 'rel="next"' in response.headers.get("link", "")):
                        return _Observation("ambiguous", "invalid_payload", checked_at, code)
                    if response.headers.get("content-type", "").split(";", 1)[0].strip().lower() not in {
                        "application/json", "application/vnd.github+json",
                    }:
                        return _Observation("ambiguous", "invalid_payload", checked_at, code)
                    length = response.headers.get("content-length")
                    if length is not None and length.isdecimal() and (len(length) > 20 or int(length) > self.max_response_bytes):
                        return _Observation("ambiguous", "response_too_large", checked_at, code)
                    body = bytearray()
                    for chunk in response.iter_raw():
                        if self._clock() >= deadline:
                            return _Observation("timeout", "timeout", checked_at, code)
                        if len(body) + len(chunk) > self.max_response_bytes:
                            return _Observation("ambiguous", "response_too_large", checked_at, code)
                        body.extend(chunk)
                    if self._clock() >= deadline:
                        return _Observation("timeout", "timeout", checked_at, code)
                    try:
                        payload = json.loads(body)
                    except (ValueError, UnicodeError, RecursionError):
                        return _Observation("ambiguous", "invalid_payload", checked_at, code)
                    if spec.rule_id == "gitlab_user":
                        if payload == []:
                            return _Observation("not_found", "not_found", checked_at, code)
                        if not isinstance(payload, list) or len(payload) != 1:
                            return _Observation("ambiguous", "invalid_payload", checked_at, code)
                        payload = payload[0]
                    handle_key, url_key = ("login", "html_url") if spec.rule_id == "github_user" else ("username", "web_url")
                    if (not isinstance(payload, dict) or type(payload.get("id")) is not int
                            or payload["id"] <= 0 or not isinstance(payload.get(handle_key), str)
                            or not spec.accepts_handle(payload[handle_key])
                            or payload[handle_key].casefold() != handle.casefold()
                            or payload.get(url_key) != spec.profile_url(payload[handle_key])):
                        return _Observation("ambiguous", "invalid_payload", checked_at, code)
                    return _Observation("public_match_possible", "verified_public_profile", checked_at,
                                        code, spec.profile_url(payload[handle_key]))
        except httpx.TimeoutException:
            return _Observation("timeout", "timeout", self._utcnow().isoformat())
        except httpx.HTTPError:
            # Do not retain upstream bodies, headers, URLs, or exception details.
            return _Observation("request_error", "request_error", self._utcnow().isoformat())

    def _result(
        self, pivot: ProfilePivot, observation: _Observation, spec: PlatformSpec | None,
        *, cache_hit: bool = False, synthetic: bool = False,
    ) -> tuple[ProfilePivot, EvidenceRecord]:
        status = observation.status
        found = status == "public_match_possible"
        caps = {"public_match_possible": 45, "not_found": 0, "timeout": 20, "request_error": 20}
        score = max(0, min(caps.get(status, 25), pivot.review_priority_score))
        method = "lab_public_profile_check" if synthetic else (
            "official_public_api" if spec and spec.api_template else "manual_only"
        )
        scope = "synthetic_http_reachability" if synthetic else (
            "public_profile_existence" if observation.checked_at else "generated_hypothesis"
        )
        workflow = {
            "public_match_possible": "retained_for_manual_review", "not_found": "rejected_profile_not_found",
            "blocked_by_platform": "blocked_cannot_determine", "rate_limited": "blocked_cannot_determine",
            "timeout": "blocked_cannot_determine", "request_error": "blocked_cannot_determine",
            "not_checked": "manual_review",
        }.get(status, "ambiguous_requires_review")
        reason = msg("profile.api.reason", reason=msg(f"profile.api.{observation.reason}"))
        limitations = pivot.limitations + [msg("profile.limitation.no_login"), msg("profile.limitation.ownership")]
        if synthetic:
            limitations.append(msg("confidence.profile.synthetic_limitation"))
        updated = replace(
            pivot, status=workflow, resolution_status=status,
            http_status_code=observation.http_status, final_url=observation.final_url,
            checked_at=observation.checked_at, confidence="medium" if found else "low",
            confidence_scope=scope, confidence_score=score, review_priority_score=score,
            evidence_strength=("synthetic" if synthetic else "moderate_public_api") if found else "none",
            sources=list(dict.fromkeys(pivot.sources + (["lab_simulation"] if synthetic else [pivot.platform]))),
            matched_fields=["public_profile_id", "exact_handle", "canonical_profile_url"] if found and not synthetic else [],
            missing_fields=["independent_identity_correlation"] if found else ["deterministic_profile_state"],
            conflicting_fields=[], ambiguity_reasons=[] if found or status == "not_found" else [observation.reason],
            decision_reasons=pivot.decision_reasons + [reason], limitations=limitations,
            rule_id=spec.rule_id if spec else None, rule_version=spec.rule_version if spec else None,
            check_method=method, cache_hit=cache_hit,
            notes=pivot.notes + ([msg("profile.api.cache")] if cache_hit else []),
        )
        evidence = EvidenceRecord(
            title=msg("profile.evidence.title"), category="public_profile", source=pivot.platform,
            reference=pivot.profile_url, collected_at=observation.checked_at or self._utcnow().isoformat(),
            method=method, confidence=updated.confidence, confidence_score=score,
            confidence_scope=scope, sources=list(updated.sources),
            summary=msg("confidence.profile.synthetic_summary" if synthetic else "profile.evidence.summary",
                        platform=pivot.platform, handle=pivot.handle, status=status),
            observations=msg("confidence.profile.observations", http_status=observation.http_status,
                             final_url=observation.final_url) if observation.http_status is not None else None,
            evidence_strength=updated.evidence_strength, risk_level=pivot.risk_level,
            decision_reasons=list(updated.decision_reasons), limitations=list(limitations),
            rule_id=updated.rule_id, rule_version=updated.rule_version, cache_hit=cache_hit,
            collection_performed=bool(observation.checked_at) and not synthetic,
        )
        return updated, evidence

    def simulate_profile_check(self, pivot: ProfilePivot, scenario: str) -> tuple[ProfilePivot, EvidenceRecord]:
        status, code = {
            "found": ("public_match_possible", 200), "not-found": ("not_found", 404),
            "ambiguous": ("ambiguous", 302), "blocked": ("blocked_by_platform", 403),
            "rate-limited": ("rate_limited", 429),
        }.get(scenario, ("ambiguous", 200))
        return self._result(pivot, _Observation(status, "synthetic", self._utcnow().isoformat(), code,
                                              pivot.profile_url), PLATFORM_BY_NAME.get(pivot.platform), synthetic=True)
