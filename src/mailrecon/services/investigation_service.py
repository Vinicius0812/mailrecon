"""Reusable OSINT investigation helpers."""

from __future__ import annotations

from collections import OrderedDict
from datetime import datetime, timezone
import re
from typing import Callable

from mailrecon.core.i18n import msg
from mailrecon.core.platform_catalog import PLATFORMS
from mailrecon.core.models import (
    EmailCandidate,
    EvidenceRecord,
    InvestigationInput,
    InvestigationResult,
    ProfilePivot,
)
from mailrecon.core.validators import (
    mask_email_address,
    normalize_domain_input,
    split_name_tokens,
    validate_email_input,
)
from mailrecon.services.dns_service import DnsService
from mailrecon.services.profile_check_service import ProfileCheckService
from mailrecon.services.recon_service import ReconService


class InvestigationService:
    """Builds structured OSINT investigations from varied starting points."""

    active_candidate_statuses = {
        "valid",
        "accepted_direct_seed",
        "retained_for_manual_review",
        "candidate_generated",
        "format_valid_unverified",
    }

    role_account_local_parts = {
        "abuse",
        "admin",
        "billing",
        "contact",
        "help",
        "info",
        "no-reply",
        "noreply",
        "postmaster",
        "sales",
        "security",
        "support",
    }

    disposable_domains = {
        "10minutemail.com",
        "guerrillamail.com",
        "mailinator.com",
        "tempmail.com",
        "throwawaymail.com",
        "yopmail.com",
    }

    def __init__(
        self,
        recon_service: ReconService,
        dns_service: DnsService,
        profile_check_service: ProfileCheckService | None = None,
    ) -> None:
        self.recon_service = recon_service
        self.dns_service = dns_service
        self.profile_check_service = profile_check_service or ProfileCheckService()

    def investigate(
        self,
        query: InvestigationInput,
        check_public_profiles: bool = False,
        lab_profile_scenario: str | None = None,
        progress_callback: Callable[[str], None] | None = None,
        *, excluded_profile_urls: set[str] | None = None,
        allow_inferred_hibp: bool = False,
    ) -> InvestigationResult:
        """Run a structured OSINT investigation using safe public signals."""
        self._notify(progress_callback, msg("investigation.progress.seeds"))
        self._ensure_useful_query(query)
        self.profile_check_service.begin_execution()

        evidences = self._build_seed_evidences(query)
        self._notify(progress_callback, msg("investigation.progress.candidates"))
        candidate_emails = self._build_candidate_emails(query)
        self._notify(progress_callback, msg("investigation.progress.pivots"))
        profile_pivots = self._build_profile_pivots(query, candidate_emails)
        profile_pivots = [pivot for pivot in profile_pivots
                          if pivot.profile_url not in (excluded_profile_urls or set())]
        findings: list[str] = []
        risks: list[str] = []
        pivot_suggestions: list[str] = []
        limitations = self._build_limitations()

        seen_domains: OrderedDict[str, None] = OrderedDict()
        for domain in query.domains:
            seen_domains[normalize_domain_input(domain)] = None

        for candidate in candidate_emails:
            seen_domains[candidate.domain] = None

            if not self._candidate_should_be_analyzed(candidate):
                continue

            self._notify(progress_callback, msg("investigation.progress.analyze", email=candidate.email))
            analysis = self.recon_service.analyze_email(
                candidate.email,
                progress_callback=progress_callback,
                use_hibp=allow_inferred_hibp or candidate.source in {"seed_email", "provided_candidate"},
            )
            candidate.analysis = analysis
            self._apply_technical_assessment_to_candidate(candidate)

            evidences.extend(self._build_candidate_evidences(candidate))

            if analysis.hibp.status == "breaches_found":
                findings.append(
                    msg("investigation.finding.breaches", email=candidate.email, count=len(analysis.hibp.breaches))
                )
                risks.append(
                    msg("investigation.risk.exposure", email=candidate.email)
                )

            if analysis.dns.resolves and analysis.dns.mx_records:
                findings.append(
                    msg("investigation.finding.mx", domain=candidate.domain)
                )
            elif not analysis.dns.resolves:
                risks.append(
                    msg("investigation.risk.domain", domain=candidate.domain)
                )

        self._notify(progress_callback, msg("investigation.progress.domains"))
        for domain in seen_domains:
            evidences.append(self._build_domain_evidence(domain))

        if candidate_emails:
            findings.append(
                msg("investigation.finding.candidates", count=len(candidate_emails))
            )
        else:
            limitations.append(
                msg("investigation.limitation.no_candidates")
            )

        if profile_pivots:
            findings.append(
                msg("investigation.finding.pivots", count=len(profile_pivots))
            )

        if check_public_profiles and profile_pivots:
            self._notify(progress_callback, msg("investigation.progress.profiles"))
            checked_pivots, profile_evidences = self._check_profile_pivots(
                profile_pivots=profile_pivots,
                lab_profile_scenario=lab_profile_scenario,
            )
            profile_pivots = checked_pivots
            evidences.extend(profile_evidences)
            findings.extend(self._build_profile_findings(profile_pivots))
            risks.extend(self._build_profile_risks(profile_pivots))

        pivot_suggestions.extend(self._build_pivot_suggestions(query, candidate_emails))
        findings = self._dedupe_preserve_order(findings)
        risks = self._dedupe_preserve_order(risks)
        pivot_suggestions = self._dedupe_preserve_order(pivot_suggestions)
        limitations = self._dedupe_preserve_order(limitations)
        self._notify(progress_callback, msg("investigation.progress.finalize"))
        review_priority_score = self._build_review_priority_score(
            candidate_emails=candidate_emails,
            profile_pivots=profile_pivots,
            evidences=evidences,
        )
        confidence_breakdown = self._build_confidence_breakdown(
            candidate_emails=candidate_emails,
            profile_pivots=profile_pivots,
            evidences=evidences,
        )

        return InvestigationResult(
            query=query,
            candidate_emails=candidate_emails,
            profile_pivots=profile_pivots,
            evidences=evidences,
            findings=findings,
            risks=risks,
            pivot_suggestions=pivot_suggestions,
            limitations=limitations,
            overall_confidence_score=review_priority_score,
            review_priority_score=review_priority_score,
            confidence_breakdown=confidence_breakdown,
        )

    def _ensure_useful_query(self, query: InvestigationInput) -> None:
        """Require at least one meaningful investigation seed."""
        if any(
            (
                self._has_meaningful_values(query.names),
                self._has_meaningful_values(query.emails),
                self._has_meaningful_values(query.usernames),
                self._has_meaningful_values(query.domains),
                self._has_meaningful_values(query.organizations),
                self._has_meaningful_values(query.contexts),
                self._has_meaningful_values(query.candidate_emails),
            )
        ):
            return

        raise ValueError(
            msg("investigation.error.seeds")
        )

    def _build_seed_evidences(self, query: InvestigationInput) -> list[EvidenceRecord]:
        """Convert the starting query into traceable manual evidence."""
        collected_at = datetime.now(timezone.utc).isoformat()
        items = [
            ("name", query.names),
            ("email", [mask_email_address(email) for email in query.emails]),
            ("username", query.usernames),
            ("domain", query.domains),
            ("organization", query.organizations),
            ("context", query.contexts),
        ]

        evidences: list[EvidenceRecord] = []
        for label, values in items:
            for value in values:
                if not value.strip():
                    continue
                evidences.append(
                    EvidenceRecord(
                        title=msg("investigation.seed.title", label=msg(f"confidence.seed.label.{label}")),
                        category="seed",
                        source="investigator_input",
                        reference=msg("investigation.seed.reference"),
                        collected_at=collected_at,
                        method="manual_input",
                        confidence="medium",
                        confidence_score=60,
                        confidence_scope="input_seed",
                        sources=["investigator_input"],
                        summary=msg("investigation.seed.summary", label=msg(f"confidence.seed.label.{label}"), value=value),
                        decision_reasons=[msg("confidence.seed.reason")],
                    )
                )
        return evidences

    def _has_meaningful_values(self, values: list[str]) -> bool:
        """Return whether at least one input value contains non-whitespace text."""
        return any(value.strip() for value in values)

    def _build_candidate_emails(self, query: InvestigationInput) -> list[EmailCandidate]:
        """Build deduplicated email candidates from direct and inferred seeds."""
        deduped: OrderedDict[str, EmailCandidate] = OrderedDict()

        def retain(candidate: EmailCandidate) -> None:
            # Visit origins strongest first; duplicates add provenance, not authority.
            existing = deduped.get(candidate.email)
            if existing is None:
                deduped[candidate.email] = candidate
            else:
                existing.sources = self._dedupe_preserve_order(existing.sources + candidate.sources)

        for email in query.emails:
            retain(self._make_candidate(email, "seed_email", "medium"))

        for email in query.candidate_emails:
            retain(self._make_candidate(email, "provided_candidate", "medium"))

        normalized_domains = [
            normalize_domain_input(domain) for domain in query.domains if domain.strip()
        ]

        for username in query.usernames:
            cleaned_username = self._normalize_handle(username)
            if not cleaned_username:
                continue
            for domain in normalized_domains:
                email = f"{cleaned_username}@{domain}"
                retain(self._make_candidate(email, "username_domain_inference", "low"))

        for name in query.names:
            for pattern in self._infer_name_patterns(name):
                for domain in normalized_domains:
                    email = f"{pattern}@{domain}"
                    candidate = self._make_candidate(
                        email,
                        "name_domain_inference",
                        "low",
                    )
                    retain(candidate)

        return list(deduped.values())

    def _check_profile_pivots(
        self,
        profile_pivots: list[ProfilePivot],
        lab_profile_scenario: str | None,
    ) -> tuple[list[ProfilePivot], list[EvidenceRecord]]:
        """Resolve public profile URLs conservatively or through a lab simulation."""
        checked: list[ProfilePivot] = []
        evidences: list[EvidenceRecord] = []
        for pivot in profile_pivots:
            if lab_profile_scenario:
                updated, evidence = self.profile_check_service.simulate_profile_check(
                    pivot,
                    lab_profile_scenario,
                )
            else:
                updated, evidence = self.profile_check_service.check_public_profile(pivot)
            checked.append(updated)
            evidences.append(evidence)
        return checked, evidences

    def _build_profile_pivots(
        self,
        query: InvestigationInput,
        candidates: list[EmailCandidate],
    ) -> list[ProfilePivot]:
        """Generate safe public-profile pivots for manual OSINT review."""
        handles = OrderedDict[str, None]()
        for username in query.usernames:
            cleaned = self._normalize_handle(username)
            if cleaned:
                handles[cleaned] = None

        for name in query.names:
            for pattern in self._infer_name_patterns(name):
                handles[pattern] = None

        for candidate in candidates:
            if self._candidate_should_be_analyzed(candidate):
                local_part = candidate.email.partition("@")[0].lower()
                handles[local_part] = None

        pivots: list[ProfilePivot] = []
        for handle in handles:
            pivots.extend(self._platform_pivots_for_handle(handle))

        return pivots

    def _infer_name_patterns(self, name: str) -> list[str]:
        """Create small, safe candidate patterns from a name."""
        tokens = split_name_tokens(name)
        if not tokens:
            return []

        if len(tokens) == 1:
            return [tokens[0]]

        first = tokens[0]
        last = tokens[-1]
        patterns = [
            f"{first}.{last}",
            f"{first}{last}",
            f"{first}_{last}",
            f"{first[0]}{last}",
        ]
        return self._dedupe_preserve_order(patterns)

    def _make_candidate(self, email: str, source: str, confidence: str) -> EmailCandidate:
        """Build a candidate email with validation metadata."""
        confidence_scope = {
            "seed_email": "input_seed",
            "provided_candidate": "provided_address",
        }.get(source, "generated_hypothesis")
        is_valid, normalized_or_error, domain = validate_email_input(email)
        if not is_valid or domain is None:
            return EmailCandidate(
                email=email.strip(),
                masked_email=mask_email_address(email.strip()),
                domain="unknown",
                source=source,
                confidence="low",
                confidence_score=0,
                confidence_scope=confidence_scope,
                sources=[source],
                status="rejected_invalid_format",
                notes=[normalized_or_error],
                evidence_strength="none",
                risk_level="none",
                review_priority_score=0,
                decision_reasons=[msg("investigation.reason.invalid_format")],
                limitations=[msg("investigation.limitation.invalid_syntax")],
            )

        classification = self._classify_email_candidate(
            email=normalized_or_error,
            source=source,
            requested_confidence=confidence,
        )
        return EmailCandidate(
            email=normalized_or_error,
            masked_email=mask_email_address(normalized_or_error),
            domain=domain,
            source=source,
            confidence=classification["confidence"],
            confidence_score=classification["review_priority_score"],
            confidence_scope=confidence_scope,
            sources=[source],
            status=classification["status"],
            notes=classification["notes"],
            evidence_strength=classification["evidence_strength"],
            risk_level=classification["risk_level"],
            review_priority_score=classification["review_priority_score"],
            decision_reasons=classification["decision_reasons"],
            limitations=classification["limitations"],
            role_account_status=classification["role_account_status"],
            disposable_status=classification["disposable_status"],
        )

    def _classify_email_candidate(
        self,
        email: str,
        source: str,
        requested_confidence: str,
    ) -> dict[str, object]:
        """Classify a syntactically valid candidate without claiming mailbox existence."""
        local_part, _, domain = email.partition("@")
        base_local = local_part.partition("+")[0].lower()
        role_account_status = (
            "role_account" if base_local in self.role_account_local_parts else "not_role_account"
        )
        disposable_status = (
            "disposable" if domain.lower() in self.disposable_domains else "unknown"
        )

        source_profiles = {
            "seed_email": {
                "status": "accepted_direct_seed",
                "confidence": "medium",
                "evidence_strength": "strong_direct_seed",
                "review_priority_score": 70,
                "reason": msg("investigation.reason.direct_seed"),
            },
            "provided_candidate": {
                "status": "retained_for_manual_review",
                "confidence": "medium",
                "evidence_strength": "moderate_third_party_status",
                "review_priority_score": 60,
                "reason": msg("investigation.reason.provided_candidate"),
            },
            "username_domain_inference": {
                "status": "candidate_generated",
                "confidence": "low",
                "evidence_strength": "weak_inferred",
                "review_priority_score": 45,
                "reason": msg("investigation.reason.username_inference"),
            },
            "name_domain_inference": {
                "status": "candidate_generated",
                "confidence": "low",
                "evidence_strength": "weak_inferred",
                "review_priority_score": 30,
                "reason": msg("investigation.reason.name_inference"),
            },
        }
        profile = source_profiles.get(
            source,
            {
                "status": "format_valid_unverified",
                "confidence": "low",
                "evidence_strength": "weak_inferred",
                "review_priority_score": 35,
                "reason": msg("investigation.reason.unverified"),
            },
        )

        notes: list[str] = []
        decision_reasons = [
            profile["reason"],
            msg("investigation.reason.syntax"),
        ]
        limitations = [
            msg("investigation.limitation.format"),
            msg("investigation.limitation.no_probing"),
        ]
        risk_level = "none"
        score = int(profile["review_priority_score"])

        if role_account_status == "role_account":
            risk_level = "medium"
            score = min(score, 35)
            notes.append(msg("recon.reason.role"))
            decision_reasons.append(msg("investigation.reason.role"))
            limitations.append(msg("investigation.limitation.role"))

        if disposable_status == "disposable":
            risk_level = "high"
            score = min(score, 25)
            notes.append(msg("recon.reason.disposable"))
            decision_reasons.append(msg("investigation.reason.disposable"))
            limitations.append(msg("investigation.limitation.disposable"))

        return {
            "status": profile["status"],
            "confidence": profile["confidence"],
            "evidence_strength": profile["evidence_strength"],
            "risk_level": risk_level,
            "review_priority_score": score,
            "notes": notes,
            "decision_reasons": decision_reasons,
            "limitations": limitations,
            "role_account_status": role_account_status,
            "disposable_status": disposable_status,
        }

    def _candidate_should_be_analyzed(self, candidate: EmailCandidate) -> bool:
        """Return whether a candidate is retained for safe public-source analysis."""
        return candidate.status in self.active_candidate_statuses

    def _apply_technical_assessment_to_candidate(self, candidate: EmailCandidate) -> None:
        """Apply DNS/domain signals to a candidate after recon analysis."""
        if candidate.analysis is None:
            return

        dns = candidate.analysis.dns
        candidate.provider_family = dns.provider_family

        if dns.domain_status == "nxdomain":
            candidate.status = "rejected_domain_unresolved"
            candidate.confidence = "low"
            candidate.evidence_strength = "none"
            candidate.review_priority_score = 0
            candidate.confidence_score = 0
            candidate.decision_reasons.append(msg("investigation.reason.nxdomain"))
            candidate.limitations.append(msg("investigation.limitation.unresolved"))
            return

        if dns.email_acceptance_status == "declares_no_mail":
            candidate.status = "rejected_domain_no_mail"
            candidate.confidence = "low"
            candidate.evidence_strength = "none"
            candidate.review_priority_score = min(candidate.review_priority_score, 5)
            candidate.confidence_score = candidate.review_priority_score
            candidate.decision_reasons.append(msg("dns.reason.null_mx"))
            candidate.limitations.append(msg("investigation.limitation.null_mx"))
            return

        if dns.email_acceptance_status == "mx_present":
            candidate.decision_reasons.append(msg("investigation.reason.mx"))
            candidate.limitations.append(msg("investigation.limitation.mx"))
        elif dns.email_acceptance_status == "implicit_mail_possible":
            candidate.review_priority_score = min(candidate.review_priority_score, 30)
            candidate.confidence_score = candidate.review_priority_score
            candidate.decision_reasons.append(msg("investigation.reason.no_mx"))
            candidate.limitations.append(msg("investigation.limitation.implicit_mail"))
        elif dns.email_acceptance_status in {"inconclusive", "no_mail_signal"}:
            candidate.review_priority_score = min(candidate.review_priority_score, 25)
            candidate.confidence_score = candidate.review_priority_score
            candidate.decision_reasons.append(
                msg("investigation.reason.mail_status", status=dns.email_acceptance_status)
            )
            candidate.limitations.append(msg("investigation.limitation.mail_signal"))

        if dns.spf_status == "present":
            candidate.decision_reasons.append(msg("investigation.reason.spf"))
        if dns.dmarc_status == "present":
            candidate.decision_reasons.append(msg("investigation.reason.dmarc"))

    def _stronger_evidence(self, current: str, candidate: str) -> str:
        """Return the stronger evidence label using a small ordered scale."""
        order = {
            "none": 0,
            "weak_inferred": 1,
            "weak_public_http": 1,
            "moderate_format_and_dns": 2,
            "moderate_third_party_status": 2,
            "strong_direct_seed": 3,
            "strong_confirmed_public_record": 4,
        }
        return candidate if order.get(candidate, 0) > order.get(current, 0) else current

    def _build_candidate_evidences(self, candidate: EmailCandidate) -> list[EvidenceRecord]:
        """Create evidence records from one analyzed candidate."""
        assert candidate.analysis is not None
        analysis = candidate.analysis
        collected_at = datetime.now(timezone.utc).isoformat()

        evidences = [
            EvidenceRecord(
                title=msg("investigation.evidence.candidate_title"),
                category="email_candidate",
                source="mailrecon",
                reference="local_analysis",
                collected_at=collected_at,
                method="email_validation",
                confidence=candidate.confidence,
                confidence_score=candidate.confidence_score,
                confidence_scope=candidate.confidence_scope,
                sources=list(candidate.sources),
                summary=msg("confidence.candidate.summary", email=candidate.email, status=candidate.status, source=candidate.source),
                evidence_strength=candidate.evidence_strength,
                risk_level=candidate.risk_level,
                decision_reasons=list(candidate.decision_reasons),
                limitations=list(candidate.limitations),
            ),
            EvidenceRecord(
                title=msg("investigation.evidence.hibp_title"),
                category="exposure",
                source="Have I Been Pwned",
                reference="https://haveibeenpwned.com/API/v3#BreachesForAccount",
                collected_at=collected_at,
                method="hibp_breach_query",
                confidence="medium" if analysis.hibp.status == "breaches_found" else "low",
                confidence_score=self._score_hibp_evidence(analysis.hibp.status),
                confidence_scope="breach_exposure",
                sources=["Have I Been Pwned"],
                summary=msg("investigation.evidence.hibp_summary", email=candidate.email, status=analysis.hibp.status),
                observations=analysis.hibp.error,
                evidence_strength=self._hibp_evidence_strength(analysis.hibp.status),
                risk_level="high" if analysis.hibp.status == "breaches_found" else "none",
                decision_reasons=self._hibp_decision_reasons(analysis.hibp.status),
                limitations=[
                    msg("investigation.limitation.hibp"),
                    msg("investigation.limitation.no_breaches"),
                ],
            ),
        ]

        return evidences

    def _build_domain_evidence(self, domain: str) -> EvidenceRecord:
        """Create evidence about a domain pivot using DNS."""
        dns_result = self.dns_service.lookup_domain(domain)
        notes = None
        for error in reversed(dns_result.errors):
            notes = error if notes is None else msg("confidence.notes.join", first=error, next=notes)
        if dns_result.resolves:
            summary = msg(
                "investigation.evidence.domain_resolves",
                domain=domain,
                a_count=len(dns_result.a_records),
                mx_count=len(dns_result.mx_records),
            )
        else:
            summary = msg("investigation.evidence.domain_unresolved", domain=domain)

        factual_observation = bool(
            dns_result.a_records
            or dns_result.aaaa_records
            or dns_result.mx_records
            or dns_result.ns_records
            or dns_result.txt_records
            or dns_result.spf_records
            or dns_result.dmarc_records
            or dns_result.null_mx
            or dns_result.domain_status == "nxdomain"
        )

        return EvidenceRecord(
            title=msg("investigation.evidence.domain_title"),
            category="domain",
            source="public_dns",
            reference=domain,
            collected_at=datetime.now(timezone.utc).isoformat(),
            method="dns_lookup",
            confidence="high" if factual_observation else "low",
            confidence_score=80 if factual_observation else 0,
            confidence_scope="dns_observation",
            sources=["public_dns"],
            summary=summary,
            observations=notes,
            evidence_strength="moderate_format_and_dns" if factual_observation else "none",
            risk_level="medium" if dns_result.null_mx or not dns_result.resolves else "none",
            decision_reasons=[
                msg("investigation.reason.domain_status", status=dns_result.domain_status),
                msg("investigation.reason.email_status", status=dns_result.email_acceptance_status),
                msg("investigation.reason.provider", provider=dns_result.provider_family),
            ],
            limitations=[
                msg("confidence.dns.limitation")
            ],
        )

    def _build_pivot_suggestions(
        self,
        query: InvestigationInput,
        candidates: list[EmailCandidate],
    ) -> list[str]:
        """Suggest safe next pivots for the investigator."""
        pivots: list[str] = []

        if candidates:
            pivots.append(
                msg("investigation.pivot.naming")
            )

        if query.domains or any(candidate.domain != "unknown" for candidate in candidates):
            pivots.append(
                msg("investigation.pivot.domains")
            )

        if query.usernames:
            pivots.append(
                msg("investigation.pivot.usernames")
            )

        if query.organizations:
            pivots.append(
                msg("investigation.pivot.organization")
            )

        if query.usernames or candidates:
            pivots.append(
                msg("investigation.pivot.profiles")
            )

        pivots.append(
            msg("investigation.pivot.independent")
        )

        return pivots

    def _build_profile_findings(self, profile_pivots: list[ProfilePivot]) -> list[str]:
        """Summarize public-profile resolution checks into investigation findings."""
        findings: list[str] = []
        matched = [pivot for pivot in profile_pivots if pivot.resolution_status == "public_match_possible"]
        if matched:
            findings.append(
                msg("investigation.finding.profiles_matched", count=len(matched))
            )
        not_found = [pivot for pivot in profile_pivots if pivot.resolution_status == "not_found"]
        if not_found:
            findings.append(
                msg("investigation.finding.profiles_missing", count=len(not_found))
            )
        return findings

    def _build_profile_risks(self, profile_pivots: list[ProfilePivot]) -> list[str]:
        """Summarize public-profile resolution checks into investigation risks."""
        risks: list[str] = []
        blocked = [pivot for pivot in profile_pivots if pivot.resolution_status == "blocked_by_platform"]
        if blocked:
            risks.append(
                msg("investigation.risk.profiles_blocked", count=len(blocked))
            )
        ambiguous = [pivot for pivot in profile_pivots if pivot.resolution_status == "ambiguous"]
        if ambiguous:
            risks.append(
                msg("investigation.risk.profiles_ambiguous", count=len(ambiguous))
            )
        return risks

    def _platform_pivots_for_handle(self, handle: str) -> list[ProfilePivot]:
        """Create public-profile pivot suggestions for a single handle."""
        return [
            ProfilePivot(
                platform=spec.name,
                handle=handle,
                profile_url=spec.profile_url(handle),
                search_url=spec.search_url(handle),
                rule_id=spec.rule_id,
                rule_version=spec.rule_version,
                source="public_profile_pivot",
                confidence="low",
                confidence_score=self._score_profile_pivot(handle),
                confidence_scope="generated_hypothesis",
                sources=["public_profile_pivot"],
                status="manual_review",
                review_priority_score=self._score_profile_pivot(handle),
                evidence_strength="weak_inferred",
                decision_reasons=[
                    msg("investigation.reason.generated_url"),
                ],
                limitations=[
                    msg("investigation.limitation.generated_url"),
                ],
                notes=[
                    msg("investigation.note.public_url"),
                    msg("investigation.note.correlation"),
                ],
            )
            for spec in PLATFORMS
        ]

    def _normalize_handle(self, handle: str) -> str:
        """Normalize user-provided handles before using them in URLs or email guesses."""
        normalized = handle.strip().lower().removeprefix("@")
        normalized = re.sub(r"[^a-z0-9._-]+", "", normalized)
        normalized = re.sub(r"[.]+", ".", normalized)
        return normalized.strip(".-_")

    def _build_limitations(self) -> list[str]:
        """Return standard investigation limitations for ethical OSINT use."""
        return [
            msg("investigation.limitation.indicators"),
            msg("investigation.limitation.credentials"),
            msg("investigation.limitation.sensitive"),
            msg("investigation.limitation.absence"),
        ]

    def _score_hibp_evidence(self, status: str) -> int:
        """Return a confidence score for HIBP-derived evidence."""
        mapping = {
            "breaches_found": 75,
            "no_breaches": 20,
            "missing_api_key": 25,
            "disabled": 20,
            "timeout": 25,
            "request_error": 20,
            "unauthorized": 15,
            "forbidden": 15,
            "rate_limited": 20,
            "http_error": 20,
            "invalid_response": 20,
        }
        return mapping.get(status, 25)

    def _hibp_evidence_strength(self, status: str) -> str:
        """Classify HIBP evidence strength conservatively."""
        if status == "breaches_found":
            return "moderate_third_party_status"
        return "none"

    def _hibp_decision_reasons(self, status: str) -> list[str]:
        """Return explanatory reasons for HIBP evidence."""
        if status == "breaches_found":
            return [msg("investigation.reason.hibp_found")]
        if status == "no_breaches":
            return [msg("investigation.reason.hibp_none")]
        return [msg("investigation.reason.hibp_status", status=status)]

    def _score_profile_pivot(self, handle: str) -> int:
        """Return a basic score for public profile pivots."""
        if "." in handle or "_" in handle:
            return 25
        if len(handle) >= 6:
            return 25
        return 20

    def _build_review_priority_score(
        self,
        candidate_emails: list[EmailCandidate],
        profile_pivots: list[ProfilePivot],
        evidences: list[EvidenceRecord],
    ) -> int:
        """Build a score that summarizes how soon the investigation deserves review."""
        scores: list[tuple[int, float]] = []
        scores.extend(
            (candidate.review_priority_score, 1.4)
            for candidate in candidate_emails
            if self._candidate_should_be_analyzed(candidate)
        )
        scores.extend((pivot.review_priority_score, 0.7) for pivot in profile_pivots[:5])
        scores.extend((evidence.confidence_score, 0.5) for evidence in evidences[:5])
        if not scores:
            return 0

        weighted_total = sum(score * weight for score, weight in scores)
        weight_total = sum(weight for _, weight in scores)
        base_score = round(weighted_total / weight_total)
        penalty = self._build_review_priority_penalty(candidate_emails, profile_pivots)
        return max(0, min(100, base_score - penalty))

    def _build_confidence_breakdown(
        self,
        candidate_emails: list[EmailCandidate],
        profile_pivots: list[ProfilePivot],
        evidences: list[EvidenceRecord],
    ) -> dict[str, int]:
        """Score observed claims independently of lead provenance and review priority."""
        syntax_scores = [
            100 if validate_email_input(candidate.email)[0] else 0
            for candidate in candidate_emails
        ]
        domain_scores = [
            evidence.confidence_score
            for evidence in evidences
            if evidence.confidence_scope == "dns_observation"
        ]
        profile_scores = [
            45 if pivot.resolution_status == "public_match_possible" else 0
            for pivot in profile_pivots
            if pivot.checked_at is not None
            and pivot.resolution_status != "not_checked"
            and pivot.confidence_scope == "public_profile_existence"
            and pivot.check_method == "official_public_api"
        ]

        return {
            "email_format_confidence": self._average(syntax_scores),
            "domain_confidence": self._average(domain_scores),
            "profile_existence_confidence": self._average(profile_scores),
            "identity_correlation_confidence": 0,
        }

    def _build_review_priority_penalty(
        self,
        candidate_emails: list[EmailCandidate],
        profile_pivots: list[ProfilePivot],
    ) -> int:
        """Penalize noisy investigations so review priority is not inflated."""
        inferred_candidates = [
            candidate
            for candidate in candidate_emails
            if candidate.source in {"username_domain_inference", "name_domain_inference"}
        ]
        ambiguous_pivots = [
            pivot
            for pivot in profile_pivots
            if pivot.resolution_status
            in {"ambiguous", "blocked_by_platform", "rate_limited", "timeout", "request_error"}
        ]
        rejected_candidates = [
            candidate
            for candidate in candidate_emails
            if candidate.status.startswith("rejected_")
        ]
        penalty = 0
        if len(inferred_candidates) > 3:
            penalty += min(15, len(inferred_candidates) - 3)
        if ambiguous_pivots:
            penalty += min(15, round(len(ambiguous_pivots) / 2))
        if rejected_candidates:
            penalty += min(15, len(rejected_candidates) * 2)
        return penalty

    def _average(self, values: list[int]) -> int:
        """Return a rounded average with an empty-list fallback."""
        if not values:
            return 0
        return round(sum(values) / len(values))

    def _dedupe_preserve_order(self, items: list[str]) -> list[str]:
        """Remove duplicates while preserving the original order."""
        return list(OrderedDict.fromkeys(item for item in items if item))

    def _notify(
        self,
        progress_callback: Callable[[str], None] | None,
        message: str,
    ) -> None:
        """Emit a progress update when the caller asked for visual feedback."""
        if progress_callback is not None:
            progress_callback(message)
