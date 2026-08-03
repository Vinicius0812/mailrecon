"""Reusable OSINT investigation helpers."""

from __future__ import annotations

from collections import OrderedDict
from datetime import datetime, timezone
import re
from typing import Callable

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
    ) -> InvestigationResult:
        """Run a structured OSINT investigation using safe public signals."""
        self._notify(progress_callback, "Preparing investigation seeds...")
        self._ensure_useful_query(query)

        evidences = self._build_seed_evidences(query)
        self._notify(progress_callback, "Building candidate emails...")
        candidate_emails = self._build_candidate_emails(query)
        self._notify(progress_callback, "Generating public-profile pivots...")
        profile_pivots = self._build_profile_pivots(query, candidate_emails)
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

            self._notify(progress_callback, f"Analyzing candidate email: {candidate.email}")
            analysis = self.recon_service.analyze_email(
                candidate.email,
                progress_callback=progress_callback,
            )
            candidate.analysis = analysis
            self._apply_technical_assessment_to_candidate(candidate)

            evidences.extend(self._build_candidate_evidences(candidate))

            if analysis.hibp.status == "breaches_found":
                findings.append(
                    f"{candidate.email} appeared in {len(analysis.hibp.breaches)} public breach record(s)."
                )
                risks.append(
                    f"Public breach exposure may increase phishing or account recovery risk for {candidate.email}."
                )

            if analysis.dns.resolves and analysis.dns.mx_records:
                findings.append(
                    f"Domain {candidate.domain} resolves publicly and exposes MX infrastructure."
                )
            elif not analysis.dns.resolves:
                risks.append(
                    f"Domain {candidate.domain} did not resolve during collection and may be stale, parked, or mistyped."
                )

        self._notify(progress_callback, "Collecting domain evidence...")
        for domain in seen_domains:
            evidences.append(self._build_domain_evidence(domain))

        if candidate_emails:
            findings.append(
                f"The investigation organized {len(candidate_emails)} candidate email(s) for safe review."
            )
        else:
            limitations.append(
                "No candidate emails were produced from the provided seeds, so email-centric pivots are limited."
            )

        if profile_pivots:
            findings.append(
                f"The investigation generated {len(profile_pivots)} safe public-profile pivot suggestion(s) for manual review."
            )

        if check_public_profiles and profile_pivots:
            self._notify(progress_callback, "Checking public profile URLs...")
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
        self._notify(progress_callback, "Finalizing investigation summary...")
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
            "Provide at least one seed such as --email, --name, --username, --domain, --organization, or --context."
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
                        title=f"Seed {label}",
                        category="seed",
                        source="investigator_input",
                        reference="CLI input",
                        collected_at=collected_at,
                        method="manual_input",
                        confidence="high",
                        confidence_score=80,
                        summary=f"The investigation started with {label}: {value}",
                    )
                )
        return evidences

    def _has_meaningful_values(self, values: list[str]) -> bool:
        """Return whether at least one input value contains non-whitespace text."""
        return any(value.strip() for value in values)

    def _build_candidate_emails(self, query: InvestigationInput) -> list[EmailCandidate]:
        """Build deduplicated email candidates from direct and inferred seeds."""
        deduped: OrderedDict[str, EmailCandidate] = OrderedDict()

        for email in query.emails:
            candidate = self._make_candidate(email, "seed_email", "high")
            deduped[candidate.email] = candidate

        for email in query.candidate_emails:
            candidate = self._make_candidate(email, "provided_candidate", "medium")
            deduped[candidate.email] = candidate

        normalized_domains = [
            normalize_domain_input(domain) for domain in query.domains if domain.strip()
        ]

        for username in query.usernames:
            cleaned_username = self._normalize_handle(username)
            if not cleaned_username:
                continue
            for domain in normalized_domains:
                email = f"{cleaned_username}@{domain}"
                candidate = self._make_candidate(email, "username_domain_inference", "medium")
                deduped[candidate.email] = candidate

        for name in query.names:
            for pattern in self._infer_name_patterns(name):
                for domain in normalized_domains:
                    email = f"{pattern}@{domain}"
                    candidate = self._make_candidate(
                        email,
                        "name_domain_inference",
                        "low",
                    )
                    deduped[candidate.email] = candidate

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
        is_valid, normalized_or_error, domain = validate_email_input(email)
        if not is_valid or domain is None:
            return EmailCandidate(
                email=email.strip(),
                masked_email=mask_email_address(email.strip()),
                domain="unknown",
                source=source,
                confidence="low",
                confidence_score=0,
                status="rejected_invalid_format",
                notes=[normalized_or_error],
                evidence_strength="none",
                risk_level="none",
                review_priority_score=0,
                decision_reasons=["Email format validation failed."],
                limitations=["Invalid email syntax prevents further technical assessment."],
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
                "reason": "Retained because the email was provided directly as an investigation seed.",
            },
            "provided_candidate": {
                "status": "retained_for_manual_review",
                "confidence": "medium",
                "evidence_strength": "moderate_third_party_status",
                "review_priority_score": 60,
                "reason": "Retained because it was explicitly provided as a candidate email.",
            },
            "username_domain_inference": {
                "status": "candidate_generated",
                "confidence": "low",
                "evidence_strength": "weak_inferred",
                "review_priority_score": 45,
                "reason": "Generated from username plus domain; this is an inferred lead.",
            },
            "name_domain_inference": {
                "status": "candidate_generated",
                "confidence": "low",
                "evidence_strength": "weak_inferred",
                "review_priority_score": 30,
                "reason": "Generated from name pattern plus domain; this is a weak inferred lead.",
            },
        }
        profile = source_profiles.get(
            source,
            {
                "status": "format_valid_unverified",
                "confidence": requested_confidence,
                "evidence_strength": "weak_inferred",
                "review_priority_score": 35,
                "reason": "Retained as a syntactically valid but unverified email candidate.",
            },
        )

        notes: list[str] = []
        decision_reasons = [
            str(profile["reason"]),
            "Email syntax is valid; mailbox existence is not confirmed.",
        ]
        limitations = [
            "A valid email format does not prove the mailbox exists.",
            "No SMTP probing, login flow, password recovery, VRFY, or RCPT TO checks are performed.",
        ]
        risk_level = "none"
        score = int(profile["review_priority_score"])

        if role_account_status == "role_account":
            risk_level = "medium"
            score = min(score, 35)
            notes.append("Local-part looks like a role or shared mailbox.")
            decision_reasons.append("Role accounts are weaker evidence for personal identity correlation.")
            limitations.append("Role/shared mailboxes may belong to teams rather than one person.")

        if disposable_status == "disposable":
            risk_level = "high"
            score = min(score, 25)
            notes.append("Domain is on the local disposable-domain list.")
            decision_reasons.append("Disposable domains are weak evidence for durable identity correlation.")
            limitations.append("Disposable domains can create false positives in identity investigations.")

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
            candidate.decision_reasons.append("Domain returned NXDOMAIN during public DNS collection.")
            candidate.limitations.append("The domain did not resolve publicly at collection time.")
            return

        if dns.email_acceptance_status == "declares_no_mail":
            candidate.status = "rejected_domain_no_mail"
            candidate.confidence = "low"
            candidate.evidence_strength = "none"
            candidate.review_priority_score = min(candidate.review_priority_score, 5)
            candidate.confidence_score = candidate.review_priority_score
            candidate.decision_reasons.append("Domain publishes Null MX and declares it does not accept email.")
            candidate.limitations.append("Null MX is a domain-level signal, not a mailbox-level response.")
            return

        if dns.email_acceptance_status == "mx_present":
            candidate.evidence_strength = self._stronger_evidence(
                candidate.evidence_strength,
                "moderate_format_and_dns",
            )
            candidate.decision_reasons.append("Domain publishes MX records, so it appears mail-capable.")
            candidate.limitations.append("MX records validate domain mail capability, not this mailbox.")
        elif dns.email_acceptance_status == "implicit_mail_possible":
            candidate.review_priority_score = min(candidate.review_priority_score, 30)
            candidate.confidence_score = candidate.review_priority_score
            candidate.decision_reasons.append("Domain has address records but no MX records.")
            candidate.limitations.append("Implicit mail delivery without MX is possible but weak evidence.")
        elif dns.email_acceptance_status in {"inconclusive", "no_mail_signal"}:
            candidate.review_priority_score = min(candidate.review_priority_score, 25)
            candidate.confidence_score = candidate.review_priority_score
            candidate.decision_reasons.append(
                f"Domain mail acceptance status is {dns.email_acceptance_status}."
            )
            candidate.limitations.append("DNS collection did not provide a strong mail-capability signal.")

        if dns.spf_status == "present":
            candidate.decision_reasons.append("Domain publishes SPF; this is hygiene evidence, not mailbox proof.")
        if dns.dmarc_status == "present":
            candidate.decision_reasons.append("Domain publishes DMARC; this is governance evidence, not mailbox proof.")

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
                title="Candidate email validation",
                category="email_candidate",
                source="mailrecon",
                reference="local_analysis",
                collected_at=collected_at,
                method="email_validation",
                confidence=candidate.confidence,
                confidence_score=candidate.confidence_score,
                summary=f"{candidate.email} was retained as a {candidate.source} candidate.",
                evidence_strength=candidate.evidence_strength,
                risk_level=candidate.risk_level,
                decision_reasons=list(candidate.decision_reasons),
                limitations=list(candidate.limitations),
            ),
            EvidenceRecord(
                title="HIBP exposure check",
                category="exposure",
                source="Have I Been Pwned",
                reference="https://haveibeenpwned.com/API/v3#BreachesForAccount",
                collected_at=collected_at,
                method="hibp_breach_query",
                confidence="medium",
                confidence_score=self._score_hibp_evidence(analysis.hibp.status),
                summary=f"{candidate.email} returned HIBP status {analysis.hibp.status}.",
                observations=analysis.hibp.error,
                evidence_strength=self._hibp_evidence_strength(analysis.hibp.status),
                risk_level="high" if analysis.hibp.status == "breaches_found" else "none",
                decision_reasons=self._hibp_decision_reasons(analysis.hibp.status),
                limitations=[
                    "HIBP exposure status is a third-party public breach signal, not proof of mailbox control.",
                    "Absence of known breaches does not prove the address is inactive or safe.",
                ],
            ),
        ]

        return evidences

    def _build_domain_evidence(self, domain: str) -> EvidenceRecord:
        """Create evidence about a domain pivot using DNS."""
        dns_result = self.dns_service.lookup_domain(domain)
        notes = "; ".join(dns_result.errors) if dns_result.errors else None
        if dns_result.resolves:
            summary = (
                f"Domain {domain} resolves publicly with {len(dns_result.a_records)} A record(s) "
                f"and {len(dns_result.mx_records)} MX host(s)."
            )
            confidence = "high"
        else:
            summary = f"Domain {domain} did not resolve during the DNS collection step."
            confidence = "medium"

        return EvidenceRecord(
            title="Domain infrastructure check",
            category="domain",
            source="public_dns",
            reference=domain,
            collected_at=datetime.now(timezone.utc).isoformat(),
            method="dns_lookup",
            confidence=confidence,
            confidence_score=80 if dns_result.resolves else 45,
            summary=summary,
            observations=notes,
            evidence_strength="moderate_format_and_dns" if dns_result.mx_records else "weak_inferred",
            risk_level="medium" if dns_result.null_mx or not dns_result.resolves else "none",
            decision_reasons=[
                f"Domain status: {dns_result.domain_status}.",
                f"Email acceptance status: {dns_result.email_acceptance_status}.",
                f"Provider family: {dns_result.provider_family}.",
            ],
            limitations=[
                "DNS describes domain infrastructure and does not confirm individual mailbox existence."
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
                "Compare candidate email naming patterns to decide which local-part formats deserve manual validation in public records."
            )

        if query.domains or any(candidate.domain != "unknown" for candidate in candidates):
            pivots.append(
                "Review the discovered domains and MX providers to map shared infrastructure and likely communication providers."
            )

        if query.usernames:
            pivots.append(
                "Search the provided usernames in public sources and compare them with the retained email candidates."
            )

        if query.organizations:
            pivots.append(
                "Correlate the organization seed with public documents or breach references, treating all matches as OSINT leads rather than proof."
            )

        if query.usernames or candidates:
            pivots.append(
                "Review the generated public-profile pivot URLs for platforms such as LinkedIn, Instagram, Facebook, GitHub, X, Spotify, Telegram, and Gravatar."
            )

        pivots.append(
            "Treat inferred candidates as review leads until at least two independent public signals correlate."
        )

        return pivots

    def _build_profile_findings(self, profile_pivots: list[ProfilePivot]) -> list[str]:
        """Summarize public-profile resolution checks into investigation findings."""
        findings: list[str] = []
        matched = [pivot for pivot in profile_pivots if pivot.resolution_status == "public_match_possible"]
        if matched:
            findings.append(
                f"{len(matched)} public profile URL(s) returned a resolvable public match signal."
            )
        not_found = [pivot for pivot in profile_pivots if pivot.resolution_status == "not_found"]
        if not_found:
            findings.append(
                f"{len(not_found)} public profile URL(s) returned not found during collection."
            )
        return findings

    def _build_profile_risks(self, profile_pivots: list[ProfilePivot]) -> list[str]:
        """Summarize public-profile resolution checks into investigation risks."""
        risks: list[str] = []
        blocked = [pivot for pivot in profile_pivots if pivot.resolution_status == "blocked_by_platform"]
        if blocked:
            risks.append(
                f"{len(blocked)} platform check(s) were blocked, so account existence remains ambiguous."
            )
        ambiguous = [pivot for pivot in profile_pivots if pivot.resolution_status == "ambiguous"]
        if ambiguous:
            risks.append(
                f"{len(ambiguous)} public profile check(s) were ambiguous and require manual verification."
            )
        return risks

    def _platform_pivots_for_handle(self, handle: str) -> list[ProfilePivot]:
        """Create public-profile pivot suggestions for a single handle."""
        platform_specs = [
            (
                "LinkedIn",
                f"https://www.linkedin.com/in/{handle}/",
                f"https://www.google.com/search?q=site%3Alinkedin.com%2Fin+%22{handle}%22",
            ),
            (
                "Instagram",
                f"https://www.instagram.com/{handle}/",
                f"https://www.google.com/search?q=site%3Ainstagram.com+%22{handle}%22",
            ),
            (
                "Facebook",
                f"https://www.facebook.com/{handle}",
                f"https://www.google.com/search?q=site%3Afacebook.com+%22{handle}%22",
            ),
            (
                "GitHub",
                f"https://github.com/{handle}",
                f"https://www.google.com/search?q=site%3Agithub.com+%22{handle}%22",
            ),
            (
                "X",
                f"https://x.com/{handle}",
                f"https://www.google.com/search?q=site%3Ax.com+%22{handle}%22",
            ),
            (
                "Spotify",
                f"https://open.spotify.com/search/{handle}",
                f"https://www.google.com/search?q=site%3Aopen.spotify.com+%22{handle}%22",
            ),
            (
                "Telegram",
                f"https://t.me/{handle}",
                f"https://www.google.com/search?q=site%3At.me+%22{handle}%22",
            ),
            (
                "Gravatar",
                f"https://gravatar.com/{handle}",
                f"https://www.google.com/search?q=site%3Agravatar.com+%22{handle}%22",
            ),
        ]

        return [
            ProfilePivot(
                platform=platform,
                handle=handle,
                profile_url=profile_url,
                search_url=search_url,
                source="public_profile_pivot",
                confidence="low",
                confidence_score=self._score_profile_pivot(handle),
                status="manual_review",
                review_priority_score=self._score_profile_pivot(handle),
                evidence_strength="weak_inferred",
                decision_reasons=[
                    "Generated as a public URL pattern for manual review.",
                ],
                limitations=[
                    "A generated public-profile URL does not prove the profile exists or belongs to the email subject.",
                ],
                notes=[
                    "Public URL generated for safe manual review.",
                    "Treat matches as possible correlations, not proof of identity ownership.",
                ],
            )
            for platform, profile_url, search_url in platform_specs
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
            "Results are OSINT indicators collected from public or permitted sources and should not be treated as definitive proof.",
            "The workflow does not collect passwords, test credentials, attempt logins, or use illicit sources.",
            "Sensitive details are masked in human-readable outputs when practical, but investigators should still handle exported data carefully.",
            "Absence of breach data or DNS signals does not prove an email or identity is safe, inactive, or nonexistent.",
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
            return ["Public breach data references this email address."]
        if status == "no_breaches":
            return ["No known public HIBP breach record was returned; this is not positive identity evidence."]
        return [f"HIBP status was {status}; treat the result as a limitation, not confirmation."]

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
            (candidate.review_priority_score or candidate.confidence_score, 1.4)
            for candidate in candidate_emails
            if self._candidate_should_be_analyzed(candidate)
        )
        scores.extend((pivot.review_priority_score or pivot.confidence_score, 0.7) for pivot in profile_pivots[:5])
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
        """Build separate confidence-like scores by claim type."""
        valid_candidates = [
            candidate for candidate in candidate_emails if self._candidate_should_be_analyzed(candidate)
        ]
        domain_scores = [
            80 if evidence.evidence_strength == "moderate_format_and_dns" else 35
            for evidence in evidences
            if evidence.category == "domain"
        ]
        profile_scores = [
            pivot.review_priority_score or pivot.confidence_score for pivot in profile_pivots[:5]
        ]
        identity_scores = [
            candidate.review_priority_score
            for candidate in valid_candidates
            if candidate.evidence_strength not in {"none", "weak_inferred"}
        ]

        return {
            "email_format_confidence": self._average(
                [candidate.review_priority_score for candidate in valid_candidates]
            ),
            "domain_confidence": self._average(domain_scores),
            "profile_existence_confidence": self._average(profile_scores),
            "identity_correlation_confidence": self._average(identity_scores),
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
