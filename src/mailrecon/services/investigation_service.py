"""Reusable OSINT investigation helpers."""

from __future__ import annotations

from collections import OrderedDict
from datetime import datetime, timezone
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

            if candidate.status != "valid":
                continue

            self._notify(progress_callback, f"Analyzing candidate email: {candidate.email}")
            analysis = self.recon_service.analyze_email(
                candidate.email,
                progress_callback=progress_callback,
            )
            candidate.analysis = analysis

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
        overall_confidence_score = self._build_overall_confidence_score(
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
            overall_confidence_score=overall_confidence_score,
        )

    def _ensure_useful_query(self, query: InvestigationInput) -> None:
        """Require at least one meaningful investigation seed."""
        if any(
            (
                query.names,
                query.emails,
                query.usernames,
                query.domains,
                query.organizations,
                query.contexts,
                query.candidate_emails,
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
            cleaned_username = username.strip().lower()
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
            cleaned = username.strip().lower()
            if cleaned:
                handles[cleaned] = None

        for name in query.names:
            for pattern in self._infer_name_patterns(name):
                handles[pattern] = None

        for candidate in candidates:
            if candidate.status == "valid":
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
                confidence=confidence,
                confidence_score=10,
                status="invalid",
                notes=[normalized_or_error],
            )

        score = self._score_email_candidate(source=source)
        return EmailCandidate(
            email=normalized_or_error,
            masked_email=mask_email_address(normalized_or_error),
            domain=domain,
            source=source,
            confidence=confidence,
            confidence_score=score,
            status="valid",
        )

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
                notes=[
                    "Public URL generated for safe manual review.",
                    "Treat matches as possible correlations, not proof of identity ownership.",
                ],
            )
            for platform, profile_url, search_url in platform_specs
        ]

    def _build_limitations(self) -> list[str]:
        """Return standard investigation limitations for ethical OSINT use."""
        return [
            "Results are OSINT indicators collected from public or permitted sources and should not be treated as definitive proof.",
            "The workflow does not collect passwords, test credentials, attempt logins, or use illicit sources.",
            "Sensitive details are masked in human-readable outputs when practical, but investigators should still handle exported data carefully.",
            "Absence of breach data or DNS signals does not prove an email or identity is safe, inactive, or nonexistent.",
        ]

    def _score_email_candidate(self, source: str) -> int:
        """Return a simple confidence score for an email candidate source."""
        mapping = {
            "seed_email": 90,
            "provided_candidate": 75,
            "username_domain_inference": 60,
            "name_domain_inference": 45,
        }
        return mapping.get(source, 40)

    def _score_hibp_evidence(self, status: str) -> int:
        """Return a confidence score for HIBP-derived evidence."""
        mapping = {
            "breaches_found": 85,
            "no_breaches": 60,
            "missing_api_key": 25,
            "disabled": 20,
            "timeout": 25,
            "request_error": 20,
            "unauthorized": 15,
            "forbidden": 15,
            "rate_limited": 20,
            "http_error": 20,
        }
        return mapping.get(status, 25)

    def _score_profile_pivot(self, handle: str) -> int:
        """Return a basic score for public profile pivots."""
        if "." in handle or "_" in handle:
            return 50
        if len(handle) >= 6:
            return 55
        return 40

    def _build_overall_confidence_score(
        self,
        candidate_emails: list[EmailCandidate],
        profile_pivots: list[ProfilePivot],
        evidences: list[EvidenceRecord],
    ) -> int:
        """Build an overall score that summarizes how actionable the investigation looks."""
        scores: list[int] = []
        scores.extend(candidate.confidence_score for candidate in candidate_emails if candidate.status == "valid")
        scores.extend(pivot.confidence_score for pivot in profile_pivots[:5])
        scores.extend(evidence.confidence_score for evidence in evidences[:5])
        if not scores:
            return 0
        return round(sum(scores) / len(scores))

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
