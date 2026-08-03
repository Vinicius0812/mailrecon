"""Safe public-profile resolution helpers."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone

import httpx

from mailrecon.core.models import EvidenceRecord, ProfilePivot


class ProfileCheckService:
    """Checks only public profile URLs or simulated lab scenarios."""

    def __init__(self, timeout: float = 10.0) -> None:
        self.timeout = timeout

    def check_public_profile(self, pivot: ProfilePivot) -> tuple[ProfilePivot, EvidenceRecord]:
        """Resolve a public profile URL conservatively.

        Real-world note:
        Keep this method limited to public pages or official documented APIs.
        Do not use login flows, password recovery, hidden endpoints, or any
        automated credential-related path to infer account existence.
        """
        checked_at = datetime.now(timezone.utc).isoformat()
        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                response = client.get(pivot.profile_url)
        except httpx.TimeoutException:
            updated = replace(
                pivot,
                resolution_status="timeout",
                status="blocked_cannot_determine",
                checked_at=checked_at,
                review_priority_score=self._score_resolution_status("timeout", pivot.confidence_score),
                ambiguity_reasons=pivot.ambiguity_reasons + ["timeout"],
                decision_reasons=pivot.decision_reasons + ["Public profile check timed out."],
                limitations=pivot.limitations + ["Timeout prevents determining whether the public profile exists."],
                notes=pivot.notes + ["Public profile check timed out."],
            )
            return updated, self._build_evidence(updated, "timeout")
        except httpx.HTTPError as exc:
            updated = replace(
                pivot,
                resolution_status="request_error",
                status="blocked_cannot_determine",
                checked_at=checked_at,
                review_priority_score=self._score_resolution_status("request_error", pivot.confidence_score),
                ambiguity_reasons=pivot.ambiguity_reasons + ["request_error"],
                decision_reasons=pivot.decision_reasons + [f"Public profile check failed: {exc}"],
                limitations=pivot.limitations + ["Request errors prevent determining whether the public profile exists."],
                notes=pivot.notes + [f"Public profile check failed: {exc}"],
            )
            return updated, self._build_evidence(updated, "request_error")

        status = self._map_http_status(response.status_code, str(response.url))
        confidence_score = self._score_resolution_status(status, pivot.confidence_score)
        status_label = self._workflow_status_for_resolution(status)
        ambiguity_reasons = pivot.ambiguity_reasons + self._ambiguity_reasons_for_resolution(
            status,
            str(response.url),
        )
        updated = replace(
            pivot,
            status=status_label,
            resolution_status=status,
            http_status_code=response.status_code,
            final_url=str(response.url),
            checked_at=checked_at,
            confidence_score=confidence_score,
            review_priority_score=confidence_score,
            evidence_strength=self._evidence_strength_for_resolution(status),
            ambiguity_reasons=ambiguity_reasons,
            matched_fields=pivot.matched_fields + self._matched_fields_for_resolution(status),
            missing_fields=pivot.missing_fields + self._missing_fields_for_resolution(status),
            decision_reasons=pivot.decision_reasons + self._decision_reasons_for_resolution(status),
            limitations=pivot.limitations + self._limitations_for_resolution(status),
        )
        return updated, self._build_evidence(updated, status)

    def simulate_profile_check(
        self,
        pivot: ProfilePivot,
        scenario: str,
    ) -> tuple[ProfilePivot, EvidenceRecord]:
        """Simulate profile checks in a controlled lab-only workflow.

        Real-world note:
        This is intentionally synthetic so you can study classification logic
        without probing real services beyond public pages.
        """
        scenario_map = {
            "found": ("public_match_possible", 200),
            "not-found": ("not_found", 404),
            "ambiguous": ("ambiguous", 302),
            "blocked": ("blocked_by_platform", 403),
            "rate-limited": ("rate_limited", 429),
        }
        status, http_status = scenario_map.get(scenario, ("ambiguous", 200))
        checked_at = datetime.now(timezone.utc).isoformat()
        updated = replace(
            pivot,
            status=self._workflow_status_for_resolution(status),
            resolution_status=status,
            http_status_code=http_status,
            final_url=pivot.profile_url,
            checked_at=checked_at,
            confidence_score=self._score_resolution_status(status, pivot.confidence_score),
            review_priority_score=self._score_resolution_status(status, pivot.confidence_score),
            evidence_strength=self._evidence_strength_for_resolution(status),
            ambiguity_reasons=pivot.ambiguity_reasons + self._ambiguity_reasons_for_resolution(
                status,
                pivot.profile_url,
            ),
            matched_fields=pivot.matched_fields + self._matched_fields_for_resolution(status),
            missing_fields=pivot.missing_fields + self._missing_fields_for_resolution(status),
            decision_reasons=pivot.decision_reasons
            + self._decision_reasons_for_resolution(status)
            + [f"Lab-only scenario applied: {scenario}."],
            limitations=pivot.limitations + self._limitations_for_resolution(status),
            notes=pivot.notes + [f"Lab-only scenario applied: {scenario}."],
        )
        return updated, self._build_evidence(updated, status, method="lab_public_profile_check")

    def _build_evidence(
        self,
        pivot: ProfilePivot,
        status: str,
        method: str = "public_profile_check",
    ) -> EvidenceRecord:
        """Create a structured evidence record for one public profile check."""
        summary = (
            f"Public profile check for {pivot.platform}/{pivot.handle} returned status {status}."
        )
        observations = (
            f"http_status={pivot.http_status_code}, final_url={pivot.final_url}"
            if pivot.http_status_code is not None
            else None
        )
        return EvidenceRecord(
            title="Public profile resolution",
            category="public_profile",
            source=pivot.platform,
            reference=pivot.profile_url,
            collected_at=pivot.checked_at or datetime.now(timezone.utc).isoformat(),
            method=method,
            confidence=self._confidence_label(status),
            confidence_score=pivot.confidence_score,
            summary=summary,
            observations=observations,
            evidence_strength=pivot.evidence_strength,
            risk_level=pivot.risk_level,
            decision_reasons=list(pivot.decision_reasons),
            limitations=list(pivot.limitations),
        )

    def _map_http_status(self, http_status: int, final_url: str = "") -> str:
        """Map an HTTP status to a conservative public-profile resolution state."""
        if http_status == 404:
            return "not_found"
        if http_status in {401, 403}:
            return "blocked_by_platform"
        if http_status == 429:
            return "rate_limited"
        if http_status in {200, 301, 302, 307, 308}:
            if self._looks_like_soft_block_or_search(final_url):
                return "ambiguous"
            return "public_match_possible"
        return "ambiguous"

    def _looks_like_soft_block_or_search(self, final_url: str) -> bool:
        """Detect common final URLs that are not strong public-profile evidence."""
        normalized = final_url.lower()
        ambiguous_markers = (
            "/auth",
            "/challenge",
            "/checkpoint",
            "/consent",
            "/error",
            "/explore",
            "/login",
            "/search",
            "/signin",
            "/unavailable",
        )
        return any(marker in normalized for marker in ambiguous_markers)

    def _score_resolution_status(self, status: str, base_score: int) -> int:
        """Return a conservative review-priority score for a profile resolution."""
        caps = {
            "public_match_possible": 45,
            "not_found": 0,
            "blocked_by_platform": 25,
            "rate_limited": 25,
            "timeout": 20,
            "request_error": 20,
            "ambiguous": 25,
        }
        return max(0, min(caps.get(status, 25), base_score))

    def _confidence_label(self, status: str) -> str:
        """Return a coarse confidence label for a profile resolution status."""
        if status == "public_match_possible":
            return "medium"
        if status in {"ambiguous", "blocked_by_platform", "rate_limited"}:
            return "low"
        return "low"

    def _workflow_status_for_resolution(self, status: str) -> str:
        """Map resolution states to explicit workflow states."""
        mapping = {
            "public_match_possible": "retained_for_manual_review",
            "not_found": "rejected_profile_not_found",
            "blocked_by_platform": "blocked_cannot_determine",
            "rate_limited": "blocked_cannot_determine",
            "timeout": "blocked_cannot_determine",
            "request_error": "blocked_cannot_determine",
            "ambiguous": "ambiguous_requires_review",
        }
        return mapping.get(status, "ambiguous_requires_review")

    def _evidence_strength_for_resolution(self, status: str) -> str:
        """Return evidence strength for a public-profile resolution."""
        if status == "public_match_possible":
            return "weak_public_http"
        return "none" if status == "not_found" else "weak_public_http"

    def _ambiguity_reasons_for_resolution(self, status: str, final_url: str) -> list[str]:
        """Return structured ambiguity reasons for profile checks."""
        if status == "ambiguous":
            if self._looks_like_soft_block_or_search(final_url):
                return ["login_search_or_challenge_redirect"]
            return ["http_success_without_profile_specific_evidence"]
        if status in {"blocked_by_platform", "rate_limited", "timeout", "request_error"}:
            return [status]
        return []

    def _matched_fields_for_resolution(self, status: str) -> list[str]:
        """Return fields that were weakly matched by the public check."""
        if status == "public_match_possible":
            return ["profile_url_resolved"]
        return []

    def _missing_fields_for_resolution(self, status: str) -> list[str]:
        """Return fields still missing after the public check."""
        if status == "public_match_possible":
            return ["independent_identity_correlation"]
        if status == "not_found":
            return ["public_profile"]
        return ["deterministic_profile_state"]

    def _decision_reasons_for_resolution(self, status: str) -> list[str]:
        """Explain the profile resolution decision."""
        mapping = {
            "public_match_possible": [
                "Public URL returned a resolvable page signal.",
                "HTTP success alone is retained only as weak public evidence.",
            ],
            "not_found": ["Public URL returned not found and is rejected as a profile lead."],
            "blocked_by_platform": ["Platform blocked the public check, so existence remains ambiguous."],
            "rate_limited": ["Platform rate-limited the public check, so existence remains ambiguous."],
            "timeout": ["Public profile check timed out."],
            "request_error": ["Public profile check returned a request error."],
            "ambiguous": ["Public profile signal is ambiguous and requires manual review."],
        }
        return mapping.get(status, ["Public profile signal requires manual review."])

    def _limitations_for_resolution(self, status: str) -> list[str]:
        """Explain why profile checks do not confirm identity ownership."""
        limitations = [
            "Public profile checks do not use login, recovery, credential, or hidden endpoints.",
            "A reachable profile URL does not prove ownership by the email subject.",
        ]
        if status == "public_match_possible":
            limitations.append("Independent public correlation is required before treating this as probable.")
        return limitations
