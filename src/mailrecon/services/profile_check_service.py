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
                checked_at=checked_at,
                notes=pivot.notes + ["Public profile check timed out."],
            )
            return updated, self._build_evidence(updated, "timeout")
        except httpx.HTTPError as exc:
            updated = replace(
                pivot,
                resolution_status="request_error",
                checked_at=checked_at,
                notes=pivot.notes + [f"Public profile check failed: {exc}"],
            )
            return updated, self._build_evidence(updated, "request_error")

        status = self._map_http_status(response.status_code)
        confidence_score = self._score_resolution_status(status, pivot.confidence_score)
        updated = replace(
            pivot,
            status="reviewed_public_url",
            resolution_status=status,
            http_status_code=response.status_code,
            final_url=str(response.url),
            checked_at=checked_at,
            confidence_score=confidence_score,
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
            status="lab_reviewed_public_url",
            resolution_status=status,
            http_status_code=http_status,
            final_url=pivot.profile_url,
            checked_at=checked_at,
            confidence_score=self._score_resolution_status(status, pivot.confidence_score),
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
        )

    def _map_http_status(self, http_status: int) -> str:
        """Map an HTTP status to a conservative public-profile resolution state."""
        if http_status == 404:
            return "not_found"
        if http_status in {401, 403}:
            return "blocked_by_platform"
        if http_status == 429:
            return "rate_limited"
        if http_status in {200, 301, 302, 307, 308}:
            return "public_match_possible"
        return "ambiguous"

    def _score_resolution_status(self, status: str, base_score: int) -> int:
        """Adjust the base score using the public-resolution outcome."""
        adjustments = {
            "public_match_possible": 20,
            "not_found": -10,
            "blocked_by_platform": -5,
            "rate_limited": -10,
            "timeout": -15,
            "request_error": -20,
            "ambiguous": 0,
        }
        adjusted = base_score + adjustments.get(status, 0)
        return max(0, min(100, adjusted))

    def _confidence_label(self, status: str) -> str:
        """Return a coarse confidence label for a profile resolution status."""
        if status == "public_match_possible":
            return "medium"
        if status in {"ambiguous", "blocked_by_platform", "rate_limited"}:
            return "low"
        return "low"
