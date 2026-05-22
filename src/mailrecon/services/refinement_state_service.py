"""Temporary refinement-state helpers for the latest investigation."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from mailrecon.core.models import InvestigationInput, InvestigationResult


class RefinementStateService:
    """Stores and reapplies manual exclusions for the latest investigation."""

    def __init__(self, state_path: str | Path | None = None) -> None:
        self.state_path = Path(state_path or ".mailrecon-temp/last-investigation-refinement.json")

    def apply_and_store(
        self,
        query: InvestigationInput,
        result: InvestigationResult,
        run_options: dict[str, object] | None = None,
    ) -> InvestigationResult:
        """Apply exclusions from the latest matching refinement file and refresh it."""
        fingerprint = self._fingerprint_query(query)
        excluded_links = self._load_excluded_links(fingerprint)
        refined_result = self._apply_exclusions(result, excluded_links)
        self._write_state(
            query_fingerprint=fingerprint,
            query=query,
            run_options=run_options or {},
            profile_urls=[pivot.profile_url for pivot in result.profile_pivots],
            excluded_links=excluded_links,
        )
        return replace(
            refined_result,
            refinement_file_path=str(self.state_path),
            refinement_excluded_links=sorted(excluded_links),
        )

    def _load_excluded_links(self, query_fingerprint: str) -> set[str]:
        """Load user-supplied exclusions only when they belong to the same query."""
        if not self.state_path.exists():
            return set()

        try:
            payload = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return set()

        if payload.get("query_fingerprint") != query_fingerprint:
            return set()

        raw_links = payload.get("excluded_profile_urls", [])
        return {link for link in raw_links if isinstance(link, str) and link.strip()}

    def _write_state(
        self,
        query_fingerprint: str,
        query: InvestigationInput,
        run_options: dict[str, object],
        profile_urls: list[str],
        excluded_links: set[str],
    ) -> None:
        """Write a simple refinement template that the investigator can revisit."""
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "query_fingerprint": query_fingerprint,
            "query": {
                "names": query.names,
                "emails": query.emails,
                "usernames": query.usernames,
                "domains": query.domains,
                "organizations": query.organizations,
                "contexts": query.contexts,
                "candidate_emails": query.candidate_emails,
            },
            "run_options": run_options,
            "instructions": (
                "Add public-profile links that were manually disproved to "
                "'excluded_profile_urls' and rerun the same investigation to hide them."
            ),
            "excluded_profile_urls": sorted(excluded_links),
            "suggested_profile_urls": profile_urls,
        }
        self.state_path.write_text(
            json.dumps(payload, indent=2),
            encoding="utf-8",
        )

    def load_last_investigation(self) -> tuple[InvestigationInput, dict[str, object]]:
        """Load the latest saved investigation query and its reusable run options."""
        if not self.state_path.exists():
            raise ValueError("No saved investigation refinement file was found.")

        try:
            payload = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("The saved investigation refinement file is unreadable.") from exc

        query_data = payload.get("query")
        if not isinstance(query_data, dict):
            raise ValueError("The saved refinement file does not contain investigation parameters.")

        query = InvestigationInput(
            names=self._coerce_string_list(query_data.get("names")),
            emails=self._coerce_string_list(query_data.get("emails")),
            usernames=self._coerce_string_list(query_data.get("usernames")),
            domains=self._coerce_string_list(query_data.get("domains")),
            organizations=self._coerce_string_list(query_data.get("organizations")),
            contexts=self._coerce_string_list(query_data.get("contexts")),
            candidate_emails=self._coerce_string_list(query_data.get("candidate_emails")),
        )
        run_options = payload.get("run_options", {})
        if not isinstance(run_options, dict):
            run_options = {}
        return query, run_options

    def _apply_exclusions(
        self,
        result: InvestigationResult,
        excluded_links: set[str],
    ) -> InvestigationResult:
        """Remove excluded public-profile links from the visible investigation output."""
        if not excluded_links:
            return result

        filtered_pivots = [
            pivot for pivot in result.profile_pivots if pivot.profile_url not in excluded_links
        ]
        filtered_evidences = [
            evidence
            for evidence in result.evidences
            if not (
                evidence.category == "public_profile"
                and evidence.reference in excluded_links
            )
        ]
        filtered_limitations = list(result.limitations)
        filtered_limitations.append(
            f"{len(excluded_links)} public-profile link(s) were manually excluded through the refinement file."
        )
        return replace(
            result,
            profile_pivots=filtered_pivots,
            evidences=filtered_evidences,
            limitations=filtered_limitations,
        )

    def _fingerprint_query(self, query: InvestigationInput) -> str:
        """Build a stable fingerprint for the latest investigation seeds."""
        normalized = {
            "names": sorted(item.strip().lower() for item in query.names if item.strip()),
            "emails": sorted(item.strip().lower() for item in query.emails if item.strip()),
            "usernames": sorted(item.strip().lower() for item in query.usernames if item.strip()),
            "domains": sorted(item.strip().lower() for item in query.domains if item.strip()),
            "organizations": sorted(
                item.strip().lower() for item in query.organizations if item.strip()
            ),
            "contexts": sorted(item.strip().lower() for item in query.contexts if item.strip()),
            "candidate_emails": sorted(
                item.strip().lower() for item in query.candidate_emails if item.strip()
            ),
        }
        digest = hashlib.sha256(
            json.dumps(normalized, sort_keys=True).encode("utf-8")
        ).hexdigest()
        return digest

    def _coerce_string_list(self, value: object) -> list[str]:
        """Safely coerce persisted JSON arrays back into string lists."""
        if not isinstance(value, list):
            return []
        return [item for item in value if isinstance(item, str)]
