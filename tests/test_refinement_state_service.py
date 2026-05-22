import json

from mailrecon.core.models import (
    EvidenceRecord,
    InvestigationInput,
    InvestigationResult,
    ProfilePivot,
)
from mailrecon.services.refinement_state_service import RefinementStateService


def build_result() -> InvestigationResult:
    return InvestigationResult(
        query=InvestigationInput(
            usernames=["user"],
            domains=["example.com"],
        ),
        candidate_emails=[],
        profile_pivots=[
            ProfilePivot(
                platform="LinkedIn",
                handle="user",
                profile_url="https://www.linkedin.com/in/user/",
                search_url="https://www.google.com/search?q=site%3Alinkedin.com",
                source="public_profile_pivot",
                confidence="low",
                confidence_score=50,
                status="manual_review",
            ),
            ProfilePivot(
                platform="GitHub",
                handle="user",
                profile_url="https://github.com/user",
                search_url="https://www.google.com/search?q=site%3Agithub.com",
                source="public_profile_pivot",
                confidence="low",
                confidence_score=55,
                status="manual_review",
            ),
        ],
        evidences=[
            EvidenceRecord(
                title="Public profile resolution",
                category="public_profile",
                source="LinkedIn",
                reference="https://www.linkedin.com/in/user/",
                collected_at="2026-05-21T12:00:00+00:00",
                method="public_profile_check",
                confidence="medium",
                confidence_score=70,
                summary="LinkedIn public profile resolved.",
            ),
            EvidenceRecord(
                title="Seed username",
                category="seed",
                source="investigator_input",
                reference="CLI input",
                collected_at="2026-05-21T12:00:00+00:00",
                method="manual_input",
                confidence="high",
                confidence_score=80,
                summary="Seed username user.",
            ),
        ],
        findings=["Two public profile URL(s) were generated."],
        risks=[],
        pivot_suggestions=[],
        limitations=["Results are OSINT indicators."],
        overall_confidence_score=60,
    )


def test_refinement_state_service_writes_template(tmp_path) -> None:
    service = RefinementStateService(tmp_path / "last-refinement.json")
    result = service.apply_and_store(
        build_result().query,
        build_result(),
        run_options={
            "use_hibp": False,
            "check_public_profiles": True,
            "lab_profile_scenario": None,
        },
    )

    payload = json.loads((tmp_path / "last-refinement.json").read_text(encoding="utf-8"))
    assert payload["excluded_profile_urls"] == []
    assert len(payload["suggested_profile_urls"]) == 2
    assert payload["query"]["usernames"] == ["user"]
    assert payload["run_options"]["check_public_profiles"] is True
    assert result.refinement_file_path is not None


def test_refinement_state_service_applies_matching_exclusions(tmp_path) -> None:
    state_path = tmp_path / "last-refinement.json"
    service = RefinementStateService(state_path)
    query = build_result().query

    initial = service.apply_and_store(query, build_result())
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    payload["excluded_profile_urls"] = ["https://www.linkedin.com/in/user/"]
    state_path.write_text(json.dumps(payload), encoding="utf-8")

    refined = service.apply_and_store(query, build_result())

    assert len(initial.profile_pivots) == 2
    assert len(refined.profile_pivots) == 1
    assert refined.profile_pivots[0].platform == "GitHub"
    assert refined.refinement_excluded_links == ["https://www.linkedin.com/in/user/"]
    assert all(
        evidence.reference != "https://www.linkedin.com/in/user/"
        for evidence in refined.evidences
        if evidence.category == "public_profile"
    )
    assert any("manually excluded" in limitation for limitation in refined.limitations)


def test_refinement_state_service_can_reload_last_query(tmp_path) -> None:
    state_path = tmp_path / "last-refinement.json"
    service = RefinementStateService(state_path)
    original_query = build_result().query

    service.apply_and_store(
        original_query,
        build_result(),
        run_options={
            "use_hibp": True,
            "check_public_profiles": False,
            "lab_profile_scenario": "found",
        },
    )

    loaded_query, loaded_options = service.load_last_investigation()

    assert loaded_query.usernames == original_query.usernames
    assert loaded_query.domains == original_query.domains
    assert loaded_options["use_hibp"] is True
    assert loaded_options["lab_profile_scenario"] == "found"
