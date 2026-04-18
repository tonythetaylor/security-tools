import pytest

from security_tools.review.verdict import calculate_verdict, build_verdict_rationale
from security_tools.models import EnrichedFinding, FindingLocation


def make_finding(
    severity: str,
    category: str = "container",
    finding_type: str = "package_vuln",
) -> EnrichedFinding:
    return EnrichedFinding(
        tool="trivy",
        finding_type=finding_type,
        rule_id="TEST-1",
        category=category,
        severity=severity,
        title=f"{severity} finding",
        description="test description",
        location=FindingLocation(path="Dockerfile", line=1, column=1),
        rationale="test rationale",
        suggested_fix="fix it",
        compliance_refs=[],
        metadata={},
        raw_payload={},
    )


@pytest.fixture
def policy() -> dict:
    return {
        "verdict_rules": {
            "operational_error_on_warnings": True,
            "block_if_missing_scans": True,
            "always_block_categories": [],
            "always_block_finding_types": [],
            "block_on_severities": ["critical", "high"],
            "warn_on_severities": ["medium"],
        },
        "risk": {
            "enabled": True,
            "block_if_score_gte": 50,
            "warn_if_score_gte": 20,
        },
    }


def test_pass_when_no_findings_and_no_errors(policy):
    verdict = calculate_verdict(
        findings=[],
        missing_scans=[],
        operational_warnings=[],
        risk_score=0,
        policy=policy,
    )
    assert verdict == "PASS"


def test_warn_on_medium(policy):
    verdict = calculate_verdict(
        findings=[make_finding("medium")],
        missing_scans=[],
        operational_warnings=[],
        risk_score=0,
        policy=policy,
    )
    assert verdict == "WARN"


def test_block_on_high(policy):
    verdict = calculate_verdict(
        findings=[make_finding("high")],
        missing_scans=[],
        operational_warnings=[],
        risk_score=0,
        policy=policy,
    )
    assert verdict == "BLOCK"


def test_block_on_critical(policy):
    verdict = calculate_verdict(
        findings=[make_finding("critical")],
        missing_scans=[],
        operational_warnings=[],
        risk_score=0,
        policy=policy,
    )
    assert verdict == "BLOCK"


def test_block_on_missing_scans(policy):
    verdict = calculate_verdict(
        findings=[],
        missing_scans=["trivy"],
        operational_warnings=[],
        risk_score=0,
        policy=policy,
    )
    assert verdict == "BLOCK"


def test_operational_error_on_warnings(policy):
    verdict = calculate_verdict(
        findings=[],
        missing_scans=[],
        operational_warnings=["parser failed"],
        risk_score=0,
        policy=policy,
    )
    assert verdict == "OPERATIONAL_ERROR"


def test_warn_on_risk_threshold(policy):
    verdict = calculate_verdict(
        findings=[],
        missing_scans=[],
        operational_warnings=[],
        risk_score=20,
        policy=policy,
    )
    assert verdict == "WARN"


def test_block_on_risk_threshold(policy):
    verdict = calculate_verdict(
        findings=[],
        missing_scans=[],
        operational_warnings=[],
        risk_score=50,
        policy=policy,
    )
    assert verdict == "BLOCK"


def test_always_block_category(policy):
    policy["verdict_rules"]["always_block_categories"] = ["secrets"]
    verdict = calculate_verdict(
        findings=[make_finding("low", category="secrets")],
        missing_scans=[],
        operational_warnings=[],
        risk_score=0,
        policy=policy,
    )
    assert verdict == "BLOCK"


def test_always_block_finding_type(policy):
    policy["verdict_rules"]["always_block_finding_types"] = ["hardcoded_secret"]
    verdict = calculate_verdict(
        findings=[make_finding("low", finding_type="hardcoded_secret")],
        missing_scans=[],
        operational_warnings=[],
        risk_score=0,
        policy=policy,
    )
    assert verdict == "BLOCK"


def test_rationale_for_block():
    findings = [make_finding("high")]
    rationale = build_verdict_rationale(
        verdict="BLOCK",
        findings=findings,
        missing_scans=[],
        operational_warnings=[],
        risk_score=0,
    )
    assert "BLOCK" in rationale
    assert "High: 1" in rationale


def test_rationale_for_missing_scans():
    rationale = build_verdict_rationale(
        verdict="BLOCK",
        findings=[],
        missing_scans=["trivy"],
        operational_warnings=[],
        risk_score=0,
    )
    assert "required scans were missing" in rationale


def test_rationale_for_operational_error():
    rationale = build_verdict_rationale(
        verdict="OPERATIONAL_ERROR",
        findings=[],
        missing_scans=[],
        operational_warnings=["parser failed"],
        risk_score=0,
    )
    assert "OPERATIONAL_ERROR" in rationale