from __future__ import annotations

from security_tools.intelligence.ingest.models import ExtractedSection
from security_tools.intelligence.models import ComplianceReference, KnowledgeDocument


CIS_CONTROL_MAPPINGS: dict[str, dict] = {
    "01": {
        "category": "asset_security",
        "applies_to": ["asset_inventory", "asset_management", "unauthorized_assets"],
        "tags": ["asset-inventory", "enterprise-assets", "visibility"],
    },
    "02": {
        "category": "software_security",
        "applies_to": ["software_inventory", "software_asset_management", "unauthorized_software"],
        "tags": ["software-inventory", "software-assets", "asset-management"],
    },
    "03": {
        "category": "data_security",
        "applies_to": ["data_protection", "data_management", "data_recovery"],
        "tags": ["data-protection", "recovery", "retention"],
    },
    "04": {
        "category": "configuration_security",
        "applies_to": ["secure_configuration", "hardening", "baseline_configuration"],
        "tags": ["hardening", "configuration", "baseline"],
    },
    "05": {
        "category": "identity_security",
        "applies_to": ["account_management", "identity_lifecycle", "privileged_accounts"],
        "tags": ["accounts", "identity", "privilege"],
    },
    "06": {
        "category": "access_security",
        "applies_to": ["access_control", "authorization", "least_privilege"],
        "tags": ["access-control", "authorization", "least-privilege"],
    },
    "07": {
        "category": "vulnerability_management",
        "applies_to": ["vulnerability_management", "container_scanning", "dependency_scan", "patch_management"],
        "tags": ["vulnerabilities", "patching", "scanning"],
    },
    "08": {
        "category": "logging_security",
        "applies_to": ["audit_logging", "log_management", "security_monitoring"],
        "tags": ["logging", "audit", "monitoring"],
    },
    "09": {
        "category": "email_web_security",
        "applies_to": ["browser_security", "email_security", "content_filtering"],
        "tags": ["email", "browser", "protections"],
    },
    "10": {
        "category": "endpoint_security",
        "applies_to": ["malware_defense", "endpoint_protection", "anti_malware"],
        "tags": ["malware", "endpoint", "defense"],
    },
    "11": {
        "category": "resilience_security",
        "applies_to": ["backup", "data_recovery", "restoration"],
        "tags": ["backup", "recovery", "resilience"],
    },
    "12": {
        "category": "network_security",
        "applies_to": ["network_infrastructure", "network_hardening", "network_management"],
        "tags": ["network", "infrastructure", "management"],
    },
    "13": {
        "category": "network_defense",
        "applies_to": ["network_monitoring", "network_defense", "traffic_analysis"],
        "tags": ["network-monitoring", "defense", "traffic"],
    },
    "14": {
        "category": "training_security",
        "applies_to": ["security_training", "awareness", "skills_development"],
        "tags": ["training", "awareness", "skills"],
    },
    "15": {
        "category": "third_party_security",
        "applies_to": ["service_provider_management", "third_party_risk", "vendor_security"],
        "tags": ["vendors", "service-providers", "third-party"],
    },
    "16": {
        "category": "application_security",
        "applies_to": ["sast", "secure_sdlc", "application_security", "dependency_scan", "third_party_components"],
        "tags": ["appsec", "sast", "secure-development", "third-party-code"],
    },
    "17": {
        "category": "incident_response",
        "applies_to": ["incident_response", "response_process", "security_operations"],
        "tags": ["incident-response", "response", "operations"],
    },
    "18": {
        "category": "assurance_security",
        "applies_to": ["penetration_testing", "security_validation", "assurance_testing"],
        "tags": ["penetration-testing", "validation", "assurance"],
    },
}


CIS_SAFEGUARD_MAPPINGS: dict[str, dict] = {
    "07.1": {
        "category": "vulnerability_management",
        "applies_to": ["vulnerability_inventory", "vulnerability_management", "risk_tracking"],
        "tags": ["vulnerabilities", "inventory", "tracking"],
    },
    "07.2": {
        "category": "vulnerability_management",
        "applies_to": ["remediation_process", "vulnerability_management", "risk_based_remediation", "patch_management"],
        "tags": ["remediation", "risk-based", "patching", "vulnerabilities"],
    },
    "07.3": {
        "category": "vulnerability_management",
        "applies_to": ["automated_scanning", "vulnerability_management", "continuous_scanning"],
        "tags": ["scanning", "automation", "vulnerabilities"],
    },
    "16.1": {
        "category": "application_security",
        "applies_to": ["secure_sdlc", "secure_development_process", "application_security"],
        "tags": ["appsec", "secure-development", "sdlc"],
    },
    "16.2": {
        "category": "application_security",
        "applies_to": ["vulnerability_intake", "application_vulnerability_management", "remediation_workflow"],
        "tags": ["vulnerability-intake", "appsec", "remediation"],
    },
    "16.3": {
        "category": "application_security",
        "applies_to": ["third_party_components", "dependency_scan", "software_supply_chain"],
        "tags": ["third-party-code", "dependencies", "supply-chain"],
    },
    "16.6": {
        "category": "application_security",
        "applies_to": ["dependency_scan", "third_party_components", "software_composition_analysis"],
        "tags": ["dependency-scanning", "sca", "third-party-code"],
    },
    "18.1": {
        "category": "assurance_security",
        "applies_to": ["penetration_testing", "security_validation"],
        "tags": ["penetration-testing", "validation"],
    },
}


def map_cis_section(section: ExtractedSection) -> KnowledgeDocument:
    level = str(section.metadata.get("level", "")).lower()
    control_id = str(section.metadata.get("control_id") or "").zfill(2)
    safeguard_id = str(section.metadata.get("safeguard_id") or "")

    if level == "safeguard" and safeguard_id:
        mapping = CIS_SAFEGUARD_MAPPINGS.get(safeguard_id, {})
        category = mapping.get("category", CIS_CONTROL_MAPPINGS.get(control_id, {}).get("category", "cis_security"))
        applies_to = mapping.get("applies_to", CIS_CONTROL_MAPPINGS.get(control_id, {}).get("applies_to", []))
        tags = sorted(set(section.tags + mapping.get("tags", []) + CIS_CONTROL_MAPPINGS.get(control_id, {}).get("tags", [])))

        refs = [
            ComplianceReference(
                framework="CIS Controls v8",
                control=f"Control {control_id}",
                note=f"Safeguard {safeguard_id}",
            )
        ]

        doc_id = f"cis-{safeguard_id.replace('.', '-')}"
        title = section.title
    else:
        mapping = CIS_CONTROL_MAPPINGS.get(control_id, {})
        category = mapping.get("category", section.category or "cis_security")
        applies_to = mapping.get("applies_to", [])
        tags = sorted(set(section.tags + mapping.get("tags", [])))

        refs = [
            ComplianceReference(
                framework="CIS Controls v8",
                control=f"Control {control_id}",
            )
        ]

        doc_id = f"cis-{control_id.lower() or 'unknown'}"
        title = section.title

    return KnowledgeDocument(
        id=doc_id,
        title=title,
        category=category,
        applies_to=applies_to,
        tags=tags,
        severity_guidance="medium",
        description=section.body[:4000],
        rationale=section.body[:4000],
        developer_guidance=section.body[:4000],
        recommended_patterns=[],
        bad_examples=[],
        good_examples=[],
        compliance_refs=refs,
        risk_context={},
        ownership={},
        remediation={},
        source_path=section.source_file,
        source_type="cis",
    )