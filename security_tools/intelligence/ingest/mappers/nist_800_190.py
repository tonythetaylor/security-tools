from __future__ import annotations

from security_tools.intelligence.ingest.models import ExtractedSection
from security_tools.intelligence.models import ComplianceReference, KnowledgeDocument


NIST_800_190_SECTION_MAPPINGS: dict[str, dict] = {
    "3.1": {
        "category": "container_security",
        "applies_to": ["image_security", "container_scanning", "image_hardening"],
        "tags": ["images", "containers", "image-security"],
    },
    "3.1.1": {
        "category": "container_security",
        "applies_to": ["image_vulnerabilities", "container_scanning", "vulnerability_management"],
        "tags": ["images", "vulnerabilities", "container-scanning"],
    },
    "3.1.2": {
        "category": "container_security",
        "applies_to": ["image_configuration", "dockerfile_scan", "secure_configuration"],
        "tags": ["images", "configuration", "hardening"],
    },
    "3.1.4": {
        "category": "secret_security",
        "applies_to": ["secret_detection", "embedded_secrets", "image_security"],
        "tags": ["secrets", "images", "secret-detection"],
    },
    "3.1.5": {
        "category": "supply_chain_security",
        "applies_to": ["trusted_images", "image_provenance", "software_supply_chain"],
        "tags": ["trusted-images", "provenance", "supply-chain"],
    },
    "4.1.1": {
        "category": "container_security",
        "applies_to": ["image_vulnerabilities", "container_scanning", "vulnerability_management"],
        "tags": ["countermeasures", "images", "vulnerabilities"],
    },
    "4.1.2": {
        "category": "configuration_security",
        "applies_to": ["image_configuration", "dockerfile_scan", "hardening"],
        "tags": ["countermeasures", "configuration", "hardening"],
    },
    "4.1.4": {
        "category": "secret_security",
        "applies_to": ["secret_detection", "embedded_secrets", "image_security"],
        "tags": ["countermeasures", "secrets", "images"],
    },
    "4.1.5": {
        "category": "supply_chain_security",
        "applies_to": ["trusted_images", "registry_policy", "software_supply_chain"],
        "tags": ["countermeasures", "trusted-images", "registry"],
    },
    "4.2": {
        "category": "registry_security",
        "applies_to": ["registry_security", "registry_access", "artifact_management"],
        "tags": ["registry", "artifacts", "containers"],
    },
    "4.2.1": {
        "category": "transport_security",
        "applies_to": ["https", "registry_tls", "secure_transport"],
        "tags": ["registry", "tls", "transport-security"],
    },
    "4.2.2": {
        "category": "artifact_security",
        "applies_to": ["stale_images", "artifact_lifecycle", "registry_hygiene"],
        "tags": ["registry", "stale-images", "lifecycle"],
    },
    "4.2.3": {
        "category": "identity_security",
        "applies_to": ["registry_authz", "registry_authn", "least_privilege"],
        "tags": ["registry", "authentication", "authorization"],
    },
    "4.3": {
        "category": "orchestrator_security",
        "applies_to": ["orchestrator_security", "cluster_security", "kubernetes_security"],
        "tags": ["orchestrator", "cluster", "kubernetes"],
    },
    "4.3.3": {
        "category": "network_security",
        "applies_to": ["network_segmentation", "inter_container_traffic", "kubernetes_network_policy"],
        "tags": ["network", "segmentation", "containers"],
    },
    "4.3.4": {
        "category": "workload_security",
        "applies_to": ["workload_separation", "environment_separation", "sensitivity_segmentation"],
        "tags": ["workloads", "segmentation", "defense-in-depth"],
    },
    "4.4": {
        "category": "runtime_security",
        "applies_to": ["runtime_security", "container_runtime", "container_hardening"],
        "tags": ["runtime", "containers", "hardening"],
    },
    "4.4.1": {
        "category": "runtime_security",
        "applies_to": ["runtime_vulnerabilities", "runtime_hardening", "container_runtime"],
        "tags": ["runtime", "vulnerabilities", "containers"],
    },
    "4.4.2": {
        "category": "network_security",
        "applies_to": ["egress_control", "network_policy", "runtime_network_access"],
        "tags": ["runtime", "network", "egress"],
    },
    "4.4.3": {
        "category": "configuration_security",
        "applies_to": ["runtime_configuration", "container_hardening", "least_privilege"],
        "tags": ["runtime", "configuration", "hardening"],
    },
    "4.4.4": {
        "category": "application_security",
        "applies_to": ["application_vulnerabilities", "sast", "application_security"],
        "tags": ["runtime", "appsec", "vulnerabilities"],
    },
    "4.5": {
        "category": "host_security",
        "applies_to": ["host_os_security", "container_host_hardening", "platform_security"],
        "tags": ["host-os", "hardening", "containers"],
    },
    "4.5.1": {
        "category": "host_security",
        "applies_to": ["attack_surface_reduction", "minimal_host_os", "host_hardening"],
        "tags": ["host-os", "attack-surface", "hardening"],
    },
    "4.5.3": {
        "category": "host_security",
        "applies_to": ["host_vulnerabilities", "patch_management", "host_hardening"],
        "tags": ["host-os", "vulnerabilities", "patching"],
    },
    "6.1": {
        "category": "governance_security",
        "applies_to": ["container_adoption", "process_change", "security_training"],
        "tags": ["governance", "operations", "training"],
    },
    "6.2": {
        "category": "design_security",
        "applies_to": ["container_design", "forensics", "incident_readiness"],
        "tags": ["design", "forensics", "incident-response"],
    },
    "6.3": {
        "category": "implementation_security",
        "applies_to": ["implementation", "prototype_testing", "security_validation"],
        "tags": ["implementation", "testing", "validation"],
    },
    "6.4": {
        "category": "operations_security",
        "applies_to": ["operations", "maintenance", "continuous_monitoring"],
        "tags": ["operations", "maintenance", "monitoring"],
    },
}


def map_nist_800_190_section(section: ExtractedSection) -> KnowledgeDocument:
    section_id = str(section.metadata.get("section_id") or section.section_id or "")
    mapping = NIST_800_190_SECTION_MAPPINGS.get(section_id, {})

    category = mapping.get("category", section.category or "container_security_guidance")
    applies_to = mapping.get(
        "applies_to",
        ["container_scanning", "runtime_hardening", "image_security"],
    )
    tags = sorted(set(section.tags + mapping.get("tags", [])))

    refs = [
        ComplianceReference(
            framework="NIST SP 800-190",
            control=section_id or "General Guidance",
        )
    ]

    safe_id = section_id.replace(".", "-") if section_id else "baseline"

    return KnowledgeDocument(
        id=f"nist-800-190-{safe_id}",
        title=section.title,
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
        source_type="nist_800_190",
    )