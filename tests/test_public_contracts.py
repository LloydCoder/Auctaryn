"""Repository-wide public claims and integration-boundary regressions."""
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_repository_has_declared_apache_20_license():
    license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert "Apache License" in license_text
    assert "Version 2.0" in license_text
    assert "AS IS" in license_text
    assert "Copyright 2026 Tinlance Limited" in license_text


def test_public_pages_do_not_claim_universal_mediation_or_unverified_metrics():
    public_pages = [
        ROOT / "site/index.html",
        ROOT / "site/about.html",
        ROOT / "site/docs.html",
        ROOT / "site/pricing.html",
        ROOT / "site/js/partials.js",
    ]
    forbidden = [
        "intercepts every AI agent action",
        "intercepts every tool call",
        "0% false positive rate across",
        "232 tests passing",
        "Production-validated",
        "FusionOps: <span>online</span>",
        "All tiers include Summer Yue scenario protection",
        "z-score 14.76",
        "Live C2 threat intelligence from FusionOps",
        "Summer Yue protection active",
        "Watch live demo",
        "Every agent gets a scoped managed identity",
        "Every row below has working, tested code",
        "Live connectivity status to FusionOps",
        "TwinGuard",
        "Built on OpenShell",
    ]
    combined = "\n".join(path.read_text(encoding="utf-8") for path in public_pages)
    for phrase in forbidden:
        assert phrase.lower() not in combined.lower(), f"unsupported public claim remains: {phrase}"


def test_public_pricing_does_not_advertise_unapproved_tiers_or_slas():
    pricing = (ROOT / "site/pricing.html").read_text(encoding="utf-8").lower()
    for phrase in ("$99", "$299", "$999", "sla guarantee", "community tier through enterprise"):
        assert phrase not in pricing
    assert "pricing on request" in pricing
    assert "no production sla" in pricing


def test_olvrix_reference_integration_fails_closed_and_is_action_scoped():
    patch = (ROOT / "integrations/olvrix_widgets/twinguard_bridge_patch.py").read_text(encoding="utf-8")
    assert "13.50.16.19" not in patch
    assert "TWINGUARD_API_URL" not in patch
    assert 'decision.get("decision") != "approved"' in patch
    assert '"security_service_unavailable"' in patch
    assert '"agent.action": ["auctaryn"]' in patch
    assert '"chat.message": ["auctaryn"]' not in patch


def test_demo_script_disclaims_external_runtime_and_production_certification():
    demo = (ROOT / "docs/DEMO_SCRIPT.md").read_text(encoding="utf-8").lower()
    assert "does not prove" in demo
    assert "universal mediation" in demo
    assert "no independent certification is claimed" in demo
    assert "identity/token" not in demo or "scoped agent token" in demo
