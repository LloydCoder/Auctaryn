"""Edge cases for risk and exact version identity."""
from tests.test_secure_skill_vetting import configured_service, make_manifest


def test_medium_permission_set_is_rejected():
    service, key = configured_service()
    manifest, artifact = make_manifest(
        key, permissions=["read_file", "write_file", "list_files", "memory:read"]
    )
    result = service.vet(manifest, artifact)
    assert not result.approved
    assert any("medium" in reason.lower() for reason in result.reasons)


def test_different_build_metadata_for_same_precedence_is_rejected():
    service, key = configured_service()
    first, artifact = make_manifest(key, version="1.0.0+build.1")
    assert service.vet(first, artifact).approved
    second, artifact = make_manifest(key, artifact=artifact, version="1.0.0+build.2")
    result = service.vet(second, artifact)
    assert not result.approved
    assert any("version identity" in reason.lower() for reason in result.reasons)
