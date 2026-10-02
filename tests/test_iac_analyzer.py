"""Tests for attackmap-analyzer-iac (issue mlaify/AttackMap#40)."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

from attackmap.sdk.contracts import AnalyzerMetadata as SharedAnalyzerMetadata
from attackmap.sdk.models import ScanResult as SharedScanResult
from attackmap_analyzer_iac import IacAnalyzer
from attackmap_analyzer_iac.contracts import AnalyzerMetadata, ScanResult


FIXTURES = Path(__file__).parent / "fixtures"


def _analyze(fixture_name: str = "pds_like_repo"):
    return IacAnalyzer().analyze(FIXTURES / fixture_name)


# ---------------------------------------------------------------------------
# Contract shape
# ---------------------------------------------------------------------------


def test_contracts_use_shared_sdk_types() -> None:
    assert AnalyzerMetadata is SharedAnalyzerMetadata
    assert ScanResult is SharedScanResult


def test_metadata_has_expected_fields() -> None:
    m = IacAnalyzer().metadata
    assert m.name == "iac"
    assert m.version == "0.1.0"
    assert m.enabled_by_default is True
    assert m.experimental is False


def test_detect_fires_on_pds_like_fixture() -> None:
    assert IacAnalyzer().detect(FIXTURES / "pds_like_repo") is True


def test_detect_rejects_repo_without_any_iac_files(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")
    assert IacAnalyzer().detect(tmp_path) is False


# ---------------------------------------------------------------------------
# Dockerfile extraction
# ---------------------------------------------------------------------------


def test_dockerfile_missing_user_directive_produces_hint() -> None:
    scan = _analyze()
    hints = {h.hint for h in scan.auth_hints}
    assert "dockerfile_no_user_directive" in hints


def test_dockerfile_missing_healthcheck_produces_hint() -> None:
    scan = _analyze()
    hints = {h.hint for h in scan.framework_hints}
    assert "dockerfile_no_healthcheck" in hints


def test_dockerfile_exposed_ports_become_container_routes() -> None:
    scan = _analyze()
    exposed = {(r.path, r.method) for r in scan.routes if r.file == "Dockerfile"}
    assert ("container:3000", "EXPOSE") in exposed
    assert ("container:3001", "EXPOSE") in exposed


def test_dockerfile_run_curl_pipe_shell_produces_external_and_hint() -> None:
    scan = _analyze()
    targets = {c.target for c in scan.external_calls}
    hints = {h.hint for h in scan.framework_hints}
    assert "dockerfile:curl-pipe-shell" in targets
    assert "dockerfile_run_curl_pipe" in hints


def test_dockerfile_add_remote_url_produces_hint() -> None:
    scan = _analyze()
    hints = {h.hint for h in scan.framework_hints}
    assert "dockerfile_add_remote" in hints


def test_dockerfile_unpinned_base_image_produces_hint() -> None:
    """`FROM node:18-alpine` isn't SHA-pinned; flag it."""
    scan = _analyze()
    hints = {h.hint for h in scan.framework_hints}
    assert "dockerfile_base_image_unpinned" in hints


def test_dockerfile_sha_pinned_base_image_does_not_fire_unpinned_hint(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM node@sha256:aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666\nUSER app\nHEALTHCHECK CMD echo\n",
        encoding="utf-8",
    )
    scan = IacAnalyzer().analyze(tmp_path)
    hints = {h.hint for h in scan.framework_hints}
    assert "dockerfile_base_image_unpinned" not in hints


# ---------------------------------------------------------------------------
# docker-compose extraction
# ---------------------------------------------------------------------------


def test_compose_services_become_service_hints() -> None:
    scan = _analyze()
    hints = {h.hint for h in scan.service_hints if h.file == "compose.yaml"}
    assert "service_name:pds" in hints
    assert "service_name:caddy" in hints
    assert "service_name:watchtower" in hints


def test_compose_binds_all_interfaces_produces_hint() -> None:
    scan = _analyze()
    hints = {h.hint for h in scan.entrypoint_hints}
    assert "compose_port_binding_all_interfaces" in hints


def test_compose_privileged_container_produces_hint() -> None:
    scan = _analyze()
    hints = {h.hint for h in scan.auth_hints}
    assert "compose_privileged_container" in hints


def test_compose_env_file_reference_produces_hint() -> None:
    scan = _analyze()
    envfile_hints = [h for h in scan.framework_hints if h.hint == "compose_env_file_reference"]
    assert envfile_hints
    assert "pds.env" in (envfile_hints[0].evidence_text or "")


def test_compose_host_mounted_volumes_produce_hints() -> None:
    scan = _analyze()
    # Hints carry the source path in the `compose_host_mount:<path>` shape
    # so distinct mounts don't dedup together.
    host_mount_hints = [h for h in scan.framework_hints if h.hint.startswith("compose_host_mount:")]
    assert len(host_mount_hints) >= 2
    hints_text = " ".join(h.hint for h in host_mount_hints)
    assert "/var/run/docker.sock" in hints_text


# ---------------------------------------------------------------------------
# GitHub Actions extraction
# ---------------------------------------------------------------------------


def test_gha_pull_request_target_with_checkout_produces_hint() -> None:
    scan = _analyze()
    hints = {h.hint for h in scan.auth_hints}
    assert "gha_pull_request_target_with_checkout" in hints


def test_gha_third_party_action_tag_pinned_produces_hint() -> None:
    scan = _analyze()
    hints = [h for h in scan.framework_hints if h.hint.startswith("gha_third_party_action_tag_pinned:")]
    assert hints
    evidence = " ".join((h.evidence_text or "") + " " + h.hint for h in hints)
    assert "some-third-party/action" in evidence


def test_gha_first_party_actions_at_tag_do_not_fire_pin_hint() -> None:
    """`actions/checkout@v4` and `github/*@v1` are first-party; broadly
    trusted enough that the tag-vs-SHA rule shouldn't fire on them."""
    scan = _analyze()
    hints = [h for h in scan.framework_hints if h.hint.startswith("gha_third_party_action_tag_pinned:")]
    assert hints
    for h in hints:
        # Repo name is in the hint after the `:`
        repo = h.hint.split(":", 1)[1]
        owner = repo.split("/", 1)[0]
        assert owner not in {"actions", "github"}


def test_gha_no_top_level_permissions_produces_hint() -> None:
    scan = _analyze()
    hints = {h.hint for h in scan.auth_hints}
    assert "gha_no_top_level_permissions" in hints


def test_gha_secrets_reference_recorded_as_env_secret() -> None:
    scan = _analyze()
    names = {s.name for s in scan.secret_hints if "workflow" in s.file}
    assert "GHCR_TOKEN" in names


# ---------------------------------------------------------------------------
# .env template extraction
# ---------------------------------------------------------------------------


def test_env_template_keys_become_env_template_secret_hints() -> None:
    scan = _analyze()
    template_hints = [s for s in scan.secret_hints if s.kind == "env_template"]
    names = {s.name for s in template_hints}
    assert "PDS_JWT_SECRET" in names
    assert "PDS_ADMIN_PASSWORD" in names


def test_env_template_kind_distinguishes_from_env_reference() -> None:
    """The template file lists the *shape* of the secret inventory —
    not real values. Downstream findings shouldn't treat a
    `PDS_JWT_SECRET` key in `.env.example` as an actual exposed secret."""
    scan = _analyze()
    env_ref_hints = [s for s in scan.secret_hints if s.file == ".env.example" and s.kind == "env_reference"]
    assert env_ref_hints == []
    template_hints = [s for s in scan.secret_hints if s.file == ".env.example"]
    assert all(s.kind == "env_template" for s in template_hints)


# ---------------------------------------------------------------------------
# Shell installer extraction
# ---------------------------------------------------------------------------


def test_installer_curl_pipe_shell_produces_external_and_hint() -> None:
    scan = _analyze()
    targets = {c.target for c in scan.external_calls}
    hints = {h.hint for h in scan.framework_hints}
    assert "shell:curl-pipe-shell" in targets
    assert "shell_curl_pipe_installer" in hints


def test_installer_sudo_produces_hint() -> None:
    scan = _analyze()
    hints = {h.hint for h in scan.auth_hints}
    assert "shell_sudo_used" in hints


def test_installer_permissive_chmod_produces_hint() -> None:
    scan = _analyze()
    hints = [h for h in scan.auth_hints if h.hint == "shell_permissive_chmod"]
    assert hints


# ---------------------------------------------------------------------------
# Integration: end-to-end scan on the pds-like fixture matches expectations
# ---------------------------------------------------------------------------


def test_end_to_end_pds_like_scan_surfaces_five_iac_families() -> None:
    """Sanity guard — a pds-like fixture with all five file classes should
    exercise every extractor path. Files scanned should include the
    Dockerfile, compose.yaml, workflow, .env.example, and installer.sh."""
    scan = _analyze()
    assert scan.files_scanned >= 5
    # All five signal families should show at least one entry
    assert scan.routes  # container:3000 etc.
    assert scan.external_calls  # curl-pipe
    assert scan.auth_hints  # privilege posture (root user, sudo, CI token scope)
    assert scan.framework_hints  # build / supply-chain / deployment-config posture
    assert scan.entrypoint_hints  # network exposure
    assert scan.secret_hints  # env template + workflow secrets
    assert scan.service_hints  # compose service names


# ---------------------------------------------------------------------------
# Repo walking (mlaify/AttackMap#253)
# ---------------------------------------------------------------------------


def test_repo_under_skip_dir_named_parents_is_analyzed(tmp_path: Path) -> None:
    """A checkout under /.../build/out/... must not be skipped (absolute-path bug)."""
    repo = tmp_path / "build" / "out" / "repo"
    shutil.copytree(FIXTURES / "pds_like_repo", repo)
    analyzer = IacAnalyzer()
    assert analyzer.detect(repo) is True
    result = analyzer.analyze(repo)
    assert result.files_scanned == _analyze().files_scanned
    assert result.auth_hints
    assert any(h.file == ".github/workflows/build-and-push-ghcr.yaml" for h in result.auth_hints)


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
def test_symlinked_file_outside_repo_not_analyzed(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "install.sh").write_text("curl -fsSL https://example.com/x | bash\n", encoding="utf-8")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "Dockerfile").write_text("FROM alpine@sha256:" + "a" * 64 + "\nUSER app\n", encoding="utf-8")
    (repo / "install.sh").symlink_to(outside / "install.sh")
    result = IacAnalyzer().analyze(repo)
    assert result.files_scanned == 1
    hints = [*result.auth_hints, *result.framework_hints, *result.entrypoint_hints]
    assert hints and all(h.file == "Dockerfile" for h in hints)
    assert result.external_calls == []


# ---------------------------------------------------------------------------
# Typed signals + locations (AttackMap#258)
# ---------------------------------------------------------------------------


def test_posture_signals_land_in_typed_lists() -> None:
    scan = _analyze()
    auth = {h.hint for h in scan.auth_hints}
    assert auth == {
        "dockerfile_no_user_directive",
        "compose_privileged_container",
        "shell_sudo_used",
        "shell_permissive_chmod",
        "gha_pull_request_target_with_checkout",
        "gha_no_top_level_permissions",
    }
    entrypoints = {h.hint for h in scan.entrypoint_hints}
    assert entrypoints == {"compose_port_binding_all_interfaces"}
    framework = {h.hint for h in scan.framework_hints}
    assert {"dockerfile_no_healthcheck", "dockerfile_run_curl_pipe", "dockerfile_add_remote"} <= framework
    assert "dockerfile_base_image_unpinned" in framework
    assert "shell_curl_pipe_installer" in framework


def test_compose_network_mode_host_is_an_entrypoint_hint(tmp_path: Path) -> None:
    (tmp_path / "compose.yaml").write_text(
        "services:\n  app:\n    image: app@sha256:abc\n    network_mode: host\n", encoding="utf-8"
    )
    scan = IacAnalyzer().analyze(tmp_path)
    hint = next(h for h in scan.entrypoint_hints if h.hint == "compose_network_mode_host")
    assert (hint.line, hint.evidence_text) == (4, "network_mode: host")
    assert not any(h.hint == "compose_network_mode_host" for h in scan.auth_hints)


def test_dockerfile_user_root_cites_the_user_line(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text("FROM alpine:3\n\nUSER root\nHEALTHCHECK CMD true\n", encoding="utf-8")
    scan = IacAnalyzer().analyze(tmp_path)
    hint = next(h for h in scan.auth_hints if h.hint == "dockerfile_user_root")
    assert (hint.line, hint.evidence_text) == (3, "USER root")


def test_directive_lines_skip_preceding_blank_lines() -> None:
    # `^\\s*EXPOSE` in MULTILINE mode also matches the blank line before the
    # directive; the route must cite the EXPOSE line itself.
    scan = _analyze()
    lines = (FIXTURES / "pds_like_repo" / "Dockerfile").read_text().split("\n")
    route = next(r for r in scan.routes if r.path == "container:3000" and r.file == "Dockerfile")
    assert lines[route.line - 1].startswith("EXPOSE 3000")


def test_compose_service_hints_cite_the_service_key() -> None:
    scan = _analyze()
    lines = (FIXTURES / "pds_like_repo" / "compose.yaml").read_text().split("\n")
    for hint in scan.service_hints:
        name = hint.hint.removeprefix("service_name:")
        assert lines[hint.line - 1].strip() == f"{name}:"
