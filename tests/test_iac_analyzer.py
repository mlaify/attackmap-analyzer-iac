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
    # The image is part of the hint (#2) so each unpinned FROM is reported.
    assert "dockerfile_base_image_unpinned:node:18-alpine" in hints


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
    # The binding is part of the hint (#2): one per published port.
    assert "compose_port_binding_all_interfaces:0.0.0.0:80:3000" in hints
    assert "compose_port_binding_all_interfaces:80:80" in hints  # caddy: no IP = all interfaces


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
        "compose_docker_socket_mount",  # watchtower mounts /var/run/docker.sock (#2)
        "shell_sudo_used",
        "shell_permissive_chmod",
        "gha_pull_request_target_with_checkout",
        "gha_no_top_level_permissions",
    }
    entrypoints = {h.hint for h in scan.entrypoint_hints}
    assert entrypoints == {
        "compose_port_binding_all_interfaces:0.0.0.0:80:3000",
        "compose_port_binding_all_interfaces:0.0.0.0:443:3443",
        "compose_port_binding_all_interfaces:80:80",
        "compose_port_binding_all_interfaces:443:443",
    }
    framework = {h.hint for h in scan.framework_hints}
    assert {"dockerfile_no_healthcheck", "dockerfile_run_curl_pipe", "dockerfile_add_remote"} <= framework
    assert "dockerfile_base_image_unpinned:node:18-alpine" in framework
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


# ---------------------------------------------------------------------------
# Dockerfile / compose misreads (#2)
# ---------------------------------------------------------------------------

MULTISTAGE = "docker_multistage_repo"


def test_final_stage_without_user_is_root_even_if_builder_sets_user() -> None:
    scan = _analyze(MULTISTAGE)
    hints = {(h.hint, h.file) for h in scan.auth_hints}
    assert ("dockerfile_no_user_directive", "Dockerfile") in hints
    hint = next(h for h in scan.auth_hints if (h.hint, h.file) == ("dockerfile_no_user_directive", "Dockerfile"))
    lines = (FIXTURES / MULTISTAGE / "Dockerfile").read_text().split("\n")
    assert lines[hint.line - 1] == "FROM scratch"  # anchored at the final stage


def test_final_stage_inherits_user_from_its_parent_stage(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM alpine:3 AS base\nUSER app\nHEALTHCHECK CMD true\n\nFROM base\nCMD [\"run\"]\n", encoding="utf-8"
    )
    scan = IacAnalyzer().analyze(tmp_path)
    assert not {"dockerfile_no_user_directive", "dockerfile_user_root"} & {h.hint for h in scan.auth_hints}
    assert "dockerfile_no_healthcheck" not in {h.hint for h in scan.framework_hints}


def test_switching_back_from_root_in_final_stage_is_not_root(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM alpine:3\nUSER root\nRUN apk add curl\nUSER 10001:10001\n", encoding="utf-8"
    )
    scan = IacAnalyzer().analyze(tmp_path)
    assert "dockerfile_user_root" not in {h.hint for h in scan.auth_hints}


@pytest.mark.parametrize(
    "dockerfile",
    [
        "FROM golang:1@sha256:{sha} AS build\nFROM scratch\n",
        "FROM node:20@sha256:{sha} AS deps\nFROM deps\n",
        "FROM node:20@sha256:{sha} AS Deps\nFROM deps\n",  # aliases are case-insensitive
        "FROM --platform=$BUILDPLATFORM golang:1@sha256:{sha}\n",  # flag, not the image
    ],
)
def test_scratch_stage_aliases_and_flags_are_not_unpinned_images(tmp_path: Path, dockerfile: str) -> None:
    (tmp_path / "Dockerfile").write_text(dockerfile.format(sha="0" * 64), encoding="utf-8")
    scan = IacAnalyzer().analyze(tmp_path)
    unpinned = [h for h in scan.framework_hints if h.hint.startswith("dockerfile_base_image_unpinned")]
    assert unpinned == []


def test_each_unpinned_from_image_is_reported_separately() -> None:
    scan = _analyze(MULTISTAGE)
    unpinned = {
        h.hint for h in scan.framework_hints
        if h.file == "api.Dockerfile" and h.hint.startswith("dockerfile_base_image_unpinned")
    }
    assert unpinned == {
        "dockerfile_base_image_unpinned:node:20",
        "dockerfile_base_image_unpinned:python:3.12-slim",
    }


def test_env_and_arg_literal_secrets_are_hardcoded_secret_hints() -> None:
    scan = _analyze(MULTISTAGE)
    secrets = {(s.name, s.file, s.kind) for s in scan.secret_hints}
    assert ("AWS_SECRET_ACCESS_KEY", "Dockerfile", "hardcoded") in secrets
    assert ("NPM_TOKEN", "api.Dockerfile", "hardcoded") in secrets  # ARG default
    names = {s.name for s in scan.secret_hints}
    # A `_FILE` path, an ARG without a default and plain settings aren't secrets.
    assert not {"DB_PASSWORD_FILE", "BUILD_TOKEN", "LOG_LEVEL"} & names
    for secret in scan.secret_hints:
        assert "fixture-" not in (secret.evidence_text or "")  # core redacts the literal


def test_dockerfile_variants_and_compose_overrides_are_analyzed() -> None:
    scan = _analyze(MULTISTAGE)
    files = {h.file for h in [*scan.auth_hints, *scan.entrypoint_hints, *scan.framework_hints, *scan.secret_hints]}
    assert {"Dockerfile.prod", "api.Dockerfile", "docker-compose.override.yml"} <= files
    assert "Dockerfile.dockerignore" not in files
    assert scan.files_scanned == 5  # Dockerfile, Dockerfile.prod, api.Dockerfile, 2 compose files


@pytest.mark.parametrize(
    "name",
    ["Dockerfile.prod", "Dockerfile-dev", "api.Dockerfile", "web.dockerfile", "Containerfile.ci"],
)
def test_dockerfile_name_variants_are_detected(tmp_path: Path, name: str) -> None:
    (tmp_path / name).write_text("FROM alpine:3\n", encoding="utf-8")
    assert IacAnalyzer().detect(tmp_path) is True


@pytest.mark.parametrize(
    "name", ["docker-compose.override.yml", "docker-compose.prod.yaml", "compose.dev.yaml", "compose-ci.yml"]
)
def test_compose_name_variants_are_analyzed(tmp_path: Path, name: str) -> None:
    (tmp_path / name).write_text("services:\n  app:\n    privileged: true\n", encoding="utf-8")
    scan = IacAnalyzer().analyze(tmp_path)
    assert ("compose_privileged_container", name) in {(h.hint, h.file) for h in scan.auth_hints}


def test_composer_yml_is_not_a_compose_file(tmp_path: Path) -> None:
    (tmp_path / "composer.yml").write_text("services:\n  app:\n    privileged: true\n", encoding="utf-8")
    assert IacAnalyzer().detect(tmp_path) is False


def test_short_syntax_ports_without_ip_bind_all_interfaces() -> None:
    scan = _analyze(MULTISTAGE)
    bindings = {
        (h.file, h.evidence_text)
        for h in scan.entrypoint_hints
        if h.hint == f"compose_port_binding_all_interfaces:{h.evidence_text}"
    }
    assert ("compose.yaml", "5432:5432") in bindings
    assert ("docker-compose.override.yml", "8080:80") in bindings  # long syntax, no host_ip
    assert ("docker-compose.override.yml", "3000") in bindings  # ephemeral host port
    assert not any("6543" in evidence for _file, evidence in bindings)  # 127.0.0.1 only


def test_compose_environment_literal_secrets_are_flagged() -> None:
    scan = _analyze(MULTISTAGE)
    secrets = {(s.name, s.file, s.kind) for s in scan.secret_hints}
    assert ("POSTGRES_PASSWORD", "compose.yaml", "hardcoded") in secrets  # map form
    assert ("API_TOKEN", "docker-compose.override.yml", "hardcoded") in secrets  # list form
    names = {s.name for s in scan.secret_hints}
    assert not {"POSTGRES_USER", "POSTGRES_PASSWORD_FILE", "REPLICATION_TOKEN", "DEBUG"} & names


def test_host_root_equivalent_compose_settings_are_elevated() -> None:
    scan = _analyze(MULTISTAGE)
    auth = {h.hint for h in scan.auth_hints if h.file == "compose.yaml"}
    assert {
        "compose_docker_socket_mount",
        "compose_cap_add_sys_admin",
        "compose_pid_host",
        "compose_seccomp_unconfined",
    } <= auth
