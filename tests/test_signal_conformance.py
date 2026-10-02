"""Signal v2 conformance (AttackMap#258).

`auth_hints` must carry only genuine authentication/authorization signals;
service names, edges, entrypoints, protocol and framework metadata go in
their typed hint lists. Every signal that cites a file must also cite a line
inside that file, plus quoted evidence where the model has the field.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from attackmap_analyzer_iac import IacAnalyzer

FIXTURES = Path(__file__).parent / "fixtures"
FIXTURE_DIRS = sorted(path for path in FIXTURES.iterdir() if path.is_dir())

# Every AuthHint.hint this analyzer may emit. Anything else is non-auth
# metadata and belongs in a typed hint list.
AUTH_HINT_NAMES = frozenset(
    {
        # Host-root-equivalent container privileges (#2): same class as
        # `compose_privileged_container`. A Docker socket mount, SYS_ADMIN/ALL
        # capabilities, the host PID namespace or disabled seccomp each
        # decide what the workload may do to the host.
        "compose_cap_add_sys_admin",
        "compose_docker_socket_mount",
        "compose_pid_host",
        "compose_privileged_container",
        "compose_seccomp_unconfined",
        "dockerfile_no_user_directive",
        "dockerfile_user_root",
        "gha_no_top_level_permissions",
        "gha_pull_request_target_with_checkout",
        "shell_permissive_chmod",
        "shell_sudo_used",
    }
)
AUTH_HINT_PREFIXES: tuple[str, ...] = ()

SIGNAL_LISTS = (
    "routes",
    "external_calls",
    "databases",
    "auth_hints",
    "service_hints",
    "edge_hints",
    "entrypoint_hints",
    "protocol_hints",
    "framework_hints",
    "secret_hints",
    "dependencies",
)


def _analyze(fixture: Path):
    return IacAnalyzer().analyze(fixture)


@pytest.mark.parametrize("fixture", FIXTURE_DIRS, ids=lambda path: path.name)
def test_auth_hints_are_genuine_auth_signals(fixture: Path) -> None:
    for hint in _analyze(fixture).auth_hints:
        assert hint.hint in AUTH_HINT_NAMES or hint.hint.startswith(AUTH_HINT_PREFIXES), (
            f"non-auth signal emitted as AuthHint: {hint.hint!r} ({hint.file})"
        )


@pytest.mark.parametrize("fixture", FIXTURE_DIRS, ids=lambda path: path.name)
def test_every_signal_with_a_file_has_a_line_and_evidence(fixture: Path) -> None:
    result = _analyze(fixture)
    for attr in SIGNAL_LISTS:
        for signal in getattr(result, attr):
            if not getattr(signal, "file", None):
                continue
            lines = (fixture / signal.file).read_text(encoding="utf-8", errors="replace").split("\n")
            assert signal.line is not None, f"{attr} without a line: {signal!r}"
            assert 1 <= signal.line <= len(lines), f"{attr} line out of range: {signal!r}"
            if "evidence_text" in type(signal).model_fields:
                assert signal.evidence_text, f"{attr} without evidence_text: {signal!r}"


def test_fixtures_exercise_typed_signals() -> None:
    # Guard against the checks above passing vacuously.
    results = [_analyze(fixture) for fixture in FIXTURE_DIRS]
    typed = [
        hint
        for result in results
        for hint in (
            *result.service_hints,
            *result.edge_hints,
            *result.entrypoint_hints,
            *result.protocol_hints,
            *result.framework_hints,
        )
    ]
    assert typed
