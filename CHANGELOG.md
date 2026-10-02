# Changelog

All notable changes to `attackmap-analyzer-iac` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed — typed signals instead of overloaded `AuthHint`s (AttackMap#258)

- **`auth_hints` now carries only privilege/authorization posture.** The SDK has no weakness/posture signal type, so the IaC posture checks that used to all be `AuthHint`s are split by meaning, keeping their hint strings (see the README's *Posture signals* table):
  - stays `AuthHint` (who the workload or CI job runs as / what it may do): `dockerfile_no_user_directive`, `dockerfile_user_root`, `compose_privileged_container`, `shell_sudo_used`, `shell_permissive_chmod`, `gha_pull_request_target_with_checkout`, `gha_no_top_level_permissions`
  - → `EntrypointHint` (network exposure): `compose_port_binding_all_interfaces`, `compose_network_mode_host`
  - → `FrameworkHint` (build, supply-chain and deployment config): `dockerfile_no_healthcheck`, `dockerfile_run_curl_pipe`, `dockerfile_add_remote`, `dockerfile_base_image_unpinned`, `compose_env_file_reference`, `compose_host_mount:*`, `gha_third_party_action_tag_pinned:*`, `shell_curl_pipe_installer`
- **Every signal now cites a line and quotes it.** Posture hints, compose `service_name:*` hints, external calls and secret hints carry `line` and `evidence_text` (via `attackmap.sdk.line_of` / `line_snippet`, or the specific image/mount/`owner/repo@ref` where that identifies the signal better). Signals about something missing anchor at the final `FROM` line (`dockerfile_no_user_directive`, `dockerfile_no_healthcheck`) or line 1 (`gha_no_top_level_permissions`) with an explanatory `evidence_text`. Hints set `confidence` (0.9 explicit directives, 0.8 PR-target/env-file/unpinned base image, 0.6 absence checks).
- **Breaking for direct consumers of `ScanResult.auth_hints`:** code that looked for the moved hints in `auth_hints` must read `entrypoint_hints` / `framework_hints`.
- New `tests/test_signal_conformance.py` asserts every emitted `AuthHint.hint` is in an explicit allow-list and every signal has an in-range `line` and evidence.

### Changed

- Walk and read the repo with the shared `attackmap.sdk` helpers (`iter_repo_files`, `read_source`, `rel`, `line_of`) instead of a local `rglob` + `_SKIP_DIRS` walk (mlaify/AttackMap#253). The skip list is now AttackMap's shared `DEFAULT_SKIP_DIRS`, a superset of the old one (adds e.g. `vendor/`, `.next/`, `.tox/`, AttackMap output dirs).

### Fixed

- A repo checked out under a directory named like a skip dir (e.g. `/build/...`, `.../out/...`) was silently not analyzed, because skip dirs were matched against absolute path parts.
- Symlinked files pointing outside the repo are no longer followed and analyzed.
- cp1252/latin-1 encoded files are analyzed instead of silently dropped.
- Directive lines no longer point at a preceding blank line. Patterns like `^\s*EXPOSE` in multiline mode also match the blank lines before a directive, so e.g. an `EXPOSE 3000` after a blank line was reported one line early; signals now cite the directive's own line. (AttackMap#258)

## [0.1.0] — 2026-07-04

### Added

- Initial public release of `attackmap-analyzer-iac`.
- Dockerfile extraction: `USER`, `EXPOSE`, `RUN curl | bash`, `COPY --chown=`,
  `HEALTHCHECK`, `ADD` remote fetches, base-image tag-vs-SHA pinning.
- docker-compose extraction: service names → topology nodes, `image:`,
  `ports:` bindings (with `0.0.0.0` detection), `env_file:` references,
  host-mounted volumes, `privileged: true`, `network_mode: host`.
- GitHub Actions workflow extraction: `pull_request_target` triggers,
  third-party actions pinned by tag vs SHA, `permissions:` and
  `${{ secrets.* }}` references.
- `.env` template detection (`.env.example`, `sample.env`) as secret
  inventory rather than secret-bearing evidence.
- Shell installer patterns: `curl | bash`, `wget | sh`, `sudo` usage.
- Emits `Route`, `ExternalCall`, `DatabaseHint`, `AuthHint`, `SecretHint`
  records via the existing AttackMap signal contract; provenance
  (`source_analyzer="iac"`) is set by core.
