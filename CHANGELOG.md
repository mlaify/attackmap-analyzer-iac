# Changelog

All notable changes to `attackmap-analyzer-iac` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Walk and read the repo with the shared `attackmap.sdk` helpers (`iter_repo_files`, `read_source`, `rel`, `line_of`) instead of a local `rglob` + `_SKIP_DIRS` walk (mlaify/AttackMap#253). The skip list is now AttackMap's shared `DEFAULT_SKIP_DIRS`, a superset of the old one (adds e.g. `vendor/`, `.next/`, `.tox/`, AttackMap output dirs).

### Fixed

- A repo checked out under a directory named like a skip dir (e.g. `/build/...`, `.../out/...`) was silently not analyzed, because skip dirs were matched against absolute path parts.
- Symlinked files pointing outside the repo are no longer followed and analyzed.
- cp1252/latin-1 encoded files are analyzed instead of silently dropped.

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
