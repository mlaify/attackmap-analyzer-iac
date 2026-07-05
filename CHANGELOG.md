# Changelog

All notable changes to `attackmap-analyzer-iac` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
