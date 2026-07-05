# attackmap-analyzer-iac

Infrastructure-as-Code analyzer plugin for [AttackMap](https://github.com/mlaify/AttackMap).

Covers the class of files that live outside application source but drive the actual runtime posture:

- **Dockerfile** — non-root user, exposed ports, `COPY`/`ADD` with credentials, `RUN curl | bash`, missing healthchecks, base-image pinning
- **docker-compose.yaml** — service list (feeds the topology graph), `env_file` references, host-mount volumes, privileged containers, `0.0.0.0` port bindings, `network_mode: host`
- **GitHub Actions workflows** — `pull_request_target` with checkout, third-party actions pinned by tag vs SHA, secret exposure to fork PRs, step-level `permissions:`
- **`.env` templates** (`.env.example`, `sample.env`) — secret inventory (the shape, not the value)
- **Shell installers** — `curl | bash` patterns, `sudo` scope, TLS material handling

Emits routes for exposed ports, external calls for third-party actions and `curl` fetches, `SecretHint` for env-template inventory, service-topology hints for compose `services:` — feeding the same pipeline as the source-code analyzers.

Bluesky FINDINGS §2 documented this as the biggest coverage gap: `bluesky-social/pds` (a deployment repo) was 95% invisible to AttackMap because every non-JS file was outside the analyzer model. This plugin closes that gap.

## Install

```bash
pip install attackmap-analyzer-iac
# or as part of the bundle
pip install "attackmap[all]"
```

## Usage

Runs automatically via the `attackmap.analyzers` entry-point group once installed:

```bash
attackmap analyze /path/to/deployment-repo --output reports
```

## Contract

Implements `AnalyzerProtocol` from `attackmap.sdk`. See the [external-analyzer guide](https://github.com/mlaify/AttackMap/blob/main/docs/external-analyzers.md).

## Scope

**In:** patterns any competent operator recognizes on inspection — the docker-compose service graph, `pull_request_target` combined with untrusted checkout, non-root User directive presence, curl-piped installer scripts.

**Out:** deep semantic analysis of container image contents, live registry scanning, executed-runtime introspection. Those belong in other tools; AttackMap's differentiator is narrative attack-path reasoning over the code you can see.
