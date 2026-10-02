# attackmap-analyzer-iac

> [!IMPORTANT]
> **Active development, slow pace.** AttackMap is under active development, but
> progress may be slow until more contributors or co-maintainers join. Help is
> very welcome with the core engine, an analyzer, the macOS app, or the docs —
> see [CONTRIBUTING.md](CONTRIBUTING.md) or open an issue on
> [mlaify/AttackMap](https://github.com/mlaify/AttackMap/issues) to say hello.
> Security reports are still welcome at [security@mlaify.io](mailto:security@mlaify.io).

Infrastructure-as-Code analyzer plugin for [AttackMap](https://github.com/mlaify/AttackMap).

Covers the class of files that live outside application source but drive the actual runtime posture:

- **Dockerfile** — non-root user, exposed ports, `COPY`/`ADD` with credentials, `RUN curl | bash`, missing healthchecks, base-image pinning
- **docker-compose.yaml** — service list (feeds the topology graph), `env_file` references, host-mount volumes, privileged containers, `0.0.0.0` port bindings, `network_mode: host`
- **GitHub Actions workflows** — `pull_request_target` with checkout, third-party actions pinned by tag vs SHA, secret exposure to fork PRs, step-level `permissions:`
- **`.env` templates** (`.env.example`, `sample.env`) — secret inventory (the shape, not the value)
- **Shell installers** — `curl | bash` patterns, `sudo` scope, TLS material handling

Emits routes for exposed ports, external calls for third-party actions and `curl` fetches, `SecretHint` for env-template inventory, service-topology hints for compose `services:` — feeding the same pipeline as the source-code analyzers.

### Posture signals

Every signal carries `file`, `line` and `evidence_text`. Signals about something *missing* (no `USER`, no `HEALTHCHECK`, no `permissions:`) point at the final `FROM` line or line 1. The SDK has no weakness/posture signal type yet, so posture items are split by meaning (AttackMap#258):

| Signal list | Hints |
|---|---|
| `auth_hints` (privilege / authorization) | `dockerfile_no_user_directive`, `dockerfile_user_root`, `compose_privileged_container`, `shell_sudo_used`, `shell_permissive_chmod`, `gha_pull_request_target_with_checkout`, `gha_no_top_level_permissions` |
| `entrypoint_hints` (network exposure) | `compose_port_binding_all_interfaces`, `compose_network_mode_host` |
| `framework_hints` (build, supply-chain and deployment config) | `dockerfile_no_healthcheck`, `dockerfile_run_curl_pipe`, `dockerfile_add_remote`, `dockerfile_base_image_unpinned`, `compose_env_file_reference`, `compose_host_mount:<host path>`, `gha_third_party_action_tag_pinned:<owner/repo>`, `shell_curl_pipe_installer` |
| `service_hints` | `service_name:<compose service>` |

Bluesky FINDINGS §2 documented this as the biggest coverage gap: `bluesky-social/pds` (a deployment repo) was 95% invisible to AttackMap because every non-JS file was outside the analyzer model. This plugin closes that gap.

## Install

```bash
pip install git+https://github.com/mlaify/attackmap-analyzer-iac.git
# or as part of the bundle
pip install "attackmap[all] @ git+https://github.com/mlaify/AttackMap.git"
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
