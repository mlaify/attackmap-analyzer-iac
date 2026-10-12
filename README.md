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

- **Dockerfile** (also `Dockerfile.*`, `Dockerfile-*`, `*.Dockerfile`, `*.dockerfile`, `Containerfile*`): non-root user and healthcheck, both checked on the *final* build stage, including what it inherits from an earlier stage it is built `FROM`; exposed ports; `RUN curl | bash`; `ADD <url>`; base-image pinning, one hint per unpinned image, skipping `scratch` and stage aliases; literal secrets in `ENV`/`ARG`
- **docker-compose** (`docker-compose*.y[a]ml`, `compose*.y[a]ml`, so overrides like `docker-compose.override.yml` too): service list (feeds the topology graph), `env_file` references, host-mount volumes, privileged containers, Docker socket mounts, `cap_add: SYS_ADMIN`/`ALL`, `pid: host`, `seccomp:unconfined`, published ports that bind all interfaces (explicit `0.0.0.0`, or short syntax with no host IP such as `"5432:5432"`), `network_mode: host`, and literal secrets in `environment:`
- **GitHub Actions workflows** — `pull_request_target` with checkout, third-party actions pinned by tag vs SHA, secret exposure to fork PRs, step-level `permissions:`
- **`.env` templates** (`.env.example`, `sample.env`) — secret inventory (the shape, not the value)
- **Shell installers** — `curl | bash` patterns, `sudo` scope, TLS material handling
- **Kubernetes manifests** (any `.yaml`/`.yml` with top-level `apiVersion:` and `kind:`) — workloads (`Pod`, `Deployment`, `StatefulSet`, `DaemonSet`, `ReplicaSet`, `Job`, `CronJob`, `ReplicationController`): `privileged`, `allowPrivilegeEscalation: true`, `runAsUser: 0`, missing `runAsNonRoot` / `allowPrivilegeEscalation: false`, `hostPath` volumes (high for the runtime socket, `/`, `/etc`, `/proc`, `/sys`, `/dev`, `/var/lib/kubelet`…), `hostNetwork`/`hostPID`/`hostIPC`, dangerous capabilities, `Unconfined` seccomp/AppArmor, `:latest`/untagged images; RBAC roles with `*` on core/RBAC/apps groups, `escalate`/`bind`/`impersonate`, `pods/exec`, Secret reads; bindings to `cluster-admin` or `system:authenticated`/`unauthenticated`/`anonymous`; `LoadBalancer`/`NodePort` Services without `loadBalancerSourceRanges` (entrypoints too; internal load balancers skipped); `Ingress` host/path rules (routes); literal `Secret` values
- **Helm charts** — templates under `templates/` next to a `Chart.yaml` are read without rendering: `{{ }}` actions are stripped (line numbers kept) and a templated value is never reported, because the chart's values decide it. A setting inside `{{ if }}`/`{{ with }}` is reported with low confidence (it may be off by default). `values.yaml` defaults (`privileged`, `hostNetwork`/`hostPID`/`hostIPC`, `allowPrivilegeEscalation`, `runAsUser: 0`, capabilities) are reported with confidence 0.5

Emits routes for exposed ports, external calls for third-party actions and `curl` fetches, `SecretHint` for env-template inventory, service-topology hints for compose `services:` — feeding the same pipeline as the source-code analyzers.

### Misconfigurations and posture signals

Every signal carries `file`, `line` and `evidence_text`. Signals about something *missing* (no `USER`, no `HEALTHCHECK`, no `permissions:`) point at the final `FROM` line or line 1.

Container and cluster misconfigurations are `CloudMisconfig` records (`cloud_misconfigs`, iac#1), which AttackMap core turns into findings with CWE/OWASP ids. Each names the `resource` (`Deployment/web container app`, `service agent`), a per-instance `severity` and `confidence`, and an `escalation_path` (e.g. `container runtime socket → start a privileged container → root on the node`):

| Kind | Dockerfile / compose | Kubernetes / Helm |
|---|---|---|
| `container_runs_as_root` | no `USER` in the final stage (low), `USER root` (medium) | `runAsUser: 0` |
| `privileged_container` | `privileged: true` | `securityContext.privileged: true` |
| `host_path_mount` | runtime socket and `/etc`, `/proc`, … bind mounts (`/srv/data` is not reported) | `hostPath` volumes |
| `host_namespace_shared` | `pid: host`, `ipc: host`, `network_mode: host` | `hostPID`, `hostNetwork`, `hostIPC` |
| `dangerous_capability` | `cap_add` | `capabilities.add` (`SYS_ADMIN`, `ALL`, `SYS_MODULE`, `SYS_PTRACE`, … high; `NET_ADMIN` medium) |
| `security_profile_disabled` | `seccomp:unconfined`, `apparmor:unconfined` | `seccompProfile`/`appArmorProfile` `Unconfined` |
| `unpinned_container_image` | `FROM image:latest` or untagged | `image:` `:latest` or untagged |
| `dockerfile_remote_add` / `dockerfile_curl_pipe_shell` | `ADD <url>` without `--checksum`, `RUN curl \| sh` | |
| `privilege_escalation_allowed`, `missing_security_context` (low) | | `allowPrivilegeEscalation: true`; no `runAsNonRoot` / `allowPrivilegeEscalation: false` |
| `rbac_wildcard`, `rbac_escalation`, `rbac_secret_access`, `cluster_admin_binding`, `exposed_service` | | RBAC and Services |

No `AuthHint`s are emitted: core reads those as auth signals, and one in a Dockerfile counted as an auth control for its `EXPOSE` route. With an AttackMap core older than the `CloudMisconfig` record, the old `AuthHint`s (`dockerfile_no_user_directive`, `dockerfile_user_root`, `compose_privileged_container`, `compose_docker_socket_mount`, `compose_cap_add_sys_admin`, `compose_pid_host`, `compose_seccomp_unconfined`) are emitted instead. The other signals are split by meaning (AttackMap#258):

| Signal list | Hints |
|---|---|
| `entrypoint_hints` (network exposure) | `compose_port_binding_all_interfaces:<binding>`, `compose_network_mode_host`, `k8s_service_loadbalancer:<name>`, `k8s_service_nodeport:<name>`, `k8s_ingress:<host>` |
| `framework_hints` (build, supply-chain, CI and deployment config) | `dockerfile_no_healthcheck`, `dockerfile_run_curl_pipe`, `dockerfile_add_remote`, `dockerfile_base_image_unpinned:<image>`, `compose_env_file_reference`, `compose_host_mount:<host path>`, `gha_third_party_action_tag_pinned:<owner/repo>`, `gha_pull_request_target_with_checkout`, `gha_no_top_level_permissions`, `shell_curl_pipe_installer`, `shell_sudo_used`, `shell_permissive_chmod` |
| `service_hints` | `service_name:<compose service>` |

The Dockerfile user check looks at the final stage's effective user (the last `USER`, inherited through `FROM <stage>`). A `USER nobody` in a builder stage doesn't hide a root final image, and `USER root` followed by `USER app` isn't flagged. A final base tagged `:nonroot` counts as setting a user.

Secret-shaped `ENV`/`ARG` names (`*SECRET*`, `*TOKEN*`, `*PASSWORD*`, `*_KEY`, …) and `environment:` entries with a literal value become `SecretHint(kind="hardcoded")`. `*_FILE` paths, `${VAR}` references, booleans and `ARG` without a default are not flagged.

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
