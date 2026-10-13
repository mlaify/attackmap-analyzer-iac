# Changelog

All notable changes to `attackmap-analyzer-iac` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — Kubernetes / Helm checks and misconfiguration records (#1, AttackMap#334)

- **Kubernetes manifests** (`.yaml`/`.yml` with top-level `apiVersion:` and `kind:`) are parsed with PyYAML's composer (line numbers kept), one `---` document at a time. `detect()` now fires on manifest-only repos.
  - Workloads (Pod, Deployment, StatefulSet, DaemonSet, ReplicaSet, Job, CronJob, ReplicationController): privileged and privilege-escalating containers, `runAsUser: 0`, `hostPath` volumes (tiered: runtime socket, `/`, `/etc`, `/proc`, `/sys`, `/dev`, `/var/lib/kubelet`… high; CA bundles, `/dev/log` and other paths low), `hostPID`/`hostNetwork`/`hostIPC`, dangerous capabilities, `Unconfined` seccomp/AppArmor, `:latest`/untagged images, and one low-confidence `missing_security_context` per workload whose containers lack `runAsNonRoot` or `allowPrivilegeEscalation: false`.
  - RBAC: `*` verbs/resources on core, RBAC, apps and other control-plane API groups (not on an operator's own CRD group), `escalate`/`bind`/`impersonate`, `create` on `pods/exec`/`pods/attach`, `get`/`list`/`watch` on Secrets; `ClusterRoleBinding`/`RoleBinding` to `cluster-admin` or to `system:authenticated`/`unauthenticated`/`anonymous`.
  - Services of type `LoadBalancer`/`NodePort` are entrypoints, and without `loadBalancerSourceRanges` an `exposed_service` record (internal load balancers skipped). `Ingress` host/path rules are `Route`s (`ANY`) plus a `k8s_ingress:<host>` entrypoint. Literal `Secret` `data`/`stringData` values with credential-shaped keys are `SecretHint(kind="hardcoded")` (value redacted).
- **Helm charts** are analyzed without rendering. `{{ }}` actions are stripped with line numbers kept. A templated value is never reported, and a `toYaml`'d block counts as set (no "missing" record). Settings inside `{{ if }}`/`{{ with }}` are reported at confidence 0.4. If the stripped text doesn't parse, the document is re-parsed with directive lines blanked and absence checks are skipped. `values.yaml` next to a `Chart.yaml` is checked for insecure defaults at confidence 0.5.
- **Dockerfile:** `FROM` with `:latest` or no tag (`unpinned_container_image`). `ADD <url>` now also matches with flags before the URL, and `ADD --checksum=…` is not reported as a misconfiguration.
- **Compose:** `ipc: host`, `apparmor:unconfined`, and other dangerous `cap_add` values (`SYS_MODULE`, `SYS_PTRACE`, `NET_ADMIN`, …). Bind mounts of `/etc`, `/proc`, `/sys` and similar host paths are reported, and so is every occurrence of each setting, not just the first. Commented-out lines and the container side of a long-syntax mount are skipped. Records name the compose service.

### Fixed — review round 1 (#1)

- **Hostile input.**
  - YAML nested deeper than 200 flow levels, or indented more than 400 columns, is skipped before it reaches libyaml. 30000 nested `[` used to crash the interpreter (SIGSEGV in CSafeLoader), including through a chart's `values.yaml`.
  - Helm stripping tracks open `{{ if }}`/`{{ with }}` blocks with a counter, so 80000 `{{ range }}` lines take 0.1 s (was 10 s, quadratic).
  - Signal dedup uses key sets, and line numbers and snippets come from a per-file line index (the SDK helpers rescan the file per call). 20000 records in one file are linear.
- **YAML is parsed with the pure-Python `SafeLoader`, never libyaml.** Shapes that slipped past the nesting pre-check (a quote inside a plain scalar, multi-line quoted strings) still segfaulted CSafeLoader. The Python composer raises a catchable `RecursionError` instead, and the pre-check stays as a fast reject. Cost: helm-charts (626 manifest/values files) 0.6 s → 3.4 s, kubernetes--examples 0.05 s → 0.13 s.
- **RBAC.**
  - A wildcard is reported only on a control-plane API group *and* for `*` or a sensitive resource. `verbs: ["*"]` on `events` or `metrics.k8s.io` isn't reported.
  - Secret reads narrowed by `resourceNames` aren't reported.
  - A binding of `system:authenticated`/`unauthenticated`/`anonymous` is reported only for `cluster-admin`, `admin` or `edit`; the default `system:basic-user`/`system:discovery` bindings aren't.
- **Services.** Internal load balancers are recognized by value, not by a substring of the annotation: `aws-load-balancer-internal: "false"` and `aws-load-balancer-scheme: internet-facing` are exposed. Recognized internal annotations are AWS, GKE, Azure, OCI, OpenStack, IBM and Alibaba; a templated value counts as internal.
- **Benign host paths:** `/etc/letsencrypt` and `/dev/dri` are low.
- **Older cores.** Records are feature-detected (the SDK exports `CloudMisconfig` *and* `ScanResult` has `cloud_misconfigs`). Without them the legacy container `AuthHint`s are emitted. The `gha_*`/`shell_*` hints are `FrameworkHint`s on every core.

### Changed — misconfigurations are `CloudMisconfig` records, not `AuthHint`s (#1)

- Container misconfigurations are emitted as core's `CloudMisconfig` record (AttackMap#334), which core turns into findings. Before this, `dockerfile_no_user_directive`, `dockerfile_user_root`, `compose_privileged_container`, `compose_docker_socket_mount`, `compose_cap_add_sys_admin`, `compose_pid_host` and `compose_seccomp_unconfined` were `AuthHint`s, which never became findings and counted as auth signals for routes in the same file (a Dockerfile `EXPOSE`). Remote `ADD`, `RUN curl | sh` and `network_mode: host` also get records. Their framework / entrypoint hints are unchanged.
- `gha_pull_request_target_with_checkout`, `gha_no_top_level_permissions`, `shell_sudo_used` and `shell_permissive_chmod` move from `auth_hints` to `framework_hints` (strings unchanged). The plugin emits no `AuthHint`s.
- With a core that has no `CloudMisconfig`, the seven container `AuthHint`s above are still emitted, so an old core sees what it saw before.
- New dependency: `PyYAML>=6.0` (already an AttackMap core dependency).

### Fixed — Dockerfile / compose misreads (#2)

- **Dockerfile and compose name variants are analyzed.**
  - Dockerfiles: `Dockerfile.prod`, `Dockerfile-dev`, `api.Dockerfile`, `*.dockerfile` and `Containerfile.*`. BuildKit's `Dockerfile.dockerignore` and `Dockerfile.md`/`.txt`/`.rst` are not.
  - Compose files: `docker-compose.override.yml`, `docker-compose.prod.yml`, `compose.*.yaml` and `compose-*.yml`. `composer.yml` is not.
- **USER and HEALTHCHECK are checked on the final build stage.** The Dockerfile is split into stages at each `FROM`. The final stage's effective `USER` and `HEALTHCHECK` come from its own last directive, or are inherited through `FROM <earlier stage>`.
  - A `USER nobody` in a builder stage no longer hides a final stage that runs as root. That case now gets `dockerfile_no_user_directive`, anchored at the final `FROM`.
  - `USER root` … `USER app` is no longer reported as root.
  - A `:nonroot` final base counts as setting a user.
- **Base-image pinning skips `scratch` and stage aliases, and reports every image.**
  - `FROM scratch` and `FROM <earlier-stage-alias>` (case-insensitive) are not unpinned images.
  - `FROM --platform=…` no longer reads the flag as the image.
  - The hint is now `dockerfile_base_image_unpinned:<image>`, one per unpinned image. Before, only the first per file survived the `(hint, file)` dedup.
- **Literal secrets in `ENV`/`ARG` and compose `environment:` are flagged** as `SecretHint(kind="hardcoded")`. This applies to secret-shaped names (`*SECRET*`, `*TOKEN*`, `*PASSWORD*`, `*_KEY`, `API_KEY`, …) with a literal value. It covers `ENV A=1 B=2`, legacy `ENV NAME value`, line continuations, `ARG NAME=default`, and the map and list forms of `environment:`. `*_FILE` paths, `${VAR}` references, booleans and `ARG` without a default are not flagged.
- **Short-syntax ports without a host IP bind all interfaces.** This includes `"5432:5432"`, a bare `"3000"`, and long syntax with `published:` and no `host_ip`. They are flagged like an explicit `0.0.0.0`. Loopback binds (`127.0.0.1:…`, `[::1]:…`) are not.
  - Ports are read only from `ports:` blocks, so other list items that happen to contain `n:n` no longer count.
  - The hint is now `compose_port_binding_all_interfaces:<binding>`, one per binding. Core merges hints by `(hint, file)`, so a bare name kept only the first.
- **Host-root-equivalent compose settings are elevated.** New `AuthHint`s: `compose_docker_socket_mount` (`/var/run/docker.sock` or `/run/docker.sock`; the generic `compose_host_mount:*` framework hint is still emitted too), `compose_cap_add_sys_admin` (`SYS_ADMIN` or `ALL`), `compose_pid_host` and `compose_seccomp_unconfined`. They are privilege posture like `compose_privileged_container`, and `test_signal_conformance.py`'s allow-list is extended with that justification.
- **Breaking for direct consumers of the hint strings:** `dockerfile_base_image_unpinned` and `compose_port_binding_all_interfaces` now carry a `:<image>` / `:<binding>` suffix, like `compose_host_mount:<path>`. AttackMap core doesn't match on either name.

### Changed — typed signals instead of overloaded `AuthHint`s (AttackMap#258)

- **`auth_hints` now carries only privilege/authorization posture.** The SDK has no weakness/posture signal type, so the IaC posture checks that used to all be `AuthHint`s are split by meaning, keeping their hint strings (see the README's *Posture signals* table):
  - stays `AuthHint` (who the workload or CI job runs as / what it may do): `dockerfile_no_user_directive`, `dockerfile_user_root`, `compose_privileged_container`, `shell_sudo_used`, `shell_permissive_chmod`, `gha_pull_request_target_with_checkout`, `gha_no_top_level_permissions`
  - → `EntrypointHint` (network exposure): `compose_port_binding_all_interfaces`, `compose_network_mode_host`
  - → `FrameworkHint` (build, supply-chain and deployment config): `dockerfile_no_healthcheck`, `dockerfile_run_curl_pipe`, `dockerfile_add_remote`, `dockerfile_base_image_unpinned`, `compose_env_file_reference`, `compose_host_mount:*`, `gha_third_party_action_tag_pinned:*`, `shell_curl_pipe_installer`
- **Every signal now cites a line and quotes it.** Posture hints, compose `service_name:*` hints, external calls and secret hints carry `line` and `evidence_text` (via `attackmap.sdk.line_of` / `line_snippet`, or the specific image/mount/`owner/repo@ref` where that identifies the signal better). Signals about something missing anchor at the final `FROM` line (`dockerfile_no_user_directive`, `dockerfile_no_healthcheck`) or line 1 (`gha_no_top_level_permissions`) with an explanatory `evidence_text`. Hints set `confidence` (0.9 explicit directives, 0.8 PR-target/env-file/unpinned base image, 0.6 absence checks).
- **Breaking for direct consumers of `ScanResult.auth_hints`:** code that looked for the moved hints in `auth_hints` must read `entrypoint_hints` / `framework_hints`.
- New `tests/test_signal_conformance.py` asserts every emitted `AuthHint.hint` is in an explicit allow-list and every signal has an in-range `line` and evidence.

### Changed

- **License metadata uses an SPDX expression (PEP 639).** `license = "MIT"` and `license-files = ["LICENSE"]` replace the deprecated `license = {text = "MIT"}` table, and the `License ::` classifier (which setuptools ≥ 77 rejects next to an expression) is gone. The build backend floor is now `setuptools>=77` (mlaify/AttackMap#259).
- **Import the analyzer contract from `attackmap.sdk` directly; `contracts.py` is gone.** It only re-exported SDK types (and aliased `AnalyzerProtocol` as `AttackMapAnalyzerProtocol`), and its four copy-pasted variants drifted across the plugins (mlaify/AttackMap#259).
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
