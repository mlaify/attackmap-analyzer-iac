"""Kubernetes / Helm checks and CloudMisconfig records (iac#1).

Needs AttackMap core with ``attackmap.sdk.CloudMisconfig`` (AttackMap#334).
"""

from __future__ import annotations

import random
from pathlib import Path

import pytest

from attackmap_analyzer_iac import IacAnalyzer, records
from attackmap_analyzer_iac.k8s import strip_helm

FIXTURES = Path(__file__).parent / "fixtures"
K8S = FIXTURES / "k8s_repo"


def _scan(tmp_path: Path, files: dict[str, str]):
    for name, text in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return IacAnalyzer().analyze(tmp_path)


def _kinds(result, file: str | None = None) -> list[tuple[str, str]]:
    return sorted((m.kind, m.severity) for m in result.cloud_misconfigs if file is None or m.file == file)


@pytest.fixture(scope="module")
def k8s():
    return IacAnalyzer().analyze(K8S)


# ---------- Acceptance fixtures and their hardened twins ----------


def test_privileged_pod_and_its_hardened_twin(k8s) -> None:
    assert _kinds(k8s, "k8s/privileged-pod.yaml") == [
        ("dangerous_capability", "high"),  # SYS_ADMIN; NET_BIND_SERVICE is fine
        ("host_namespace_shared", "high"),  # hostPID
        ("missing_security_context", "low"),
        ("privileged_container", "high"),
        ("unpinned_container_image", "low"),  # image: busybox
    ]
    record = next(
        m for m in k8s.cloud_misconfigs if (m.kind, m.file) == ("privileged_container", "k8s/privileged-pod.yaml")
    )
    assert (record.line, record.resource, record.platform) == (11, "Pod/debug container shell", "kubernetes")
    assert record.escalation_path and "root on the host" in record.escalation_path
    assert _kinds(k8s, "k8s/hardened-pod.yaml") == []


def test_docker_socket_and_host_root_mounts_and_their_hardened_twin(k8s) -> None:
    mounts = {
        m.evidence_text: (m.severity, m.line)
        for m in k8s.cloud_misconfigs
        if m.file == "k8s/docker-sock-daemonset.yaml" and m.kind == "host_path_mount"
    }
    assert mounts == {"hostPath: /var/run/docker.sock": ("high", 26), "hostPath: /": ("high", 29)}
    assert ("host_namespace_shared", "medium") in _kinds(k8s, "k8s/docker-sock-daemonset.yaml")
    # Twin: a read-only /var/log mount is reported low, nothing else.
    assert _kinds(k8s, "k8s/log-collector-daemonset.yaml") == [("host_path_mount", "low")]


def test_rbac_escalate_verb_secret_read_and_wildcards_and_readonly_twin(k8s) -> None:
    by_resource = {(m.kind, m.resource): m for m in k8s.cloud_misconfigs if m.file == "k8s/rbac-escalate.yaml"}
    assert set(by_resource) == {
        ("rbac_escalation", "ClusterRole/role-manager"),
        ("rbac_secret_access", "ClusterRole/role-manager"),
        ("rbac_wildcard", "Role/everything"),
    }
    assert by_resource[("rbac_escalation", "ClusterRole/role-manager")].line == 6
    assert by_resource[("rbac_wildcard", "Role/everything")].severity == "medium"  # namespaced
    assert _kinds(k8s, "k8s/rbac-readonly.yaml") == []


def test_cluster_admin_bound_to_default_sa_and_viewer_twin(k8s) -> None:
    (record,) = [m for m in k8s.cloud_misconfigs if m.file == "k8s/cluster-admin-default-sa.yaml"]
    assert (record.kind, record.severity, record.line) == ("cluster_admin_binding", "high", 8)
    assert "ServiceAccount default" in (record.evidence_text or "")
    assert _kinds(k8s, "k8s/viewer-binding.yaml") == []


def test_services_entrypoints_and_source_ranges(k8s) -> None:
    exposed = [m.resource for m in k8s.cloud_misconfigs if m.kind == "exposed_service"]
    assert exposed == ["Service/web-public"]
    hints = {h.hint for h in k8s.entrypoint_hints if h.file == "k8s/services.yaml"}
    assert hints == {"k8s_service_loadbalancer:web-public", "k8s_service_loadbalancer:web-office"}


def test_ingress_rules_are_routes_and_entrypoints(k8s) -> None:
    routes = {(r.path, r.method, r.line) for r in k8s.routes if r.file == "k8s/ingress.yaml"}
    assert routes == {("/api", "ANY", 10), ("/admin", "ANY", 17)}
    assert "k8s_ingress:shop.example.com" in {h.hint for h in k8s.entrypoint_hints}


def test_literal_secret_values_are_hardcoded_secrets(k8s) -> None:
    secrets = {(s.name, s.kind) for s in k8s.secret_hints if s.file == "k8s/secret.yaml"}
    assert secrets == {("k8s_secret:db/password", "hardcoded")}  # not username, not "<set me>"
    assert all("correct-horse" not in (s.evidence_text or "") for s in k8s.secret_hints)


# ---------- Helm ----------


def test_helm_templated_values_are_not_reported(k8s) -> None:
    template = [m for m in k8s.cloud_misconfigs if m.file == "charts/agent/templates/daemonset.yaml"]
    got = {(m.kind, m.line): m for m in template}
    # hostNetwork: {{ .Values.hostNetwork }} and the toYaml'd securityContext
    # are the chart's values' business; image tag is templated too.
    assert set(got) == {("privileged_container", 27), ("host_path_mount", 32)}
    conditional = got[("privileged_container", 27)]
    assert conditional.confidence == 0.4 and "{{ if }}" in (conditional.context or "")
    assert got[("host_path_mount", 32)].confidence == 0.9  # literal /proc, unconditional
    assert {m.platform for m in template} == {"helm"}
    assert all("Helm template" in (m.context or "") for m in template)


def test_helm_values_defaults_are_low_confidence(k8s) -> None:
    values = {(m.kind, m.evidence_text, m.confidence) for m in k8s.cloud_misconfigs if m.file == "charts/agent/values.yaml"}
    assert values == {
        ("host_namespace_shared", "hostNetwork: true", 0.5),
        ("container_runs_as_root", "securityContext.runAsUser: 0", 0.5),
    }  # privileged: false and debug.enabled are not flagged


def test_strip_helm_keeps_line_count_and_marks_output_lines() -> None:
    text = (
        "spec:\n"
        "  {{- if .Values.x }}\n"
        "  hostNetwork: {{ .Values.hostNetwork }}\n"
        "  securityContext:\n"
        "    {{- toYaml .Values.sc | nindent 4 }}\n"
        "  {{- end }}\n"
        "  {{/* a\n multi-line\n comment */}}\n"
        "  privileged: true\n"
    )
    stripped = strip_helm(text)
    assert len(stripped.marked) == len(stripped.blanked) == text.count("\n") + 1
    assert stripped.marked[2] == "  hostNetwork: __TPL__"
    assert stripped.marked[4] == "    __templated__: true"
    assert stripped.blanked[4] == ""
    assert {3, 4, 5} <= stripped.conditional and 9 not in stripped.conditional


def test_unterminated_template_action_does_not_hang_or_raise(tmp_path: Path) -> None:
    text = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: x {{ .Values.oops\n" + "a" * 10000
    _scan(tmp_path, {"pod.yaml": text})


def test_marker_inside_a_list_falls_back_without_absence_findings(tmp_path: Path) -> None:
    text = (
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  containers:\n"
        "    - name: app\n      image: app:1.0\n"
        "    {{- toYaml .Values.sidecars | nindent 4 }}\n"
        "  volumes:\n    - name: root\n      hostPath:\n        path: /\n"
    )
    result = _scan(tmp_path, {"pod.yaml": text})
    assert _kinds(result) == [("host_path_mount", "high")]  # no missing_security_context


# ---------- Workload details ----------


@pytest.mark.parametrize(
    "container, expected",
    [
        ("securityContext:\n        runAsUser: 0", [("container_runs_as_root", "medium")]),
        ("securityContext:\n        allowPrivilegeEscalation: true", [("privilege_escalation_allowed", "medium")]),
        ("securityContext:\n        capabilities:\n          add: [NET_ADMIN]", [("dangerous_capability", "medium")]),
        ("securityContext:\n        seccompProfile:\n          type: Unconfined", [("security_profile_disabled", "medium")]),
        ("image: app:latest", [("unpinned_container_image", "low")]),
        ("image: registry.local:5000/app", [("unpinned_container_image", "low")]),
        ("image: registry.local:5000/app:1.2", []),
        ("image: app@sha256:" + "0" * 64, []),
        ('image: "{{ .Values.image }}"', []),
    ],
)
def test_container_settings(tmp_path: Path, container: str, expected: list) -> None:
    text = (
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  securityContext:\n    runAsNonRoot: true\n"
        "  containers:\n    - name: app\n      image: app:1.0\n"
        + ("" if container.startswith("image") else "      ")
        + (container.replace("image:", "      image:", 1) if container.startswith("image") else container)
        + "\n"
    )
    if container.startswith("image"):
        text = text.replace("      image: app:1.0\n", "")
    result = _scan(tmp_path, {"pod.yaml": text})
    got = [k for k in _kinds(result) if k[0] != "missing_security_context"]
    assert got == expected


def test_missing_security_context_is_one_low_record_per_workload(tmp_path: Path) -> None:
    text = (
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  template:\n    spec:\n"
        "      containers:\n        - name: a\n          image: a:1\n        - name: b\n          image: b:1\n"
        "          securityContext:\n            runAsNonRoot: true\n            allowPrivilegeEscalation: false\n"
    )
    (record,) = _scan(tmp_path, {"deploy.yaml": text}).cloud_misconfigs
    assert (record.kind, record.severity, record.confidence) == ("missing_security_context", "low", 0.4)
    assert "a (no runAsNonRoot / allowPrivilegeEscalation: false)" in (record.evidence_text or "")
    assert "b (" not in (record.evidence_text or "")


@pytest.mark.parametrize(
    "path, severity",
    [("/etc/ssl/certs", "low"), ("/dev/log", "low"), ("/etc/kubernetes", "high"), ("/var/lib/kubelet/pods", "high"),
     ("/run/containerd/containerd.sock", "high"), ("//", "high"), ("/data/app", "low")],
)
def test_host_path_severity(tmp_path: Path, path: str, severity: str) -> None:
    text = (
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  containers: []\n"
        f"  volumes:\n    - name: v\n      hostPath:\n        path: {path}\n"
    )
    assert _kinds(_scan(tmp_path, {"pod.yaml": text})) == [("host_path_mount", severity)]


def test_cronjob_pod_template_is_checked(tmp_path: Path) -> None:
    text = (
        "apiVersion: batch/v1\nkind: CronJob\nmetadata:\n  name: c\nspec:\n  jobTemplate:\n    spec:\n"
        "      template:\n        spec:\n          hostPID: true\n          containers: []\n"
    )
    assert _kinds(_scan(tmp_path, {"cron.yaml": text})) == [("host_namespace_shared", "high")]


def test_rbac_wildcard_on_an_operator_crd_group_is_not_flagged(tmp_path: Path) -> None:
    text = (
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata:\n  name: op\nrules:\n"
        "  - apiGroups: [monitoring.coreos.com]\n    resources: ['*']\n    verbs: ['*']\n"
        "  - apiGroups: ['']\n    resources: [pods/exec]\n    verbs: [create]\n"
        "  - apiGroups: ['']\n    resources: [users, groups]\n    verbs: [impersonate]\n"
    )
    records_ = [(m.kind, m.escalation_path) for m in _scan(tmp_path, {"role.yaml": text}).cloud_misconfigs]
    assert [k for k, _ in records_] == ["rbac_escalation", "rbac_escalation"]
    assert "impersonate" in records_[1][1]


def test_binding_to_system_authenticated(tmp_path: Path) -> None:
    text = (
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata:\n  name: all\n"
        "roleRef:\n  kind: ClusterRole\n  name: edit\nsubjects:\n  - kind: Group\n    name: system:authenticated\n"
    )
    (record,) = _scan(tmp_path, {"b.yaml": text}).cloud_misconfigs
    assert (record.kind, record.line) == ("cluster_admin_binding", 9)


def test_detect_finds_manifest_only_repos(tmp_path: Path) -> None:
    (tmp_path / "deploy").mkdir()
    (tmp_path / "deploy" / "svc.yaml").write_text("apiVersion: v1\nkind: Service\nmetadata:\n  name: s\n", encoding="utf-8")
    assert IacAnalyzer().detect(tmp_path) is True
    other = tmp_path / "other"
    other.mkdir()
    (other / "openapi.yaml").write_text("openapi: 3.0.0\ninfo:\n  title: x\n", encoding="utf-8")
    assert IacAnalyzer().detect(other) is False


# ---------- Dockerfile and compose ----------


@pytest.mark.parametrize(
    "dockerfile, expected",
    [
        ("FROM alpine:latest\nUSER app\n", [("unpinned_container_image", "low")]),
        ("FROM alpine\nUSER app\n", [("unpinned_container_image", "low")]),
        ("ARG BASE=alpine\nFROM ${BASE}\nUSER app\n", []),
        ("FROM alpine:3.20\nUSER root\n", [("container_runs_as_root", "medium")]),
        ("FROM alpine:3.20\n", [("container_runs_as_root", "low")]),
        ("FROM alpine:3.20\nUSER app\nADD https://example.com/tool.tgz /opt/\n", [("dockerfile_remote_add", "medium")]),
        ("FROM alpine:3.20\nUSER app\nADD --checksum=sha256:abc https://example.com/t.tgz /opt/\n", []),
        ("FROM alpine:3.20\nUSER app\nRUN curl -fsSL https://x.sh | sh\n", [("dockerfile_curl_pipe_shell", "medium")]),
    ],
)
def test_dockerfile_records(tmp_path: Path, dockerfile: str, expected: list) -> None:
    assert _kinds(_scan(tmp_path, {"Dockerfile": dockerfile})) == expected


def test_compose_records_and_their_negatives(tmp_path: Path) -> None:
    compose = (
        "services:\n"
        "  agent:\n"
        "    image: agent:1\n"
        "    ipc: host\n"
        "    cap_add: [NET_ADMIN]\n"
        "    security_opt:\n"
        "      - apparmor:unconfined\n"
        "    volumes:\n"
        "      - /etc:/host/etc:ro\n"
        "      - /srv/data:/data\n"
        "      # - /var/run/docker.sock:/var/run/docker.sock\n"
        "      - type: bind\n"
        "        source: /run/docker.sock\n"
        "        target: /var/run/docker.sock\n"
    )
    result = _scan(tmp_path, {"compose.yaml": compose})
    got = sorted((m.kind, m.severity, m.line, m.resource) for m in result.cloud_misconfigs)
    assert got == [
        ("dangerous_capability", "medium", 5, "service agent"),
        ("host_namespace_shared", "medium", 4, "service agent"),
        ("host_path_mount", "high", 9, "service agent"),  # /etc
        ("host_path_mount", "high", 13, "service agent"),  # long-syntax source; not the target or the comment
        ("security_profile_disabled", "medium", 7, "service agent"),
    ]
    assert result.auth_hints == []


def test_old_core_gets_the_legacy_auth_hints(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(records, "CLOUD_RECORDS", False)
    result = _scan(
        tmp_path,
        {
            "Dockerfile": "FROM alpine:3.20\n",
            "compose.yaml": "services:\n  app:\n    privileged: true\n    pid: host\n",
        },
    )
    assert {h.hint for h in result.auth_hints} == {
        "dockerfile_no_user_directive", "compose_privileged_container", "compose_pid_host",
    }
    assert result.cloud_misconfigs == []


# ---------- Robustness ----------

_FRAGMENTS = [
    "apiVersion: v1\n", "kind: Pod\n", "kind: ClusterRole\n", "kind: Service\n", "spec:\n", "  containers:\n",
    "    - name: a\n", "      securityContext:\n", "        privileged: true\n", "  hostPID: yes\n",
    "{{- if .Values.x }}\n", "{{ end }}\n", "{{ toYaml . | nindent 8 }}\n", "{{", "}}", "---\n", "rules:\n",
    "  - verbs: ['*']\n", "    resources: *a\n", "&a [1, 2]\n", "[[[[[[", "]]]", "!!python/object:os.system\n",
    "  volumes:\n", "    - hostPath:\n", "        path: /\n", "\t", ": :", "- - -\n", "'\n", '"\n',
]


@pytest.mark.parametrize("seed", range(60))
def test_random_and_truncated_manifests_never_raise(tmp_path: Path, seed: int) -> None:
    rng = random.Random(seed)
    text = "".join(rng.choice(_FRAGMENTS) for _ in range(rng.randint(1, 60)))
    text = "apiVersion: v1\nkind: Pod\n" + text[: rng.randint(0, len(text))]
    (tmp_path / "Chart.yaml").write_text("apiVersion: v2\nname: c\n", encoding="utf-8")
    (tmp_path / "values.yaml").write_text(text, encoding="utf-8")
    (tmp_path / "templates").mkdir()
    (tmp_path / "templates" / "x.yaml").write_text(text, encoding="utf-8")
    (tmp_path / "plain.yaml").write_text(text.replace("{{", "").replace("}}", ""), encoding="utf-8")
    IacAnalyzer().analyze(tmp_path)


def test_deeply_nested_yaml_is_skipped(tmp_path: Path) -> None:
    text = "apiVersion: v1\nkind: Pod\nspec: " + "[" * 5000 + "]" * 5000 + "\n"
    _scan(tmp_path, {"deep.yaml": text})


# ---------- End to end with core ----------


def test_dockerfile_and_compose_misconfigs_are_core_findings(tmp_path: Path) -> None:
    from attackmap.analyzers import analyze_repository
    from attackmap.recon_to_analysis import translate_recon

    (tmp_path / "Dockerfile").write_text(
        "FROM node:20.11.1\nRUN curl -fsSL https://get.example.com | sh\nEXPOSE 3000\n", encoding="utf-8"
    )
    (tmp_path / "compose.yaml").write_text("services:\n  app:\n    privileged: true\n", encoding="utf-8")
    (tmp_path / "rbac.yaml").write_text((K8S / "k8s" / "cluster-admin-default-sa.yaml").read_text(), encoding="utf-8")
    scan = analyze_repository(tmp_path, analyzers=[IacAnalyzer()])
    findings = {f.rule_id: f for f in translate_recon(scan).findings}
    assert {
        "container-runs-as-root", "dockerfile-curl-pipe-shell", "privileged-container", "cluster-admin-binding",
    } <= set(findings)
    assert findings["privileged-container"].severity == "high"
    assert findings["container-runs-as-root"].taxonomy and findings["container-runs-as-root"].taxonomy.cwe
    # No AuthHint lands next to the Dockerfile's EXPOSE route as a fake auth control.
    assert not scan.auth_hints


# ---------- Hostile input (review round 1) ----------

_RUN_ANALYZER = "import sys; from attackmap_analyzer_iac import IacAnalyzer; IacAnalyzer().analyze(sys.argv[1])"


@pytest.mark.parametrize(
    "files",
    [
        {"deep.yaml": "apiVersion: v1\nkind: Pod\nspec: " + "[" * 30000 + "\n"},
        {"Chart.yaml": "apiVersion: v2\nname: c\n", "values.yaml": "a: " + "{" * 30000 + "\n"},
        {"indent.yaml": "apiVersion: v1\nkind: Pod\n" + "".join(" " * i + "a:\n" for i in range(0, 1200, 2))},
    ],
    ids=["flow-nesting", "values-nesting", "indent-nesting"],
)
def test_deep_nesting_does_not_crash_the_interpreter(tmp_path: Path, files: dict[str, str]) -> None:
    # libyaml segfaulted (exit -11) on 30000 nested `[`; run in a subprocess
    # so a crash fails the test instead of killing pytest.
    import os
    import subprocess
    import sys

    for name, text in files.items():
        (tmp_path / name).write_text(text, encoding="utf-8")
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)}
    proc = subprocess.run([sys.executable, "-c", _RUN_ANALYZER, str(tmp_path)], env=env, timeout=120,
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr[-2000:]


def test_too_nested_allows_real_manifests() -> None:
    from attackmap_analyzer_iac.k8s import too_nested

    assert not too_nested((K8S / "k8s" / "docker-sock-daemonset.yaml").read_text())
    assert not too_nested("a: '[[[[[['\nb: \"{{{{\"\n")  # brackets inside quotes don't count
    assert too_nested("x: " + "[" * 201)


def test_many_helm_blocks_are_linear(tmp_path: Path) -> None:
    import time

    (tmp_path / "x.yaml").write_text("apiVersion: v1\nkind: Pod\n" + "{{ range . }}\n" * 80000, encoding="utf-8")
    start = time.monotonic()
    IacAnalyzer().analyze(tmp_path)
    assert time.monotonic() - start < 5  # was ~10 s (quadratic any(stack))


def test_many_records_dedup_is_linear(tmp_path: Path) -> None:
    import time

    compose = "services:\n  a:\n" + "".join(f"    privileged: true\n" for _ in range(20000))
    (tmp_path / "compose.yaml").write_text(compose, encoding="utf-8")
    start = time.monotonic()
    result = IacAnalyzer().analyze(tmp_path)
    assert time.monotonic() - start < 5
    assert len(result.cloud_misconfigs) == 20000


# ---------- Precision (review round 1) ----------


@pytest.mark.parametrize(
    "rule, expected",
    [
        ("  - apiGroups: ['']\n    resources: [events]\n    verbs: ['*']\n", []),
        ("  - apiGroups: [metrics.k8s.io]\n    resources: ['*']\n    verbs: [get, list]\n", []),
        ("  - apiGroups: ['']\n    resources: [pods]\n    verbs: ['*']\n", ["rbac_wildcard"]),
        ("  - apiGroups: ['*']\n    resources: ['*']\n    verbs: [get]\n", ["rbac_wildcard"]),
        ("  - apiGroups: ['']\n    resources: [secrets]\n    resourceNames: [app-tls]\n    verbs: [get]\n", []),
        ("  - apiGroups: ['']\n    resources: [secrets]\n    verbs: [get]\n", ["rbac_secret_access"]),
    ],
)
def test_rbac_api_group_resource_and_resource_names_filters(tmp_path: Path, rule: str, expected: list) -> None:
    text = "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata:\n  name: r\nrules:\n" + rule
    assert [m.kind for m in _scan(tmp_path, {"role.yaml": text}).cloud_misconfigs] == expected


@pytest.mark.parametrize("role, expected", [("system:basic-user", 0), ("view", 0), ("edit", 1), ("admin", 1)])
def test_system_authenticated_binding_needs_an_admin_like_role(tmp_path: Path, role: str, expected: int) -> None:
    text = (
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata:\n  name: b\n"
        f"roleRef:\n  kind: ClusterRole\n  name: {role}\nsubjects:\n  - kind: Group\n    name: system:authenticated\n"
    )
    assert len(_scan(tmp_path, {"b.yaml": text}).cloud_misconfigs) == expected


@pytest.mark.parametrize(
    "annotation, exposed",
    [
        ('service.beta.kubernetes.io/aws-load-balancer-internal: "true"', False),
        ('service.beta.kubernetes.io/aws-load-balancer-internal: "false"', True),
        ("service.beta.kubernetes.io/aws-load-balancer-scheme: internet-facing", True),
        ("service.beta.kubernetes.io/aws-load-balancer-scheme: internal", False),
        ("networking.gke.io/load-balancer-type: Internal", False),
        ('service.beta.kubernetes.io/azure-load-balancer-internal: "{{ .Values.internal }}"', False),
        ("prometheus.io/scrape: 'true'", True),
    ],
)
def test_internal_load_balancer_annotations(tmp_path: Path, annotation: str, exposed: bool) -> None:
    text = (
        f"apiVersion: v1\nkind: Service\nmetadata:\n  name: s\n  annotations:\n    {annotation}\n"
        "spec:\n  type: LoadBalancer\n"
    )
    assert bool(_scan(tmp_path, {"svc.yaml": text}).cloud_misconfigs) is exposed


@pytest.mark.parametrize("path", ["/etc/letsencrypt", "/dev/dri"])
def test_more_benign_host_paths(tmp_path: Path, path: str) -> None:
    text = (
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  containers: []\n"
        f"  volumes:\n    - name: v\n      hostPath:\n        path: {path}\n"
    )
    assert _kinds(_scan(tmp_path, {"pod.yaml": text})) == [("host_path_mount", "low")]


@pytest.mark.parametrize("seed", range(20))
def test_cached_line_helpers_match_the_sdk(seed: int) -> None:
    from attackmap.sdk import line_of as sdk_line_of, line_snippet as sdk_snippet

    from attackmap_analyzer_iac.records import line_of, line_snippet

    rng = random.Random(seed)
    text = "".join(rng.choice(["a", " ", "\n", "\r\n", "\f", "x" * 300, "\t"]) for _ in range(rng.randint(0, 200)))
    for offset in range(0, len(text) + 1, max(1, len(text) // 17 or 1)):
        assert line_of(text, offset) == sdk_line_of(text, offset)
    for line in range(0, text.count("\n") + 3):
        assert line_snippet(text, line) == sdk_snippet(text, line)


def test_records_and_hints_are_deduplicated() -> None:
    from attackmap_analyzer_iac.contracts import ScanResult

    result = ScanResult(root=".")
    for _ in range(3):
        records.append_misconfig(result, "privileged_container", "a.yaml", 3, "privileged: true", severity="high")
    records.append_misconfig(result, "privileged_container", "a.yaml", 3, "privileged: true", severity="high",
                             resource="other")
    assert len(result.cloud_misconfigs) == 2
    other = ScanResult(root=".")
    records.append_misconfig(other, "privileged_container", "a.yaml", 3, "privileged: true", severity="high")
    assert len(other.cloud_misconfigs) == 1  # keys are per result
    records.release(result, other)
