"""Misconfiguration records (iac#1).

Container and cluster misconfigurations go to core's `CloudMisconfig` record
(AttackMap#334), which core turns into findings with CWE/OWASP ids. They used
to be `AuthHint`s, which core reads as recon: an `AuthHint` in a Dockerfile
even counted as an auth control for the `EXPOSE` route next to it.

With a core that predates `CloudMisconfig` (feature-detected: the SDK doesn't
export it, or `ScanResult` has no `cloud_misconfigs`), the legacy `AuthHint`
(if the check had one) is emitted instead. The `gha_*` / `shell_*` posture
hints are `FrameworkHint`s on every core, old ones included: they were never
auth signals and no core version consumes them by name.
"""

from __future__ import annotations

from bisect import bisect_right

from .contracts import AuthHint, CloudMisconfig, ScanResult

_EVIDENCE_MAX = 200
# Feature detection: an older core neither exports the record nor has the field.
CLOUD_RECORDS = CloudMisconfig is not None and "cloud_misconfigs" in getattr(ScanResult, "model_fields", {})

# Dedup keys per result, so appending stays O(1) on hostile input with
# tens of thousands of signals (a linear `any(...)` scan per append is
# quadratic). Keyed by id(); the result object is kept to rule out reuse.
_SEEN: dict[int, tuple[object, set]] = {}


def first_seen(owner: object, key: tuple) -> bool:
    """True the first time ``key`` is offered for ``owner`` (a result, or a
    hint list of one)."""
    entry = _SEEN.get(id(owner))
    if entry is None or entry[0] is not owner:
        entry = _SEEN[id(owner)] = (owner, set())
    if key in entry[1]:
        return False
    entry[1].add(key)
    return True


# Line starts of the file being analyzed: `line_of` / `line_snippet` from the
# SDK rescan the text on every call, which is quadratic for a file with
# tens of thousands of matches. Files are analyzed one at a time, so one
# cached index is enough.
_LINES: list = [None, [0]]


def _starts(content: str) -> list[int]:
    if _LINES[0] is not content:
        starts = [0]
        index = content.find("\n")
        while index != -1:
            starts.append(index + 1)
            index = content.find("\n", index + 1)
        _LINES[0], _LINES[1] = content, starts
    return _LINES[1]


def line_of(content: str, offset: int) -> int:
    """1-indexed line of ``offset`` (same numbering as `attackmap.sdk.line_of`)."""
    return bisect_right(_starts(content), max(offset, 0))


def line_snippet(content: str, line: int, max_len: int = 200) -> str:
    """Stripped text of 1-indexed ``line`` (as `attackmap.sdk.line_snippet`)."""
    starts = _starts(content)
    if line < 1 or line > len(starts):
        return ""
    end = starts[line] - 1 if line < len(starts) else len(content)
    text = content[starts[line - 1]:end].strip()
    return text if len(text) <= max_len else text[: max_len - 1] + "…"


def release(*owners: object) -> None:
    for owner in owners:
        _SEEN.pop(id(owner), None)


def append_misconfig(
    result: ScanResult,
    kind: str,
    file: str,
    line: int | None,
    evidence: str,
    *,
    severity: str,
    confidence: float = 0.8,
    resource: str | None = None,
    platform: str | None = None,
    escalation: str | None = None,
    context: str | None = None,
    legacy_auth_hint: str | None = None,
) -> None:
    """One record per (kind, file, line, resource)."""
    evidence = " ".join(evidence.split())
    if len(evidence) > _EVIDENCE_MAX:
        evidence = evidence[: _EVIDENCE_MAX - 1] + "…"
    if not CLOUD_RECORDS:
        if legacy_auth_hint and first_seen(result, ("auth", legacy_auth_hint, file)):
            result.auth_hints.append(
                AuthHint(hint=legacy_auth_hint, file=file, line=line, evidence_text=evidence, confidence=0.9)
            )
        return
    if not first_seen(result, ("misconfig", kind, file, line, resource, evidence)):
        return
    result.cloud_misconfigs.append(
        CloudMisconfig(
            kind=kind, file=file, line=line, resource=resource, platform=platform, context=context,
            escalation_path=escalation, evidence_text=evidence, severity=severity, confidence=confidence,
        )
    )


# Linux capabilities that let a process break out of its container or take
# over the node (high) or its network (medium). `CAP_` prefix stripped.
DANGEROUS_CAPABILITIES = {
    "ALL": "high",
    "SYS_ADMIN": "high",
    "SYS_MODULE": "high",
    "SYS_PTRACE": "high",
    "SYS_RAWIO": "high",
    "DAC_READ_SEARCH": "high",
    "BPF": "high",
    "NET_ADMIN": "medium",
    "SYS_TIME": "medium",
}

# Host paths whose mount hands a container the node: runtime sockets, the
# root filesystem, kubelet state, kernel interfaces.
_RUNTIME_SOCKETS = ("/var/run/docker.sock", "/run/docker.sock", "/var/run/containerd", "/run/containerd",
                    "/var/run/crio", "/run/crio", "/var/run/cri-dockerd.sock")
_SENSITIVE_HOST_PATHS = (*_RUNTIME_SOCKETS, "/etc", "/root", "/proc", "/sys", "/dev", "/boot",
                         "/var/lib/kubelet", "/var/lib/docker", "/var/lib/containerd")


# Read-only system data under the sensitive trees above: CA bundles, time
# zone, the syslog socket.
_BENIGN_HOST_PATHS = ("/etc/ssl", "/etc/pki", "/etc/ca-certificates", "/etc/localtime", "/etc/timezone",
                      "/etc/machine-id", "/etc/os-release", "/etc/letsencrypt", "/dev/log", "/dev/dri",
                      "/usr/share/ca-certificates")


def _normalize(path: str) -> str:
    path = path.strip().strip("'\"")
    while "//" in path:
        path = path.replace("//", "/")
    return path.rstrip("/") or "/"


def host_path_risk(path: str) -> tuple[str, str]:
    """``(severity, escalation)`` for mounting host ``path``."""
    norm = _normalize(path)
    if any(norm == s or norm.startswith(s + "/") for s in _RUNTIME_SOCKETS):
        return "high", "container runtime socket → start a privileged container → root on the node"
    if norm == "/":
        return "high", "host root filesystem → node root, kubelet credentials and every pod's secrets"
    if any(norm == s or norm.startswith(s + "/") for s in _BENIGN_HOST_PATHS):
        return "low", f"host {norm} is readable from the container"
    if any(norm == s or norm.startswith(s + "/") for s in _SENSITIVE_HOST_PATHS):
        return "high", f"host {norm} → node credentials or kernel interfaces → root on the node"
    return "low", f"host {norm} is readable (and possibly writable) from the container"


def capability_severity(cap: str) -> str | None:
    return DANGEROUS_CAPABILITIES.get(cap.strip().strip("'\"").upper().removeprefix("CAP_"))


# ---------- Kubernetes RBAC and Service exposure (shared by manifests) ----------

# API groups whose objects are cluster control. A wildcard on a CRD group an
# operator owns (`monitoring.coreos.com`) or on `metrics.k8s.io` is normal.
SENSITIVE_API_GROUPS = frozenset({
    "", "*", "apps", "batch", "extensions", "policy", "networking.k8s.io", "rbac.authorization.k8s.io",
    "admissionregistration.k8s.io", "certificates.k8s.io", "apiextensions.k8s.io",
})
# Resources whose write (or read, for secrets) is a step toward cluster control.
SENSITIVE_RESOURCES = frozenset({
    "*", "secrets", "pods", "pods/exec", "pods/attach", "pods/ephemeralcontainers", "deployments", "daemonsets",
    "statefulsets", "replicasets", "jobs", "cronjobs", "replicationcontrollers", "serviceaccounts",
    "serviceaccounts/token", "roles", "rolebindings", "clusterroles", "clusterrolebindings", "nodes",
    "nodes/proxy", "persistentvolumes", "mutatingwebhookconfigurations", "validatingwebhookconfigurations",
    "customresourcedefinitions", "certificatesigningrequests", "certificatesigningrequests/approval",
    "configmaps", "namespaces", "networkpolicies",
})
# Roles whose grant to every authenticated user is a takeover.
ADMIN_LIKE_ROLES = frozenset({"cluster-admin", "admin", "edit"})


def rbac_wildcard(groups: set[str] | None, verbs: set[str], resources: set[str]) -> bool:
    """A `*` that matters: on a control-plane API group (``groups`` None
    means the rule names none), and either every resource or a sensitive
    one. `verbs: ["*"]` on `events` or `metrics.k8s.io` is not reported."""
    if "*" not in verbs and "*" not in resources:
        return False
    if groups is not None and not groups & SENSITIVE_API_GROUPS:
        return False
    return "*" in resources or bool(resources & SENSITIVE_RESOURCES)


# Annotation key suffix → values that make a LoadBalancer internal.
_INTERNAL_LB_ANNOTATIONS = {
    "aws-load-balancer-internal": {"true", "0.0.0.0/0"},
    "aws-load-balancer-scheme": {"internal"},
    "azure-load-balancer-internal": {"true"},
    "oci-load-balancer-internal": {"true"},
    "openstack-internal-load-balancer": {"true"},
    "load-balancer-type": {"internal"},  # networking.gke.io/, cloud.google.com/
    "ibm-load-balancer-cloud-provider-ip-type": {"private"},
    "alibaba-cloud-loadbalancer-address-type": {"intranet"},
}


def internal_lb(annotations: dict[str, str]) -> bool:
    """True when a cloud's internal-load-balancer annotation says so. An
    explicit ``"false"`` / ``internet-facing`` is external; a templated
    value (``__TPL__`` / ``${...}``) is unknown, so treated as internal
    (not reported)."""
    for key, value in annotations.items():
        suffix = key.rsplit("/", 1)[-1].lower()
        accepted = _INTERNAL_LB_ANNOTATIONS.get(suffix)
        if accepted is None:
            continue
        text = value.strip().strip("\"'").lower()
        if "__tpl__" in text or "${" in text or text.startswith("var."):
            return True
        if text in accepted:
            return True
    return False
