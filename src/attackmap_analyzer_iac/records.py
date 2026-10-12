"""Misconfiguration records (iac#1).

Container and cluster misconfigurations go to core's `CloudMisconfig` record
(AttackMap#334), which core turns into findings with CWE/OWASP ids. They used
to be `AuthHint`s, which core reads as recon: an `AuthHint` in a Dockerfile
even counted as an auth control for the `EXPOSE` route next to it.

With a core that predates `CloudMisconfig`, the legacy hint (if the check had
one) is emitted instead, so an old core sees what it saw before.
"""

from __future__ import annotations

from .contracts import AuthHint, CloudMisconfig, ScanResult

_EVIDENCE_MAX = 200


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
    if CloudMisconfig is None:
        if legacy_auth_hint and not any((h.hint, h.file) == (legacy_auth_hint, file) for h in result.auth_hints):
            result.auth_hints.append(
                AuthHint(hint=legacy_auth_hint, file=file, line=line, evidence_text=evidence, confidence=0.9)
            )
        return
    key = (kind, file, line, resource)
    if any((m.kind, m.file, m.line, m.resource) == key for m in result.cloud_misconfigs):
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
                      "/etc/machine-id", "/etc/os-release", "/dev/log", "/usr/share/ca-certificates")


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
