"""Kubernetes manifests and Helm charts (iac#1).

Raw manifests are parsed with PyYAML's composer, which keeps line numbers.
Helm templates are not rendered: each ``{{ ... }}`` action is stripped first
(line count preserved) so the YAML around it still parses:

- an action inside a value (``image: "{{ .Values.repo }}:{{ .Values.tag }}"``)
  becomes the token ``__TPL__``, and a value containing it is *templated*:
  never reported, because the chart's values decide it;
- a line holding only an output action (``{{- toYaml .Values.securityContext
  | nindent 12 }}``) becomes ``__templated__: true`` at the action's indent,
  so the mapping it fills is known to be templated (no "missing" findings);
- a line holding only control actions (``if`` / ``end`` / ``range`` / ``$x :=``)
  becomes blank. A setting inside ``if`` / ``with`` may be off by default, so
  it is reported with low confidence.

If the marked text doesn't parse (a marker can land inside a list), the
document is parsed again with those lines blank and absence checks are
skipped for it. A document that still doesn't parse is skipped. ``values.yaml``
next to a ``Chart.yaml`` is scanned for insecure defaults (low confidence:
the templates may not use them).
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from .contracts import EntrypointHint, Route, ScanResult, SecretHint
from .records import (
    ADMIN_LIKE_ROLES,
    append_misconfig,
    capability_severity,
    first_seen,
    host_path_risk,
    internal_lb,
    rbac_wildcard,
)

_TPL = "__TPL__"
_TEMPLATED_KEY = "__templated__"
_ACTION_MAX = 4096  # an unterminated `{{` blanks at most this much
_DOC_MAX = 2000  # documents per file
_WALK_BUDGET = 20000  # nodes visited per values.yaml

# `{{- if ...}}`, `{{ end }}`, `{{/* comment */}}`, `{{- $x := ... }}`: produce no output.
_CONTROL_RE = re.compile(r"\{\{-?\s*(?:/\*|(?:if|else|end|range|with|define|block|break|continue)\b|\$\w*\s*:?=)")
_OPENS_CONDITIONAL_RE = re.compile(r"\{\{-?\s*(?:if|with)\b")
_OPENS_BLOCK_RE = re.compile(r"\{\{-?\s*(?:range|define|block)\b")
_ENDS_BLOCK_RE = re.compile(r"\{\{-?\s*end\b")
_NINDENT_RE = re.compile(r"\bn?indent\s+(\d{1,3})\b")
_DOC_SEPARATOR_RE = re.compile(r"^---(?:[ \t]|$)")
_K8S_MARKER_RE = re.compile(r"^apiVersion:", re.MULTILINE)
_K8S_KIND_RE = re.compile(r"^kind:", re.MULTILINE)
_IMAGE_TAG_RE = re.compile(r":([\w][\w.-]{0,127})$")
# Secret data keys that hold credentials (not `username`, `host`, `tls.crt`).
_SECRET_DATA_KEY_RE = re.compile(r"secret|token|passw|pwd|credential|private|key|auth|dockerconfig|htpasswd", re.IGNORECASE)
# ...except identifiers next to them (`auth.username`, `api-key-id`).
_SECRET_DATA_NON_SECRET_RE = re.compile(r"user|(?:^|[._-])(?:name|host|port|url|endpoint|id)$", re.IGNORECASE)
_SECRET_DATA_STRONG_RE = re.compile(r"passw|secret|token", re.IGNORECASE)

_Loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
# libyaml (and PyYAML's composer) recurse per nesting level; 30000 nested `[`
# segfaults CSafeLoader. Real manifests nest a few dozen levels.
_MAX_FLOW_DEPTH = 200
_MAX_INDENT = 400

_POD_SPEC_PATHS: dict[str, tuple[str, ...]] = {
    "Pod": ("spec",),
    "Deployment": ("spec", "template", "spec"),
    "ReplicaSet": ("spec", "template", "spec"),
    "StatefulSet": ("spec", "template", "spec"),
    "DaemonSet": ("spec", "template", "spec"),
    "Job": ("spec", "template", "spec"),
    "ReplicationController": ("spec", "template", "spec"),
    "CronJob": ("spec", "jobTemplate", "spec", "template", "spec"),
}
_CONTAINER_LISTS = ("initContainers", "containers", "ephemeralContainers")
_BROAD_GROUPS = frozenset({"system:authenticated", "system:unauthenticated", "system:anonymous"})
_NAMESPACES = (
    ("hostPID", "high", "host PID namespace → see and signal node processes and read their environment"),
    ("hostNetwork", "medium", "host network namespace → reach node-local services (kubelet, cloud metadata) and other pods' traffic"),
    ("hostIPC", "medium", "host IPC namespace → read other processes' shared memory"),
)


def looks_like_k8s(content: str) -> bool:
    return bool(_K8S_MARKER_RE.search(content) and _K8S_KIND_RE.search(content))


# ---------- Helm stripping ----------


class _Stripped:
    __slots__ = ("marked", "blanked", "conditional", "templated")

    def __init__(self, marked: list[str], blanked: list[str], conditional: set[int], templated: bool) -> None:
        self.marked = marked  # lines, output-only directive lines as `__templated__: true`
        self.blanked = blanked  # lines, every directive-only line blank
        self.conditional = conditional  # 1-based lines inside {{ if }} / {{ with }}
        self.templated = templated


def strip_helm(text: str) -> _Stripped:
    """Strip Go-template actions from ``text`` (see the module docstring)."""
    lines = text.split("\n")
    if "{{" not in text:
        return _Stripped(lines, lines, set(), False)
    pieces: list[str] = []
    # Per line: output actions' requested indent (or None), whether any action started there.
    line_outputs: dict[int, list[int | None]] = {}
    line_has_action: set[int] = set()
    conditional: set[int] = set()
    stack: list[bool] = []  # True for if/with frames
    open_conditionals = [0]  # how many True frames are on the stack (O(1) check)
    pos = 0
    line_no = 0
    while True:
        start = text.find("{{", pos)
        if start == -1:
            chunk = text[pos:]
            _mark_conditional(conditional, line_no, chunk.count("\n"), open_conditionals[0])
            pieces.append(chunk)
            break
        chunk = text[pos:start]
        _mark_conditional(conditional, line_no, chunk.count("\n"), open_conditionals[0])
        line_no += chunk.count("\n")
        pieces.append(chunk)
        end = text.find("}}", start + 2, start + _ACTION_MAX)
        end = min(len(text), start + _ACTION_MAX) if end == -1 else end + 2
        action = text[start:end]
        line_has_action.add(line_no)
        if _CONTROL_RE.match(action):
            if _OPENS_CONDITIONAL_RE.match(action):
                stack.append(True)
                open_conditionals[0] += 1
            elif _OPENS_BLOCK_RE.match(action):
                stack.append(False)
            elif _ENDS_BLOCK_RE.match(action) and stack:
                open_conditionals[0] -= stack.pop()
            replacement = ""
        else:
            indent = _NINDENT_RE.search(action)
            line_outputs.setdefault(line_no, []).append(int(indent.group(1)) if indent else None)
            replacement = _TPL
        newlines = action.count("\n")
        pieces.append(replacement + "\n" * newlines)
        _mark_conditional(conditional, line_no, newlines, open_conditionals[0])
        line_no += newlines
        pos = end
    cleaned = "".join(pieces).split("\n")
    marked = list(cleaned)
    blanked = list(cleaned)
    for index in line_has_action:
        if index >= len(cleaned):
            continue
        line = cleaned[index]
        if line.replace(_TPL, "").strip():
            continue  # real YAML on the line: keep it with its __TPL__ tokens
        blanked[index] = ""
        outputs = line_outputs.get(index)
        if outputs:
            indent = next((i for i in outputs if i is not None), len(line) - len(line.lstrip()))
            marked[index] = " " * indent + f"{_TEMPLATED_KEY}: true"
        else:
            marked[index] = ""
    return _Stripped(marked, blanked, conditional, True)


def _mark_conditional(conditional: set[int], first_line: int, newlines: int, open_conditionals: int) -> None:
    if open_conditionals:
        conditional.update(range(first_line + 1, first_line + newlines + 2))


def _documents(lines: list[str]) -> list[tuple[int, int]]:
    """``(first, end)`` line index ranges of the ``---``-separated documents."""
    docs: list[tuple[int, int]] = []
    start = 0
    for index, line in enumerate(lines):
        if _DOC_SEPARATOR_RE.match(line):
            docs.append((start, index))
            start = index + 1
            if len(docs) >= _DOC_MAX:
                return docs
    docs.append((start, len(lines)))
    return docs


def too_nested(text: str) -> bool:
    """Cheap pre-check before handing text to libyaml: flow-collection
    depth (``[``/``{`` outside quotes) or block indentation beyond what any
    real manifest uses. Linear in the text."""
    depth = 0
    quote = ""
    for ch in text:
        if quote:
            if ch == quote or ch == "\n":
                quote = ""
        elif ch in "[{":
            depth += 1
            if depth > _MAX_FLOW_DEPTH:
                return True
        elif ch in "]}":
            depth = max(depth - 1, 0)
        elif ch in "\"'":
            quote = ch
        elif ch == "\n":
            pass
    return any(len(line) - len(line.lstrip(" ")) > _MAX_INDENT for line in text.split("\n"))


def _compose(lines: list[str], first: int, end: int):
    text = "\n".join(lines[first:end])
    if not text.strip() or too_nested(text):
        return None
    try:
        return yaml.compose(text, Loader=_Loader)
    except Exception:  # YAMLError, RecursionError, bad tags: hostile or templated input
        return None


# ---------- YAML node helpers ----------


def _get(node, key: str):
    if isinstance(node, yaml.MappingNode):
        for k, v in node.value:
            if isinstance(k, yaml.ScalarNode) and k.value == key:
                return v
    return None


def _path(node, keys: tuple[str, ...]):
    for key in keys:
        node = _get(node, key)
        if node is None:
            return None
    return node


def _items(node) -> list:
    return list(node.value) if isinstance(node, yaml.SequenceNode) else []


def _scalar(node) -> str | None:
    return node.value if isinstance(node, yaml.ScalarNode) else None


def _literal(node) -> str | None:
    """A scalar's value unless templated."""
    value = _scalar(node)
    return None if value is None or _TPL in value else value


def _is_true(node) -> bool:
    return isinstance(node, yaml.ScalarNode) and node.tag.endswith(":bool") and node.value.lower() in {"true", "yes", "on"}


def _is_false(node) -> bool:
    return isinstance(node, yaml.ScalarNode) and node.tag.endswith(":bool") and node.value.lower() in {"false", "no", "off"}


def _int(node) -> int | None:
    if isinstance(node, yaml.ScalarNode) and node.tag.endswith(":int"):
        try:
            return int(node.value.replace("_", ""), 0)
        except ValueError:
            return None
    return None


def _line(node, offset: int) -> int:
    return offset + node.start_mark.line + 1


def _templated(node, budget: int = 500) -> bool:
    """True if ``node`` or anything under it came from a template action."""
    stack = [node]
    seen: set[int] = set()
    while stack and budget > 0:
        current = stack.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        budget -= 1
        if isinstance(current, yaml.ScalarNode):
            if _TPL in current.value or current.value == _TEMPLATED_KEY:
                return True
        elif isinstance(current, yaml.MappingNode):
            for k, v in current.value:
                stack += [k, v]
        elif isinstance(current, yaml.SequenceNode):
            stack += current.value
    return budget <= 0


def _display(value: str | None) -> str:
    return (value or "?").replace(_TPL, "{{…}}")


# ---------- Manifest analysis ----------


class _Doc:
    """One parsed document plus where it came from."""

    __slots__ = ("root", "offset", "file", "templated", "chart", "precise", "conditional", "result")

    def __init__(self, root, offset: int, file: str, templated: bool, chart: bool, precise: bool,
                 conditional: set[int], result: ScanResult) -> None:
        self.root = root
        self.offset = offset
        self.file = file
        self.templated = templated
        self.chart = chart
        self.precise = precise  # parsed with templated markers: absence checks are safe
        self.conditional = conditional
        self.result = result

    def record(self, kind: str, node, evidence: str, *, resource: str, severity: str,
               confidence: float, escalation: str | None = None) -> None:
        line = _line(node, self.offset)
        context = []
        if self.chart:
            context.append("Helm template")
        elif self.templated:
            context.append("templated manifest")
        if line in self.conditional:
            context.append("inside an {{ if }}/{{ with }} block: may be off by default")
            confidence = min(confidence, 0.4)
        append_misconfig(
            self.result, kind, self.file, line, evidence, severity=severity, confidence=confidence,
            resource=resource, platform="helm" if self.chart else "kubernetes", escalation=escalation,
            context="; ".join(context) or None,
        )


def analyze_manifest(content: str, relative: str, result: ScanResult, *, chart: bool = False) -> None:
    """Kubernetes manifest or Helm template (``chart``): workloads, RBAC,
    Services, Ingresses and literal Secrets."""
    stripped = strip_helm(content)
    for first, end in _documents(stripped.marked):
        root = _compose(stripped.marked, first, end)
        precise = root is not None
        if root is None and stripped.templated:
            root = _compose(stripped.blanked, first, end)
        if not isinstance(root, yaml.MappingNode):
            continue
        doc = _Doc(root, first, relative, stripped.templated, chart, precise, stripped.conditional, result)
        try:
            _analyze_object(doc)
        except RecursionError:  # pathological nesting
            continue


def _analyze_object(doc: _Doc) -> None:
    kind = _literal(_get(doc.root, "kind"))
    if not kind:
        return
    name = _display(_scalar(_path(doc.root, ("metadata", "name"))))
    resource = f"{kind}/{name}"
    if kind in _POD_SPEC_PATHS:
        pod = _path(doc.root, _POD_SPEC_PATHS[kind])
        if isinstance(pod, yaml.MappingNode):
            _check_pod(doc, pod, resource)
    elif kind in {"ClusterRole", "Role"}:
        _check_role(doc, kind, resource)
    elif kind in {"ClusterRoleBinding", "RoleBinding"}:
        _check_binding(doc, resource)
    elif kind == "Service":
        _check_service(doc, name, resource)
    elif kind == "Ingress":
        _check_ingress(doc, name)
    elif kind == "Secret":
        _check_secret(doc, name)


def _check_pod(doc: _Doc, pod, resource: str) -> None:
    for key, severity, escalation in _NAMESPACES:
        node = _get(pod, key)
        if _is_true(node):
            doc.record("host_namespace_shared", node, f"{key}: true", resource=resource, severity=severity,
                       confidence=0.9, escalation=escalation)
    for volume in _items(_get(pod, "volumes")):
        path_node = _path(volume, ("hostPath", "path"))
        path = _literal(path_node)
        if path:
            severity, escalation = host_path_risk(path)
            doc.record("host_path_mount", path_node, f"hostPath: {path}", resource=resource, severity=severity,
                       confidence=0.9 if severity == "high" else 0.6, escalation=escalation)
    pod_sc = _get(pod, "securityContext")
    _check_profiles(doc, pod_sc, resource)
    pod_user = _int(_get(pod_sc, "runAsUser"))
    pod_nonroot = _is_true(_get(pod_sc, "runAsNonRoot")) or (pod_user is not None and pod_user > 0)

    unhardened: list[str] = []
    for list_key in _CONTAINER_LISTS:
        for container in _items(_get(pod, list_key)):
            cname = _display(_scalar(_get(container, "name")))
            where = f"{resource} container {cname}"
            sc = _get(container, "securityContext")
            privileged = _get(sc, "privileged")
            if _is_true(privileged):
                doc.record("privileged_container", privileged, "privileged: true", resource=where, severity="high",
                           confidence=0.9,
                           escalation="privileged container → every device and capability of the node → root on the host")
            escalation_node = _get(sc, "allowPrivilegeEscalation")
            if _is_true(escalation_node):
                doc.record("privilege_escalation_allowed", escalation_node, "allowPrivilegeEscalation: true",
                           resource=where, severity="medium", confidence=0.9,
                           escalation="setuid binaries in the image can raise the process to root")
            for cap in _items(_path(sc, ("capabilities", "add"))):
                value = _literal(cap)
                severity = capability_severity(value or "")
                if severity:
                    doc.record("dangerous_capability", cap, f"capabilities.add: {value}", resource=where,
                               severity=severity, confidence=0.9,
                               escalation=f"CAP_{value.upper().removeprefix('CAP_')} → kernel interfaces that allow a container escape"
                               if severity == "high" else f"CAP_{value.upper().removeprefix('CAP_')} → control of the pod's network stack")
            user_node = _get(sc, "runAsUser")
            user = _int(user_node)
            if user == 0:
                doc.record("container_runs_as_root", user_node, "runAsUser: 0", resource=where, severity="medium",
                           confidence=0.9, escalation="a compromise of the process is root inside the container")
            elif user is None and pod_user == 0:
                doc.record("container_runs_as_root", _get(pod_sc, "runAsUser"), "pod runAsUser: 0", resource=where,
                           severity="medium", confidence=0.9,
                           escalation="a compromise of the process is root inside the container")
            _check_profiles(doc, sc, where)
            _check_image(doc, container, where)
            if list_key == "ephemeralContainers":
                continue
            nonroot = _is_true(_get(sc, "runAsNonRoot")) or (user is not None and user > 0) or (
                user is None and pod_nonroot
            )
            missing = []
            if not nonroot and not _is_false(_get(sc, "runAsNonRoot")):
                missing.append("runAsNonRoot")
            if not _is_false(escalation_node) and not _is_true(escalation_node) and not _is_true(privileged):
                missing.append("allowPrivilegeEscalation: false")
            # A container inside {{ if }} may not exist; a templated one may
            # get its securityContext from values.
            if missing and not _templated(container) and _line(container, doc.offset) not in doc.conditional:
                unhardened.append(f"{cname} (no {' / '.join(missing)})")
    pod_sc_templated = pod_sc is not None and _templated(pod_sc)
    if unhardened and doc.precise and not pod_sc_templated:
        doc.record("missing_security_context", pod, "containers " + ", ".join(unhardened[:4])
                   + (f" +{len(unhardened) - 4} more" if len(unhardened) > 4 else ""),
                   resource=resource, severity="low", confidence=0.4,
                   escalation="a compromised process keeps root or can regain it through setuid binaries")


def _check_profiles(doc: _Doc, sc, resource: str) -> None:
    for key in ("seccompProfile", "appArmorProfile"):
        type_node = _path(sc, (key, "type"))
        if (_literal(type_node) or "").lower() == "unconfined":
            doc.record("security_profile_disabled", type_node, f"{key}.type: Unconfined", resource=resource,
                       severity="medium", confidence=0.9,
                       escalation="no syscall/LSM filter: kernel exploits and escape techniques aren't blocked")


def _check_image(doc: _Doc, container, where: str) -> None:
    node = _get(container, "image")
    image = _literal(node)
    if not image or "@" in image or "$" in image:
        return
    last = image.rsplit("/", 1)[-1]
    tag = _IMAGE_TAG_RE.search(last)
    if tag is None or tag.group(1) == "latest":
        doc.record("unpinned_container_image", node, f"image: {image}", resource=where, severity="low",
                   confidence=0.8, escalation="whoever can push the tag changes what runs, without a deploy")


def _check_role(doc: _Doc, kind: str, resource: str) -> None:
    cluster = kind == "ClusterRole"
    for rule in _items(_get(doc.root, "rules")):
        verbs = {(_literal(v) or "").lower() for v in _items(_get(rule, "verbs"))}
        resources = {(_literal(r) or "").lower() for r in _items(_get(rule, "resources"))}
        summary = f"verbs {sorted(verbs - {''})} on {sorted(resources - {''})}"
        groups_node = _get(rule, "apiGroups")
        groups = None if groups_node is None else {_literal(g) or "" for g in _items(groups_node)}
        if rbac_wildcard(groups, verbs, resources):
            doc.record("rbac_wildcard", rule, summary, resource=resource, severity="high" if cluster else "medium",
                       confidence=0.9,
                       escalation="every verb or resource, including Secrets and RBAC objects → full control"
                       + (" of the cluster" if cluster else " of the namespace"))
            continue
        escalating = sorted(verbs & {"escalate", "bind", "impersonate"})
        exec_like = sorted(resources & {"pods/exec", "pods/attach"}) if "create" in verbs else []
        if escalating or exec_like:
            escalation = (
                "impersonate → act as any user or group, including system:masters" if "impersonate" in escalating
                else "escalate/bind → grant itself any role, up to cluster-admin" if escalating
                else "pods/exec → a shell in any pod in scope → that pod's service-account token and secrets"
            )
            doc.record("rbac_escalation", rule, summary, resource=resource, severity="high", confidence=0.85,
                       escalation=escalation)
        elif "secrets" in resources and verbs & {"get", "list", "watch"} and not _items(_get(rule, "resourceNames")):
            # `resourceNames` narrows it to named Secrets the workload owns.
            doc.record("rbac_secret_access", rule, summary, resource=resource,
                       severity="medium" if cluster else "low", confidence=0.8,
                       escalation="read Secrets → service-account tokens and credentials of every workload in scope")


def _check_binding(doc: _Doc, resource: str) -> None:
    role_node = _path(doc.root, ("roleRef", "name"))
    role = _literal(role_node) or ""
    subjects = []
    broad = []
    for subject in _items(_get(doc.root, "subjects")):
        skind = _display(_scalar(_get(subject, "kind")))
        sname = _display(_scalar(_get(subject, "name")))
        subjects.append(f"{skind} {sname}")
        if sname in _BROAD_GROUPS:
            broad.append(subject)
    # The default system:basic-user / system:discovery bindings to
    # system:authenticated are fine; an admin-like role is not.
    if role == "cluster-admin" or (broad and role in ADMIN_LIKE_ROLES):
        who = ", ".join(subjects[:4]) or "no subjects"
        node = role_node if role == "cluster-admin" else broad[0]
        doc.record("cluster_admin_binding", node, f"roleRef {role or '?'} → {who}", resource=resource,
                   severity="high", confidence=0.9,
                   escalation=("cluster-admin → full control of every namespace and node" if role == "cluster-admin"
                               else "every authenticated (or anonymous) caller gets this role"))


def _check_service(doc: _Doc, name: str, resource: str) -> None:
    type_node = _path(doc.root, ("spec", "type"))
    svc_type = _literal(type_node)
    if svc_type not in {"LoadBalancer", "NodePort"}:
        return
    annotations = _path(doc.root, ("metadata", "annotations"))
    if isinstance(annotations, yaml.MappingNode):
        pairs = {_scalar(k) or "": _scalar(v) or "" for k, v in annotations.value}
        if internal_lb(pairs):
            return  # internal load balancer
    hint = f"k8s_service_{svc_type.lower()}:{name}"
    line = _line(type_node, doc.offset)
    if first_seen(doc.result, ("entrypoint", hint, doc.file)):
        doc.result.entrypoint_hints.append(
            EntrypointHint(hint=hint, file=doc.file, line=line, evidence_text=f"type: {svc_type}", confidence=0.8)
        )
    if _path(doc.root, ("spec", "loadBalancerSourceRanges")) is not None:
        return
    doc.record("exposed_service", type_node, f"type: {svc_type} with no loadBalancerSourceRanges", resource=resource,
               severity="low", confidence=0.7 if svc_type == "LoadBalancer" else 0.6,
               escalation="reachable from outside the cluster by any source address")


def _check_ingress(doc: _Doc, name: str) -> None:
    for rule in _items(_path(doc.root, ("spec", "rules"))):
        host = _literal(_get(rule, "host")) or "*"
        hint = f"k8s_ingress:{host}"
        if first_seen(doc.result, ("entrypoint", hint, doc.file)):
            doc.result.entrypoint_hints.append(
                EntrypointHint(hint=hint, file=doc.file, line=_line(rule, doc.offset),
                               evidence_text=f"Ingress {name} host {host}", confidence=0.8)
            )
        for item in _items(_path(rule, ("http", "paths"))):
            path_node = _get(item, "path")
            path = _literal(path_node) if path_node is not None else "/"
            if not path or not path.startswith("/"):
                continue
            key = (path, "ANY", doc.file)
            if first_seen(doc.result, ("route", *key)):
                doc.result.routes.append(Route(path=path, method="ANY", file=doc.file,
                                               line=_line(path_node or item, doc.offset)))


def _check_secret(doc: _Doc, name: str) -> None:
    for field in ("data", "stringData"):
        data = _get(doc.root, field)
        if not isinstance(data, yaml.MappingNode):
            continue
        for k, v in data.value:
            key = _literal(k)
            value = _literal(v)
            if not key or not value or not value.strip() or value.strip().startswith(("<", "${", "$(")):
                continue
            if not _SECRET_DATA_KEY_RE.search(key) or (
                _SECRET_DATA_NON_SECRET_RE.search(key) and not _SECRET_DATA_STRONG_RE.search(key)
            ):
                continue
            line = _line(k, doc.offset)
            secret_name = f"k8s_secret:{name}/{key}"
            if not first_seen(doc.result, ("secret", secret_name, doc.file, line)):
                continue
            doc.result.secret_hints.append(
                SecretHint(name=secret_name, file=doc.file, line=line, kind="hardcoded",
                           evidence_text=f"{field}.{key}: <redacted>")
            )


# ---------- Helm values ----------

_VALUES_FLAGS = {
    "privileged": ("privileged_container", "high", "privileged container → root on the node, if the chart applies it"),
    "allowPrivilegeEscalation": ("privilege_escalation_allowed", "medium", "setuid binaries can raise the process to root"),
    "hostPID": ("host_namespace_shared", "high", "host PID namespace, if the chart applies it"),
    "hostNetwork": ("host_namespace_shared", "medium", "host network namespace, if the chart applies it"),
    "hostIPC": ("host_namespace_shared", "medium", "host IPC namespace, if the chart applies it"),
}


def analyze_values(content: str, relative: str, result: ScanResult) -> None:
    """Insecure defaults in a chart's ``values.yaml``. Reported with low
    confidence: a default only matters if a template uses it."""
    if too_nested(content):
        return
    try:
        root = yaml.compose(content, Loader=_Loader)
    except Exception:
        return
    stack: list[tuple[object, str]] = [(root, "")]
    seen: set[int] = set()
    budget = _WALK_BUDGET
    while stack and budget > 0:
        node, path = stack.pop()
        budget -= 1
        if id(node) in seen or not isinstance(node, (yaml.MappingNode, yaml.SequenceNode)):
            continue
        seen.add(id(node))
        if isinstance(node, yaml.SequenceNode):
            stack += [(item, f"{path}[]") for item in node.value]
            continue
        for k, v in node.value:
            key = _scalar(k) or ""
            dotted = f"{path}.{key}" if path else key
            if key in _VALUES_FLAGS and _is_true(v):
                kind, severity, escalation = _VALUES_FLAGS[key]
                _values_record(result, relative, kind, v, f"{dotted}: true", severity, escalation)
            elif key == "runAsUser" and _int(v) == 0:
                _values_record(result, relative, "container_runs_as_root", v, f"{dotted}: 0", "medium",
                               "the container runs as root, if the chart applies it")
            elif key == "add" and path.endswith("capabilities"):
                for cap in _items(v):
                    value = _literal(cap) or ""
                    severity = capability_severity(value)
                    if severity:
                        _values_record(result, relative, "dangerous_capability", cap, f"{dotted}: {value}", severity,
                                       f"CAP_{value.upper().removeprefix('CAP_')}, if the chart applies it")
            else:
                stack.append((v, dotted))


def _values_record(result: ScanResult, relative: str, kind: str, node, evidence: str, severity: str,
                   escalation: str) -> None:
    append_misconfig(
        result, kind, relative, node.start_mark.line + 1, evidence, severity=severity, confidence=0.5,
        resource=f"values {evidence.split(':', 1)[0]}", platform="helm", escalation=escalation,
        context="Helm values default",
    )


def is_chart_values(path: Path) -> bool:
    return path.name in {"values.yaml", "values.yml"} and (path.parent / "Chart.yaml").is_file()


def is_chart_template(path: Path, repo: Path) -> bool:
    """Under a chart's ``templates/`` directory (``templates/tests/`` too)."""
    for ancestor in path.parents:
        if ancestor == repo or len(ancestor.parts) <= len(repo.parts):
            return False
        if ancestor.name == "templates" and (ancestor.parent / "Chart.yaml").is_file():
            return True
    return False
