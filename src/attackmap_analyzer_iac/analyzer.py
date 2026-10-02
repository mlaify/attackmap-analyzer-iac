"""Infrastructure-as-Code analyzer for AttackMap.

Covers files that drive the runtime posture but aren't application
source: Dockerfile, docker-compose, GitHub Actions workflows, `.env`
templates, and shell installers. All extraction is regex-based —
intentionally shallow and dependency-free (no yaml/toml parser needed).

See the Bluesky FINDINGS §2 for the motivating gap: `bluesky-social/pds`
was 95% invisible to AttackMap because none of these file types had
analyzer coverage.
"""

from __future__ import annotations

import re
from pathlib import Path

from attackmap.sdk import DEFAULT_SKIP_DIRS, iter_repo_files, line_of, line_snippet, read_source, rel

from .contracts import (
    AnalyzerMetadata,
    AuthHint,
    EntrypointHint,
    ExternalCall,
    FrameworkHint,
    Route,
    ScanResult,
    SecretHint,
    ServiceHint,
)

# Where each posture signal goes (AttackMap#258). The SDK has no weakness /
# posture signal type, so:
# - privilege and authorization posture (who the workload or CI job runs as,
#   what it may do) stays an AuthHint;
# - network exposure is an EntrypointHint;
# - build / supply-chain / deployment-config posture is a FrameworkHint.
# Hint strings are unchanged.


# Every directory this plugin used to skip is in the shared list; matched
# against directory names *inside* the repo only.
_SKIP_DIRS = DEFAULT_SKIP_DIRS


# ---- Dockerfile patterns -----------------------------------------------------

# Exact canonical names; `_is_dockerfile` also accepts `Dockerfile.prod`,
# `Dockerfile-dev`, `api.Dockerfile`, `*.dockerfile` and `Containerfile.*`.
DOCKERFILE_NAMES = {"Dockerfile", "dockerfile", "Containerfile"}
# `Dockerfile.dockerignore` is BuildKit's per-Dockerfile ignore file; docs
# named after a Dockerfile aren't Dockerfiles either.
_DOCKERFILE_NON_SOURCE_SUFFIXES = (".dockerignore", ".md", ".rst", ".txt")

# `FROM [--platform=...] <image> [AS <alias>]`
_DF_FROM = re.compile(
    r"^\s*FROM\s+(?:--\S+\s+)*(?P<image>[^\s-][\S]*)(?:\s+AS\s+(?P<alias>\S+))?",
    re.IGNORECASE | re.MULTILINE,
)
_DF_USER = re.compile(r"^\s*USER\s+(?P<user>\S+)", re.IGNORECASE | re.MULTILINE)
_DF_EXPOSE = re.compile(r"^\s*EXPOSE\s+(?P<ports>[0-9\s/tcpud]+)", re.IGNORECASE | re.MULTILINE)
_DF_HEALTHCHECK = re.compile(r"^\s*HEALTHCHECK\s+", re.IGNORECASE | re.MULTILINE)
_DF_RUN_CURL_PIPE = re.compile(
    r"^\s*RUN\s+.*?(?:curl|wget)\s+[^|;\n]*\s*[|;]\s*(?:bash|sh|zsh|python)",
    re.IGNORECASE | re.MULTILINE,
)
_DF_COPY_CHOWN = re.compile(r"^\s*COPY\s+--chown=", re.IGNORECASE | re.MULTILINE)
_DF_ADD_REMOTE = re.compile(r"^\s*ADD\s+https?://", re.IGNORECASE | re.MULTILINE)


# ---- docker-compose patterns -------------------------------------------------

# Canonical names; `_is_compose_file` also accepts overrides and variants
# (`docker-compose.override.yml`, `docker-compose.prod.yml`, `compose.dev.yaml`).
COMPOSE_NAMES = {"docker-compose.yaml", "docker-compose.yml", "compose.yaml", "compose.yml"}
_COMPOSE_NAME = re.compile(r"^(?:docker-)?compose(?:[.-][^/]+)?\.ya?ml$", re.IGNORECASE)

# service block: `services:\n  <name>:` — we grab each `<name>:` at
# the second indent level. Cheap; doesn't need a real YAML parser.
_COMPOSE_SERVICE_NAME = re.compile(
    r"^(?P<indent>[ \t]{2,4})(?P<name>[a-z0-9_-]+):\s*$",
    re.MULTILINE,
)
_COMPOSE_SERVICES_HEADER = re.compile(r"^services:\s*$", re.MULTILINE)
_COMPOSE_IMAGE = re.compile(r"^\s{2,}image:\s*['\"]?(?P<image>[^\s'\"#]+)", re.MULTILINE)
_COMPOSE_HOST_MOUNT = re.compile(r"['\"]?(?P<host_path>/[^:\s]*):[^:\s]+['\"]?", re.MULTILINE)
_COMPOSE_DOCKER_SOCKET = re.compile(r"(?:^|[\s'\"=:])(?P<sock>/(?:var/)?run/docker\.sock)\b", re.MULTILINE)
_COMPOSE_PID_HOST = re.compile(r"^\s+pid:\s*['\"]?host['\"]?\s*(?:#.*)?$", re.IGNORECASE | re.MULTILINE)
_COMPOSE_SECCOMP_UNCONFINED = re.compile(r"seccomp[:=]\s*['\"]?unconfined\b", re.IGNORECASE)
_COMPOSE_PRIVILEGED = re.compile(r"^\s+privileged:\s*true", re.IGNORECASE | re.MULTILINE)
_COMPOSE_NETWORK_HOST = re.compile(r"^\s+network_mode:\s*['\"]?host['\"]?", re.IGNORECASE | re.MULTILINE)
# Matches both `env_file: pds.env` (inline) and the list form:
#   env_file:
#     - pds.env
# The `following` group captures either the inline value or the entire
# list block; we normalize downstream to pull the filename(s) out.
_COMPOSE_ENV_FILE = re.compile(
    # Use [ \t]* (not \s*) so we don't accidentally jump over the newline
    # and treat the first list-item as the inline value.
    r"^\s+env_file:[ \t]*(?P<inline>[^\s#\n][^\n]*)?\n(?P<listed>(?:\s+-\s+[^\n]+\n)*)",
    re.IGNORECASE | re.MULTILINE,
)


# Secret-shaped variable names (Dockerfile ENV/ARG, compose `environment:`).
# `*_FILE` variants hold a path to a mounted secret, and `PUBLIC` keys aren't
# secret.
_SECRET_NAME = re.compile(
    r"SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|PRIVATE_?KEY|ACCESS_?KEY|API_?KEY|(?:^|_)KEY(?:_|$)",
    re.IGNORECASE,
)
_NON_SECRET_VALUES = {"", "true", "false", "yes", "no", "on", "off", "0", "1", "null", "~"}


# ---- GitHub Actions patterns -------------------------------------------------

_GHA_PATH = re.compile(r"\.github/workflows/[^/]+\.ya?ml$", re.IGNORECASE)
_GHA_PR_TARGET = re.compile(r"^\s*pull_request_target\s*:", re.IGNORECASE | re.MULTILINE)
_GHA_CHECKOUT = re.compile(r"uses:\s+actions/checkout@", re.IGNORECASE)
# `uses: owner/repo@ref` where ref is not a 40-char SHA
_GHA_USES = re.compile(
    r"uses:\s+(?P<repo>[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+)@(?P<ref>\S+)",
    re.IGNORECASE,
)
_SHA40 = re.compile(r"^[a-f0-9]{40}$", re.IGNORECASE)
_GHA_SECRETS_REF = re.compile(r"\$\{\{\s*secrets\.[A-Z0-9_]+\s*\}\}", re.IGNORECASE)
_GHA_PERMISSIONS = re.compile(r"^\s*permissions\s*:", re.IGNORECASE | re.MULTILINE)


# ---- .env template names -----------------------------------------------------

ENV_TEMPLATE_NAMES = {".env.example", ".env.sample", ".env.template", "sample.env"}
_ENV_KEY = re.compile(r"^\s*(?P<key>[A-Z][A-Z0-9_]*)\s*=", re.MULTILINE)


# ---- Shell installer patterns ------------------------------------------------

SHELL_SUFFIXES = {".sh", ".bash", ".zsh"}
_SH_CURL_PIPE = re.compile(
    r"(?:curl|wget)\s+[^|;\n]*\s*[|;]\s*(?:bash|sh|zsh|python)",
    re.IGNORECASE,
)
_SH_SUDO = re.compile(r"^\s*sudo\s+", re.MULTILINE)
_SH_CHMOD_777 = re.compile(r"\bchmod\s+(?:0?7[0-7]{2}|a\+w)\b")


class IacAnalyzer:
    metadata = AnalyzerMetadata(
        name="iac",
        display_name="IaC / Deployment-Surface Analyzer",
        version="0.1.0",
        description="Analyzer for infrastructure-as-code and deployment files: Dockerfile, docker-compose, GitHub Actions, .env templates, shell installers.",
        scope="Deployment / operations repositories where the runtime posture is defined outside application source. Closes the coverage gap Bluesky FINDINGS §2 documented for bluesky-social/pds.",
        targets=["docker", "docker-compose", "github-actions", "env-template", "shell-installer"],
        languages=[],
        priority=40,
        experimental=False,
        enabled_by_default=True,
    )

    @property
    def name(self) -> str:
        return self.metadata.name

    def detect(self, repo_path: str | Path) -> bool:
        repo = Path(repo_path).resolve()
        if not repo.exists() or not repo.is_dir():
            return False
        for candidate in _iter_candidates(repo):
            if _is_iac_file(candidate, rel(candidate, repo)):
                return True
        return False

    def analyze(self, repo_path: str | Path) -> ScanResult:
        repo = Path(repo_path).resolve()
        result = ScanResult(root=str(repo))
        if not repo.exists() or not repo.is_dir():
            return result

        for path in _iter_candidates(repo):
            relative = rel(path, repo)
            if not _is_iac_file(path, relative):
                continue
            content = read_source(path)
            if content is None:
                continue
            result.files_scanned += 1
            if _is_dockerfile(path.name):
                _analyze_dockerfile(content, relative, result)
            elif _is_compose_file(path.name):
                _analyze_compose(content, relative, result)
            elif _GHA_PATH.search(relative):
                _analyze_gha_workflow(content, relative, result)
            elif path.name in ENV_TEMPLATE_NAMES:
                _analyze_env_template(content, relative, result)
            elif path.suffix in SHELL_SUFFIXES:
                _analyze_shell_installer(content, relative, result)
        return result


def _iter_candidates(repo: Path):
    """Files that might be IaC files; ``_is_iac_file`` makes the final call.

    Unfiltered: Dockerfile variants (`Dockerfile.prod`) have arbitrary
    suffixes, so they can't be selected by name or suffix up front.
    """
    return iter_repo_files(repo, skip_dirs=_SKIP_DIRS)


def _is_dockerfile(name: str) -> bool:
    lower = name.lower()
    if lower.endswith(_DOCKERFILE_NON_SOURCE_SUFFIXES):
        return False
    return (
        lower.startswith(("dockerfile", "containerfile"))
        or lower.endswith((".dockerfile", ".containerfile"))
    )


def _is_compose_file(name: str) -> bool:
    return name in COMPOSE_NAMES or bool(_COMPOSE_NAME.match(name))


def _is_iac_file(path: Path, relative: str) -> bool:
    if _is_dockerfile(path.name):
        return True
    if _is_compose_file(path.name):
        return True
    if _GHA_PATH.search(relative):
        return True
    if path.name in ENV_TEMPLATE_NAMES:
        return True
    if path.suffix in SHELL_SUFFIXES:
        return True
    return False


# ---- File-specific extractors ------------------------------------------------


def _dockerfile_stages(content: str, from_matches: list[re.Match]) -> list[dict]:
    """Split a Dockerfile at each FROM into stages.

    Each stage records its base image, alias, the offset of its FROM, its
    body text (up to the next FROM) and that body's offset in ``content``.
    """
    stages = []
    for index, match in enumerate(from_matches):
        body_end = from_matches[index + 1].start() if index + 1 < len(from_matches) else len(content)
        stages.append(
            {
                "image": match.group("image"),
                "alias": (match.group("alias") or "").lower() or None,
                "offset": _at(match),
                "body": content[match.end():body_end],
                "body_offset": match.end(),
            }
        )
    return stages


def _effective_stage_directive(stages: list[dict], index: int, pattern: re.Pattern) -> tuple[re.Match, int] | None:
    """Last ``pattern`` match that applies to stage ``index``.

    A stage built `FROM <earlier-stage-alias>` inherits that stage's USER and
    HEALTHCHECK, so walk back through aliases. Returns (match, body_offset).
    """
    seen: set[int] = set()
    while index not in seen:
        seen.add(index)
        stage = stages[index]
        matches = list(pattern.finditer(stage["body"]))
        if matches:
            return matches[-1], stage["body_offset"]
        image = stage["image"].lower()
        parent = next(
            (i for i in range(index - 1, -1, -1) if stages[i]["alias"] == image),
            None,
        )
        if parent is None:
            return None
        index = parent
    return None


def _analyze_dockerfile(content: str, relative: str, result: ScanResult) -> None:
    from_matches = list(_DF_FROM.finditer(content))
    stages = _dockerfile_stages(content, from_matches)
    # Absence signals apply to the final build stage: anchor them at its FROM.
    final_stage = stages[-1]["offset"] if stages else None

    # USER: only the final stage's effective user matters. A `USER nobody`
    # in a builder stage says nothing about the image that ships.
    if stages:
        effective_user = _effective_stage_directive(stages, len(stages) - 1, _DF_USER)
    else:
        user_matches = list(_DF_USER.finditer(content))
        effective_user = (user_matches[-1], 0) if user_matches else None
    final_image = stages[-1]["image"].lower() if stages else ""
    if effective_user is None:
        # A `:nonroot` / `:nonroot-…` distroless-style base sets its own user.
        if not re.search(r":nonroot\b", final_image):
            _append_hint(
                result.auth_hints, AuthHint, "dockerfile_no_user_directive", relative, content, final_stage,
                evidence=(
                    "no USER directive in the final stage: the container runs as root"
                    if len(stages) > 1
                    else "no USER directive: the container runs as root"
                ),
                confidence=0.6,
            )
    else:
        match, base = effective_user
        user = match.group("user").strip("'\"").split(":", 1)[0]
        if user.lower() in {"root", "0"}:
            _append_hint(
                result.auth_hints, AuthHint, "dockerfile_user_root", relative, content, base + _at(match),
                confidence=0.9,
            )

    # EXPOSE — each exposed port is a route-like entry point.
    for match in _DF_EXPOSE.finditer(content):
        ports = re.findall(r"\d+", match.group("ports"))
        for port in ports:
            _append_route(result, f"container:{port}", "EXPOSE", relative, line=line_of(content, _at(match)))

    # HEALTHCHECK absence signals thin operational monitoring (final stage).
    has_healthcheck = (
        _effective_stage_directive(stages, len(stages) - 1, _DF_HEALTHCHECK) is not None
        if stages
        else bool(_DF_HEALTHCHECK.search(content))
    )
    if not has_healthcheck:
        _append_hint(
            result.framework_hints, FrameworkHint, "dockerfile_no_healthcheck", relative, content, final_stage,
            evidence="no HEALTHCHECK directive", confidence=0.6,
        )

    # RUN curl|bash — fetching + executing remote content in the image build.
    for match in _DF_RUN_CURL_PIPE.finditer(content):
        _append_external(result, "dockerfile:curl-pipe-shell", relative, content, _at(match))
        _append_hint(
            result.framework_hints, FrameworkHint, "dockerfile_run_curl_pipe", relative, content, _at(match),
            confidence=0.9,
        )

    # ADD https://... — remote fetch during build, no signature check by default.
    for match in _DF_ADD_REMOTE.finditer(content):
        _append_hint(
            result.framework_hints, FrameworkHint, "dockerfile_add_remote", relative, content, _at(match),
            confidence=0.9,
        )

    # FROM image tag vs SHA pinning. `scratch` is not an image and
    # `FROM <earlier-stage-alias>` refers to a stage in this file. One hint
    # per image: the image is part of the hint so they don't dedup together.
    aliases: set[str] = set()
    for stage in stages:
        image = stage["image"]
        if image.lower() != "scratch" and image.lower() not in aliases and "@sha256:" not in image:
            _append_hint(
                result.framework_hints, FrameworkHint, f"dockerfile_base_image_unpinned:{image}", relative, content,
                stage["offset"], evidence=image, confidence=0.8,
            )
        if stage["alias"]:
            aliases.add(stage["alias"])

    # ENV / ARG with a secret-shaped name and a literal value is baked into
    # the image config / build history.
    for name, value, offset in _dockerfile_env_assignments(content):
        if _is_literal_secret(name, value):
            _append_secret(result, name=name, file=relative, content=content, offset=offset, kind="hardcoded")


_DF_ENV_ARG = re.compile(r"^[ \t]*(?P<kw>ENV|ARG)[ \t]+(?P<rest>(?:[^\n]*\\\n)*[^\n]*)", re.IGNORECASE | re.MULTILINE)
_DF_KV = re.compile(r"""(?P<key>[A-Za-z_][A-Za-z0-9_]*)=(?P<value>"(?:[^"\\]|\\.)*"|'[^']*'|\S*)""")


def _dockerfile_env_assignments(content: str):
    """Yield (name, value, offset) for each ENV/ARG assignment.

    Handles `ENV A=1 B=2`, the legacy `ENV NAME value` form, `ARG NAME=default`
    and backslash line continuations. `ARG NAME` without a default yields
    nothing.
    """
    for match in _DF_ENV_ARG.finditer(content):
        rest = match.group("rest")
        rest_offset = match.start("rest")
        parts = rest.strip().split(None, 1)
        if not parts:
            continue
        if "=" not in parts[0]:
            # Legacy `ENV NAME value` (ARG always uses `=` for a default).
            if match.group("kw").upper() == "ENV" and len(parts) == 2:
                yield parts[0], parts[1].strip(), rest_offset + rest.find(parts[0])
            continue
        for kv in _DF_KV.finditer(rest):
            yield kv.group("key"), kv.group("value"), rest_offset + kv.start()


def _is_literal_secret(name: str, value: str) -> bool:
    if not _SECRET_NAME.search(name):
        return False
    upper = name.upper()
    if upper.endswith("_FILE") or "PUBLIC" in upper:
        return False
    value = value.strip().strip("'\"").strip()
    if value.lower() in _NON_SECRET_VALUES:
        return False
    # `${VAR}` / `$VAR` is a reference resolved at build or run time.
    return not value.startswith("$")


def _analyze_compose(content: str, relative: str, result: ScanResult) -> None:
    # Find the services block; only match keys under that block as service names.
    services_start = _COMPOSE_SERVICES_HEADER.search(content)
    if services_start:
        services_block = content[services_start.end():]
        top_indent = None
        for match in _COMPOSE_SERVICE_NAME.finditer(services_block):
            indent = len(match.group("indent"))
            if top_indent is None:
                top_indent = indent
            if indent != top_indent:
                continue  # nested (env vars, labels, etc.) — not a service
            name = match.group("name")
            _append_hint(
                result.service_hints, ServiceHint, f"service_name:{name}", relative, content,
                services_start.end() + match.start(), confidence=0.9,
            )

    # Port bindings, read from `ports:` blocks only. Short syntax without a
    # host IP (`"5432:5432"`, or a bare `"3000"`) publishes on every
    # interface, exactly like an explicit `0.0.0.0`. One hint per binding:
    # the binding is part of the hint, since core merges hints by (hint, file).
    for binding, offset in _compose_port_bindings(content):
        host_ip, container = _parse_port_binding(binding)
        if container is None:
            continue
        if host_ip in {"", "0.0.0.0", "::"}:
            _append_hint(
                result.entrypoint_hints, EntrypointHint, f"compose_port_binding_all_interfaces:{binding}", relative,
                content, offset, evidence=binding, confidence=0.9,
            )
        _append_route(result, f"container:{container}", "EXPOSE", relative, line=line_of(content, offset))

    # Literal secrets in `environment:` (map or list form).
    for name, value, offset in _compose_environment(content):
        if _is_literal_secret(name, value):
            _append_secret(result, name=name, file=relative, content=content, offset=offset, kind="hardcoded")

    # Host-root-equivalent settings: Docker socket mounts, SYS_ADMIN/ALL
    # capabilities, the host PID namespace, seccomp disabled.
    sock = _COMPOSE_DOCKER_SOCKET.search(content)
    if sock:
        _append_hint(
            result.auth_hints, AuthHint, "compose_docker_socket_mount", relative, content, sock.start("sock"),
            confidence=0.95,
        )
    for cap, offset in _compose_cap_add(content):
        if cap.upper().removeprefix("CAP_") in {"SYS_ADMIN", "ALL"}:
            _append_hint(
                result.auth_hints, AuthHint, "compose_cap_add_sys_admin", relative, content, offset,
                confidence=0.9,
            )
    pid_host = _COMPOSE_PID_HOST.search(content)
    if pid_host:
        _append_hint(
            result.auth_hints, AuthHint, "compose_pid_host", relative, content, _at(pid_host), confidence=0.9,
        )
    seccomp = _COMPOSE_SECCOMP_UNCONFINED.search(content)
    if seccomp:
        _append_hint(
            result.auth_hints, AuthHint, "compose_seccomp_unconfined", relative, content, seccomp.start(),
            confidence=0.9,
        )

    privileged = _COMPOSE_PRIVILEGED.search(content)
    if privileged:
        _append_hint(
            result.auth_hints, AuthHint, "compose_privileged_container", relative, content, _at(privileged),
            confidence=0.9,
        )
    network_host = _COMPOSE_NETWORK_HOST.search(content)
    if network_host:
        _append_hint(
            result.entrypoint_hints, EntrypointHint, "compose_network_mode_host", relative, content,
            _at(network_host), confidence=0.9,
        )

    for match in _COMPOSE_ENV_FILE.finditer(content):
        inline = (match.group("inline") or "").strip()
        listed = match.group("listed") or ""
        # Pull filenames from either the inline value or the list block.
        env_files = []
        if inline and not inline.startswith("-"):
            env_files.append(inline.strip("'\""))
        for m in re.finditer(r"-\s+(?P<f>[^\s\n]+)", listed):
            env_files.append(m.group("f").strip("'\""))
        for env_file in env_files or ["(unnamed)"]:
            _append_hint(
                result.framework_hints, FrameworkHint, "compose_env_file_reference", relative, content,
                _at(match), evidence=env_file, confidence=0.8,
            )

    # Host-mounted volumes — anything starting with `/` is a bind mount from
    # the host filesystem into the container. Highly variable in scope; we
    # emit a per-mount hint so each shows up in the report — dedup at the
    # (hint, file) level would collapse them to one otherwise.
    for line_match in re.finditer(r"^\s+-\s*(?P<mount>['\"]?/[^:\n]+:/[^\s]+)", content, re.MULTILINE):
        mount = line_match.group("mount").strip("'\"")
        # Encode the source path into the hint so different mounts don't
        # dedup against each other. Downstream findings can key off the
        # `compose_host_mount:` prefix.
        _append_hint(
            result.framework_hints, FrameworkHint, f"compose_host_mount:{mount.split(':')[0]}", relative, content,
            _at(line_match), evidence=mount, confidence=0.9,
        )


def _yaml_block(content: str, key: str):
    """Yield (key_match, block_text, block_offset) for each `key:` mapping.

    The block is every following line indented deeper than the key (blank
    and comment lines included). Inline values (`key: [..]`) give an empty
    block; the caller reads them from ``key_match``.
    """
    pattern = re.compile(rf"^(?P<indent>[ \t]*){re.escape(key)}:[ \t]*(?P<inline>[^\n#]*)", re.MULTILINE)
    for match in pattern.finditer(content):
        indent = len(match.group("indent"))
        pos = match.end()
        newline = content.find("\n", pos)
        start = len(content) if newline == -1 else newline + 1
        end = start
        while end < len(content):
            line_end = content.find("\n", end)
            line_end = len(content) if line_end == -1 else line_end
            line = content[end:line_end]
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and len(line) - len(line.lstrip()) <= indent:
                break
            end = line_end + 1
        yield match, content[start:min(end, len(content))], start


def _compose_port_bindings(content: str):
    """Yield (binding, offset) for each published port in `ports:` blocks."""
    for key, block, base in _yaml_block(content, "ports"):
        inline = key.group("inline").strip()
        if inline.startswith("["):
            for item in re.finditer(r"[^,\[\]\s][^,\[\]]*", inline):
                yield item.group().strip().strip("'\""), key.start("inline") + item.start()
            continue
        # Long syntax: `- target: 80` / `published: 8080` / `host_ip: ...`.
        for item in re.finditer(r"^[ \t]*-[ \t]*(?P<entry>[^\n]*(?:\n(?![ \t]*-)[^\n]*)*)", block, re.MULTILINE):
            entry = item.group("entry")
            offset = base + item.start("entry")
            if re.match(r"(?:target|published|host_ip|protocol|mode)\s*:", entry.strip()):
                fields = dict(re.findall(r"(target|published|host_ip)\s*:\s*['\"]?([^'\"\s#]+)", entry))
                if "published" not in fields:
                    continue  # not published on the host
                host_ip = fields.get("host_ip", "")
                prefix = f"{host_ip}:" if host_ip else ""
                yield f"{prefix}{fields['published']}:{fields.get('target', '')}", offset
                continue
            value = entry.split("#", 1)[0].strip().strip("'\"")
            if value:
                yield value, offset


def _parse_port_binding(binding: str) -> tuple[str, str | None]:
    """Split a short-syntax binding into (host_ip, container_port).

    `"5432:5432"` / `"3000"` → ("", ...): no IP means every interface.
    `"127.0.0.1:5432:5432"` → ("127.0.0.1", "5432"); `"[::1]:80:80"` → ("::1", "80").
    """
    value = binding.strip().strip("'\"").split("/", 1)[0]
    host_ip = ""
    if value.startswith("["):
        close = value.find("]")
        host_ip, value = value[1:close], value[close + 2:]
        parts = value.split(":")
    else:
        parts = value.split(":")
        if len(parts) >= 3:
            host_ip, parts = ":".join(parts[:-2]), parts[-2:]
    container = parts[-1] if parts and re.fullmatch(r"[0-9]+(?:-[0-9]+)?", parts[-1] or "") else None
    if host_ip.lower() == "localhost" or host_ip.startswith("127.") or host_ip == "::1":
        host_ip = "loopback"
    return host_ip, container


def _compose_environment(content: str):
    """Yield (name, value, offset) from `environment:` blocks (map or list)."""
    for _key, block, base in _yaml_block(content, "environment"):
        for item in re.finditer(
            r"^[ \t]*(?:-[ \t]*['\"]?(?P<lname>[A-Za-z_][A-Za-z0-9_]*)=(?P<lvalue>[^\n]*?)['\"]?[ \t]*$"
            r"|(?P<mname>[A-Za-z_][A-Za-z0-9_]*):[ \t]*(?P<mvalue>[^\n#]*))",
            block,
            re.MULTILINE,
        ):
            name = item.group("lname") or item.group("mname")
            value = item.group("lvalue") if item.group("lname") else item.group("mvalue")
            yield name, (value or "").strip(), base + item.start("lname" if item.group("lname") else "mname")


def _compose_cap_add(content: str):
    """Yield (capability, offset) from `cap_add:` (inline or list form)."""
    for key, block, base in _yaml_block(content, "cap_add"):
        inline = key.group("inline").strip()
        if inline.startswith("["):
            for cap in re.finditer(r"[A-Za-z_]+", inline):
                yield cap.group(), key.start("inline") + cap.start()
            continue
        for item in re.finditer(r"^[ \t]*-[ \t]*['\"]?(?P<cap>[A-Za-z_]+)", block, re.MULTILINE):
            yield item.group("cap"), base + item.start("cap")


def _analyze_gha_workflow(content: str, relative: str, result: ScanResult) -> None:
    pr_target = _GHA_PR_TARGET.search(content)
    has_checkout = bool(_GHA_CHECKOUT.search(content))
    if pr_target and has_checkout:
        _append_hint(
            result.auth_hints, AuthHint, "gha_pull_request_target_with_checkout", relative, content,
            _at(pr_target), confidence=0.8,
        )

    for match in _GHA_USES.finditer(content):
        repo = match.group("repo")
        ref = match.group("ref").strip("'\"")
        # actions/* and github/* are first-party; skip the pin check for them
        # since they're widely trusted. Third parties get flagged when tag-pinned.
        owner = repo.split("/", 1)[0].lower()
        if owner in {"actions", "github"}:
            continue
        if not _SHA40.match(ref):
            # Encode the repo into the hint so multiple unpinned actions
            # in one workflow file don't dedup against each other.
            _append_hint(
                result.framework_hints, FrameworkHint, f"gha_third_party_action_tag_pinned:{repo}", relative,
                content, _at(match), evidence=f"{repo}@{ref}", confidence=0.9,
            )

    if not _GHA_PERMISSIONS.search(content):
        # Absent block: anchor at the top of the workflow.
        _append_hint(
            result.auth_hints, AuthHint, "gha_no_top_level_permissions", relative, content, None,
            evidence="no top-level permissions: block (GITHUB_TOKEN gets the repo default scope)",
            confidence=0.6,
        )

    # Every ${{ secrets.X }} reference is an outbound trust — feeds
    # into the secret inventory context.
    for match in _GHA_SECRETS_REF.finditer(content):
        secret_name = re.search(r"secrets\.([A-Z0-9_]+)", match.group()).group(1)
        _append_secret(
            result,
            name=secret_name,
            file=relative,
            content=content,
            offset=_at(match),
            kind="env_reference",
        )


def _analyze_env_template(content: str, relative: str, result: ScanResult) -> None:
    """`.env.example` and friends define the shape of the runtime secret
    inventory. Every KEY=... entry becomes a `SecretHint` with `kind`
    set to `env_template` so downstream consumers know the value is a
    template placeholder, not a real secret."""
    for match in _ENV_KEY.finditer(content):
        key = match.group("key")
        _append_secret(
            result,
            name=key,
            file=relative,
            content=content,
            # `^\s*` can swallow blank lines before the key; point at the key.
            offset=match.start("key"),
            kind="env_template",
        )


def _analyze_shell_installer(content: str, relative: str, result: ScanResult) -> None:
    for match in _SH_CURL_PIPE.finditer(content):
        _append_external(result, "shell:curl-pipe-shell", relative, content, _at(match))
        _append_hint(
            result.framework_hints, FrameworkHint, "shell_curl_pipe_installer", relative, content, _at(match),
            confidence=0.9,
        )

    sudo = _SH_SUDO.search(content)
    if sudo:
        _append_hint(
            result.auth_hints, AuthHint, "shell_sudo_used", relative, content, _at(sudo),
            confidence=0.8,
        )

    for match in _SH_CHMOD_777.finditer(content):
        _append_hint(
            result.auth_hints, AuthHint, "shell_permissive_chmod", relative, content, _at(match),
            evidence=match.group(), confidence=0.9,
        )


# ---- Small append helpers with (file, key) dedup ----------------------------


def _at(match: re.Match) -> int:
    """Offset of the first non-blank character of ``match``.

    Most patterns here start with ``^\\s*`` in MULTILINE mode, which also
    swallows preceding blank lines, so ``match.start()`` can sit one or more
    lines above the directive it matched.
    """
    text = match.group()
    return match.start() + (len(text) - len(text.lstrip()))


def _append_route(
    result: ScanResult, path: str, method: str, file: str, line: int | None = None
) -> None:
    key = (path, method, file)
    if any((r.path, r.method, r.file) == key for r in result.routes):
        return
    result.routes.append(Route(path=path, method=method, file=file, line=line))


def _append_external(result: ScanResult, target: str, file: str, content: str, offset: int) -> None:
    key = (target, file)
    if any((c.target, c.file) == key for c in result.external_calls):
        return
    line = line_of(content, offset)
    result.external_calls.append(
        ExternalCall(target=target, file=file, line=line, evidence_text=line_snippet(content, line) or target)
    )


def _append_hint(
    bucket: list,
    model: type,
    hint: str,
    file: str,
    content: str,
    offset: int | None,
    *,
    evidence: str | None = None,
    confidence: float | None = None,
) -> None:
    """Append an Auth/Service/Entrypoint/Framework hint once per (hint, file).

    ``offset`` locates the hint (``None`` anchors it at line 1, for signals
    about something *missing* from the file). ``evidence`` overrides the
    quoted source line when a more specific value (an image, a mount, an
    ``owner/repo@ref``) identifies the signal better.
    """
    if any((h.hint, h.file) == (hint, file) for h in bucket):
        return
    line = line_of(content, offset) if offset is not None else 1
    evidence_text = evidence or line_snippet(content, line) or hint
    extra = {"confidence": confidence} if confidence is not None else {}
    bucket.append(model(hint=hint, file=file, line=line, evidence_text=evidence_text, **extra))


def _append_secret(
    result: ScanResult, name: str, file: str, content: str, offset: int, kind: str = "env_reference"
) -> None:
    line = line_of(content, offset)
    key = (name, file, line)
    if any((s.name, s.file, s.line or 0) == key for s in result.secret_hints):
        return
    result.secret_hints.append(
        SecretHint(name=name, file=file, line=line, evidence_text=line_snippet(content, line) or name, kind=kind)
    )
