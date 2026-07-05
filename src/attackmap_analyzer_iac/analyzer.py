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

from .contracts import (
    AnalyzerMetadata,
    AuthHint,
    ExternalCall,
    Route,
    ScanResult,
    SecretHint,
    ServiceHint,
)


_SKIP_DIRS = frozenset(
    {"node_modules", ".git", ".venv", "venv", "dist", "build", ".turbo", "out", "target"}
)


# ---- Dockerfile patterns -----------------------------------------------------

DOCKERFILE_NAMES = {"Dockerfile", "dockerfile", "Containerfile"}

_DF_FROM = re.compile(r"^\s*FROM\s+(?P<image>[\S]+)(?:\s+AS\s+(?P<alias>\S+))?", re.IGNORECASE | re.MULTILINE)
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

COMPOSE_NAMES = {"docker-compose.yaml", "docker-compose.yml", "compose.yaml", "compose.yml"}

# service block: `services:\n  <name>:` — we grab each `<name>:` at
# the second indent level. Cheap; doesn't need a real YAML parser.
_COMPOSE_SERVICE_NAME = re.compile(
    r"^(?P<indent>[ \t]{2,4})(?P<name>[a-z0-9_-]+):\s*$",
    re.MULTILINE,
)
_COMPOSE_SERVICES_HEADER = re.compile(r"^services:\s*$", re.MULTILINE)
_COMPOSE_IMAGE = re.compile(r"^\s{2,}image:\s*['\"]?(?P<image>[^\s'\"#]+)", re.MULTILINE)
_COMPOSE_PORT_BINDING = re.compile(
    r"['\"]?(?P<host>0\.0\.0\.0|[0-9]+):(?P<container>[0-9]+)(?:/(?:tcp|udp))?['\"]?",
    re.IGNORECASE,
)
_COMPOSE_HOST_MOUNT = re.compile(r"['\"]?(?P<host_path>/[^:\s]*):[^:\s]+['\"]?", re.MULTILINE)
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
        for candidate in repo.rglob("*"):
            if not candidate.is_file():
                continue
            if any(part in _SKIP_DIRS for part in candidate.parts):
                continue
            if _is_iac_file(candidate):
                return True
        return False

    def analyze(self, repo_path: str | Path) -> ScanResult:
        repo = Path(repo_path).resolve()
        result = ScanResult(root=str(repo))
        if not repo.exists() or not repo.is_dir():
            return result

        for path in repo.rglob("*"):
            if not path.is_file():
                continue
            if any(part in _SKIP_DIRS for part in path.parts):
                continue
            if not _is_iac_file(path):
                continue
            content = _read_text(path)
            if content is None:
                continue
            relative = str(path.relative_to(repo)).replace("\\", "/")
            result.files_scanned += 1
            if path.name in DOCKERFILE_NAMES:
                _analyze_dockerfile(content, relative, result)
            elif path.name in COMPOSE_NAMES:
                _analyze_compose(content, relative, result)
            elif _GHA_PATH.search(relative):
                _analyze_gha_workflow(content, relative, result)
            elif path.name in ENV_TEMPLATE_NAMES:
                _analyze_env_template(content, relative, result)
            elif path.suffix in SHELL_SUFFIXES:
                _analyze_shell_installer(content, relative, result)
        return result


def _is_iac_file(path: Path) -> bool:
    if path.name in DOCKERFILE_NAMES:
        return True
    if path.name in COMPOSE_NAMES:
        return True
    if _GHA_PATH.search(str(path).replace("\\", "/")):
        return True
    if path.name in ENV_TEMPLATE_NAMES:
        return True
    if path.suffix in SHELL_SUFFIXES:
        return True
    return False


# ---- File-specific extractors ------------------------------------------------


def _analyze_dockerfile(content: str, relative: str, result: ScanResult) -> None:
    # USER directive absence is a signal: containers default to root.
    if not _DF_USER.search(content):
        _append_auth(result, "dockerfile_no_user_directive", relative)
    else:
        # If USER is present but set to root explicitly, flag it.
        for match in _DF_USER.finditer(content):
            user = match.group("user").strip("'\"")
            if user.lower() in {"root", "0"}:
                _append_auth(result, "dockerfile_user_root", relative, line=_line_of(content, match.start()))

    # EXPOSE — each exposed port is a route-like entry point.
    for match in _DF_EXPOSE.finditer(content):
        ports = re.findall(r"\d+", match.group("ports"))
        for port in ports:
            _append_route(result, f"container:{port}", "EXPOSE", relative, line=_line_of(content, match.start()))

    # HEALTHCHECK absence signals thin operational monitoring.
    if not _DF_HEALTHCHECK.search(content):
        _append_auth(result, "dockerfile_no_healthcheck", relative)

    # RUN curl|bash — fetching + executing remote content in the image build.
    for match in _DF_RUN_CURL_PIPE.finditer(content):
        _append_external(result, "dockerfile:curl-pipe-shell", relative, line=_line_of(content, match.start()))
        _append_auth(result, "dockerfile_run_curl_pipe", relative)

    # ADD https://... — remote fetch during build, no signature check by default.
    for match in _DF_ADD_REMOTE.finditer(content):
        _append_auth(result, "dockerfile_add_remote", relative, line=_line_of(content, match.start()))

    # FROM image tag vs SHA pinning.
    for match in _DF_FROM.finditer(content):
        image = match.group("image")
        if "@sha256:" not in image:
            _append_auth(
                result,
                "dockerfile_base_image_unpinned",
                relative,
                line=_line_of(content, match.start()),
                evidence=image,
            )


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
            _append_service(result, f"service_name:{name}", relative)

    # Port bindings.
    for line_match in re.finditer(r"^\s*-\s*(?P<binding>[^#\n]+)", content, re.MULTILINE):
        binding = line_match.group("binding").strip()
        port_match = _COMPOSE_PORT_BINDING.search(binding)
        if port_match:
            host, container = port_match.group("host"), port_match.group("container")
            if host == "0.0.0.0":
                _append_auth(
                    result,
                    "compose_port_binding_all_interfaces",
                    relative,
                    line=_line_of(content, line_match.start()),
                    evidence=binding,
                )
            _append_route(
                result,
                f"container:{container}",
                "EXPOSE",
                relative,
                line=_line_of(content, line_match.start()),
            )

    if _COMPOSE_PRIVILEGED.search(content):
        _append_auth(result, "compose_privileged_container", relative)
    if _COMPOSE_NETWORK_HOST.search(content):
        _append_auth(result, "compose_network_mode_host", relative)

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
            _append_auth(
                result,
                "compose_env_file_reference",
                relative,
                line=_line_of(content, match.start()),
                evidence=env_file,
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
        _append_auth(
            result,
            f"compose_host_mount:{mount.split(':')[0]}",
            relative,
            line=_line_of(content, line_match.start()),
            evidence=mount,
        )


def _analyze_gha_workflow(content: str, relative: str, result: ScanResult) -> None:
    has_pr_target = bool(_GHA_PR_TARGET.search(content))
    has_checkout = bool(_GHA_CHECKOUT.search(content))
    if has_pr_target and has_checkout:
        _append_auth(result, "gha_pull_request_target_with_checkout", relative)

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
            _append_auth(
                result,
                f"gha_third_party_action_tag_pinned:{repo}",
                relative,
                line=_line_of(content, match.start()),
                evidence=f"{repo}@{ref}",
            )

    if not _GHA_PERMISSIONS.search(content):
        _append_auth(result, "gha_no_top_level_permissions", relative)

    # Every ${{ secrets.X }} reference is an outbound trust — feeds
    # into the secret inventory context.
    for match in _GHA_SECRETS_REF.finditer(content):
        secret_name = re.search(r"secrets\.([A-Z0-9_]+)", match.group()).group(1)
        _append_secret(
            result,
            name=secret_name,
            file=relative,
            line=_line_of(content, match.start()),
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
            line=_line_of(content, match.start()),
            kind="env_template",
        )


def _analyze_shell_installer(content: str, relative: str, result: ScanResult) -> None:
    for match in _SH_CURL_PIPE.finditer(content):
        _append_external(
            result,
            "shell:curl-pipe-shell",
            relative,
            line=_line_of(content, match.start()),
        )
        _append_auth(result, "shell_curl_pipe_installer", relative)

    if _SH_SUDO.search(content):
        _append_auth(result, "shell_sudo_used", relative)

    for match in _SH_CHMOD_777.finditer(content):
        _append_auth(
            result,
            "shell_permissive_chmod",
            relative,
            line=_line_of(content, match.start()),
            evidence=match.group(),
        )


# ---- Small append helpers with (file, key) dedup ----------------------------


def _line_of(content: str, offset: int) -> int:
    return content.count("\n", 0, offset) + 1


def _append_route(
    result: ScanResult, path: str, method: str, file: str, line: int | None = None
) -> None:
    key = (path, method, file)
    if any((r.path, r.method, r.file) == key for r in result.routes):
        return
    result.routes.append(Route(path=path, method=method, file=file, line=line))


def _append_external(
    result: ScanResult, target: str, file: str, line: int | None = None
) -> None:
    key = (target, file)
    if any((c.target, c.file) == key for c in result.external_calls):
        return
    result.external_calls.append(ExternalCall(target=target, file=file, line=line))


def _append_auth(
    result: ScanResult,
    hint: str,
    file: str,
    line: int | None = None,
    evidence: str | None = None,
) -> None:
    key = (hint, file)
    if any((h.hint, h.file) == key for h in result.auth_hints):
        return
    result.auth_hints.append(AuthHint(hint=hint, file=file, line=line, evidence_text=evidence))


def _append_service(result: ScanResult, hint: str, file: str) -> None:
    key = (hint, file)
    if any((h.hint, h.file) == key for h in result.service_hints):
        return
    result.service_hints.append(ServiceHint(hint=hint, file=file))


def _append_secret(
    result: ScanResult, name: str, file: str, line: int | None = None, kind: str = "env_reference"
) -> None:
    key = (name, file, line or 0)
    if any((s.name, s.file, s.line or 0) == key for s in result.secret_hints):
        return
    result.secret_hints.append(SecretHint(name=name, file=file, line=line, kind=kind))


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return None
