from __future__ import annotations

from attackmap.sdk.contracts import AnalyzerMetadata, AnalyzerProtocol
from attackmap.sdk.models import (
    AuthHint,
    DatabaseHint,
    EntrypointHint,
    ExternalCall,
    FrameworkHint,
    Route,
    ScanResult,
    SecretHint,
    ServiceHint,
)

try:  # AttackMap#334; older cores have no CloudMisconfig (see records.py).
    from attackmap.sdk.models import CloudMisconfig
except ImportError:  # pragma: no cover - depends on the installed core
    CloudMisconfig = None  # type: ignore[assignment,misc]

AttackMapAnalyzerProtocol = AnalyzerProtocol

__all__ = [
    "AnalyzerMetadata",
    "AttackMapAnalyzerProtocol",
    "Route",
    "ExternalCall",
    "DatabaseHint",
    "AuthHint",
    "CloudMisconfig",
    "EntrypointHint",
    "FrameworkHint",
    "ServiceHint",
    "SecretHint",
    "ScanResult",
]
