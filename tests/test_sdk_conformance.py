"""SDK 1.0 conformance (mlaify/AttackMap#254): attackmap.sdk.testing.assert_conforms."""

from pathlib import Path

from attackmap.sdk.testing import assert_conforms

from attackmap_analyzer_iac import IacAnalyzer


def _has_signals(result) -> None:
    assert any(isinstance(v, list) and v for v in result.__dict__.values()), "the analyzer emitted nothing"


FIXTURE = Path(__file__).parent / "fixtures" / "k8s_repo"


def test_conforms_to_the_sdk() -> None:
    _has_signals(assert_conforms(IacAnalyzer(), FIXTURE))
