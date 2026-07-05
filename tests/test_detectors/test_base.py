# test_base.py — Tests pour la classe de base des détecteurs

import pytest

from colandix.detectors.base import (
    BaseDetector,
    DetectorConfig,
    DetectorError,
    safe_analyze,
)
from colandix.result import Action, DetectionEvent


class AlwaysMatchDetector(BaseDetector):
    """Détecteur de test qui matche toujours avec score=1.0"""
    @safe_analyze
    def analyze(self, text: str) -> DetectionEvent:
        return self._make_event(matched=True, score=1.0, evidence="test_evidence")


class AlwaysFailDetector(BaseDetector):
    """Détecteur de test qui lève toujours une exception"""
    @safe_analyze
    def analyze(self, text: str) -> DetectionEvent:
        raise ValueError("Erreur simulée pour les tests")


class NeverMatchDetector(BaseDetector):
    """Détecteur de test qui ne matche jamais"""
    @safe_analyze
    def analyze(self, text: str) -> DetectionEvent:
        return self._make_event(matched=False, score=0.0)


@pytest.fixture
def block_config():
    return DetectorConfig(name="test_detector", action=Action.BLOCK)


@pytest.fixture
def warn_config():
    return DetectorConfig(name="warn_detector", action=Action.WARN)


def test_base_detector_cannot_be_instantiated_directly(block_config):
    with pytest.raises(TypeError):
        BaseDetector(config=block_config)


def test_always_match_returns_correct_event(block_config):
    detector = AlwaysMatchDetector(block_config)
    event = detector.analyze("texte")
    assert event.matched is True
    assert event.score == 1.0
    assert event.action == Action.BLOCK
    assert event.detector_name == "test_detector"
    assert event.evidence == "test_evidence"


def test_never_match_forces_pass_action(block_config):
    detector = NeverMatchDetector(block_config)
    event = detector.analyze("texte")
    assert event.matched is False
    assert event.action == Action.PASS
    assert event.score == 0.0


def test_make_event_long_evidence_truncated(block_config):
    detector = AlwaysMatchDetector(block_config)
    event = detector._make_event(matched=True, score=0.5, evidence="A" * 100)
    assert len(event.evidence) == 50


def test_make_event_no_evidence_returns_none(block_config):
    detector = AlwaysMatchDetector(block_config)
    event = detector._make_event(matched=True, score=0.5)
    assert event.evidence is None


def test_safe_analyze_catches_exception(block_config):
    detector = AlwaysFailDetector(block_config)
    event = detector.analyze("texte")
    assert event.matched is False
    assert event.score == 0.0
    assert event.evidence.startswith("ERROR:")
    assert len(event.evidence) <= 50
    assert event.action == Action.PASS


def test_safe_analyze_preserves_normal_flow(block_config):
    detector = AlwaysMatchDetector(block_config)
    event = detector.analyze("texte")
    assert event.matched is True


def test_detector_config_defaults():
    config = DetectorConfig(name="test", action=Action.WARN)
    assert config.weight == 1.0
    assert config.enabled is True
    assert config.anssi_ref == "R25"
    assert config.extra == {}


def test_detector_config_weight_too_high_raises():
    with pytest.raises(ValueError):
        DetectorConfig(name="test", action=Action.WARN, weight=1.5)


def test_detector_config_weight_zero_valid():
    config = DetectorConfig(name="test", action=Action.WARN, weight=0.0)
    assert config.weight == 0.0


def test_detector_config_extra_independence():
    config1 = DetectorConfig(name="a", action=Action.WARN)
    config2 = DetectorConfig(name="b", action=Action.WARN)
    config1.extra["key"] = "value"
    assert config2.extra == {}


def test_detector_repr_format(block_config):
    detector = AlwaysMatchDetector(block_config)
    assert repr(detector) == "AlwaysMatchDetector(name='test_detector', action='block', enabled=True)"  # noqa: E501


def test_detector_error_message():
    err = DetectorError("mon_detecteur", ValueError("raison"))
    assert "mon_detecteur" in str(err)
    assert "raison" in str(err)


def test_detector_error_stores_original():
    original = ValueError("raison")
    err = DetectorError("test", original)
    assert err.original_error is original
