# test_result.py — Tests unitaires pour les types de base de colandix

import pytest

from colandix.result import (
    Action,
    DetectionEvent,
    PipelineConfig,
    ScanDirection,
    ScanResult,
)


def test_detection_event_not_matched_forces_pass_action():
    event = DetectionEvent(
        detector_name="test",
        detector_type="test",
        matched=False,
        score=0.0,
        action=Action.BLOCK
    )
    assert event.action == Action.PASS


def test_detection_event_not_matched_forces_zero_score():
    event = DetectionEvent(
        detector_name="test",
        detector_type="test",
        matched=False,
        score=0.9,
        action=Action.PASS
    )
    assert event.score == 0.0


def test_detection_event_evidence_truncated_at_50_chars():
    event = DetectionEvent(
        detector_name="test",
        detector_type="test",
        matched=True,
        score=1.0,
        action=Action.PASS,
        evidence="A" * 100
    )
    assert len(event.evidence) == 50
    assert event.evidence == "A" * 50


def test_detection_event_evidence_not_truncated_if_short():
    event = DetectionEvent(
        detector_name="test",
        detector_type="test",
        matched=True,
        score=1.0,
        action=Action.PASS,
        evidence="NIR: 123"
    )
    assert event.evidence == "NIR: 123"


def test_detection_event_score_out_of_range_raises_value_error():
    with pytest.raises(ValueError):
        DetectionEvent(
            detector_name="test",
            detector_type="test",
            matched=True,
            score=1.5,
            action=Action.PASS
        )


def test_detection_event_score_negative_raises_value_error():
    with pytest.raises(ValueError):
        DetectionEvent(
            detector_name="test",
            detector_type="test",
            matched=True,
            score=-0.1,
            action=Action.PASS
        )


def test_scan_result_is_clean_true_when_pass_and_not_blocked():
    res = ScanResult(
        direction=ScanDirection.INPUT,
        original_text="test",
        sanitized_text="test",
        blocked=False,
        action=Action.PASS,
        global_score=0.0
    )
    assert res.is_clean is True


def test_scan_result_is_clean_false_when_blocked():
    res = ScanResult(
        direction=ScanDirection.INPUT,
        original_text="test",
        sanitized_text="test",
        blocked=True,
        action=Action.PASS,
        global_score=0.0
    )
    assert res.is_clean is False


def test_scan_result_is_clean_false_when_warn():
    res = ScanResult(
        direction=ScanDirection.INPUT,
        original_text="test",
        sanitized_text="test",
        blocked=False,
        action=Action.WARN,
        global_score=0.0
    )
    assert res.is_clean is False


def test_scan_result_matched_events_filters_correctly():
    events = [
        DetectionEvent("1", "t", True, 1.0, Action.PASS),
        DetectionEvent("2", "t", True, 1.0, Action.PASS),
        DetectionEvent("3", "t", False, 1.0, Action.BLOCK)
    ]
    res = ScanResult(
        direction=ScanDirection.INPUT,
        original_text="test",
        sanitized_text="test",
        blocked=False,
        action=Action.PASS,
        global_score=0.0,
        events=events
    )
    assert len(res.matched_events) == 2


def test_scan_result_matched_events_empty_when_no_match():
    events = [
        DetectionEvent("1", "t", False, 1.0, Action.BLOCK),
        DetectionEvent("2", "t", False, 1.0, Action.BLOCK)
    ]
    res = ScanResult(
        direction=ScanDirection.INPUT,
        original_text="test",
        sanitized_text="test",
        blocked=False,
        action=Action.PASS,
        global_score=0.0,
        events=events
    )
    assert len(res.matched_events) == 0


def test_scan_result_anssi_refs_covered_returns_set():
    events = [
        DetectionEvent("1", "t", True, 1.0, Action.PASS, anssi_ref="R25"),
        DetectionEvent("2", "t", True, 1.0, Action.PASS, anssi_ref="R26")
    ]
    res = ScanResult(
        direction=ScanDirection.INPUT,
        original_text="test",
        sanitized_text="test",
        blocked=False,
        action=Action.PASS,
        global_score=0.0,
        events=events
    )
    assert res.anssi_refs_covered == {"R25", "R26"}


def test_scan_result_anssi_refs_covered_ignores_unmatched():
    events = [
        DetectionEvent("1", "t", True, 1.0, Action.PASS, anssi_ref="R25"),
        DetectionEvent("2", "t", False, 1.0, Action.BLOCK, anssi_ref="R26")
    ]
    res = ScanResult(
        direction=ScanDirection.INPUT,
        original_text="test",
        sanitized_text="test",
        blocked=False,
        action=Action.PASS,
        global_score=0.0,
        events=events
    )
    assert res.anssi_refs_covered == {"R25"}


def test_scan_result_anssi_refs_covered_ignores_none():
    events = [
        DetectionEvent("1", "t", True, 1.0, Action.PASS, anssi_ref=None)
    ]
    res = ScanResult(
        direction=ScanDirection.INPUT,
        original_text="test",
        sanitized_text="test",
        blocked=False,
        action=Action.PASS,
        global_score=0.0,
        events=events
    )
    assert res.anssi_refs_covered == set()


def test_scan_result_has_blocked_action_true():
    events = [
        DetectionEvent("1", "t", True, 1.0, Action.BLOCK)
    ]
    res = ScanResult(
        direction=ScanDirection.INPUT,
        original_text="test",
        sanitized_text="test",
        blocked=False,
        action=Action.PASS,
        global_score=0.0,
        events=events
    )
    assert res.has_blocked_action is True


def test_scan_result_has_blocked_action_false():
    events = [
        DetectionEvent("1", "t", True, 1.0, Action.WARN)
    ]
    res = ScanResult(
        direction=ScanDirection.INPUT,
        original_text="test",
        sanitized_text="test",
        blocked=False,
        action=Action.PASS,
        global_score=0.0,
        events=events
    )
    assert res.has_blocked_action is False


def test_scan_result_default_events_is_empty_list():
    res1 = ScanResult(
        direction=ScanDirection.INPUT,
        original_text="t1",
        sanitized_text="t1",
        blocked=False,
        action=Action.PASS,
        global_score=0.0
    )
    res2 = ScanResult(
        direction=ScanDirection.INPUT,
        original_text="t2",
        sanitized_text="t2",
        blocked=False,
        action=Action.PASS,
        global_score=0.0
    )
    res1.events.append(DetectionEvent("1", "t", True, 1.0, Action.PASS))
    assert len(res2.events) == 0


def test_pipeline_config_defaults():
    config = PipelineConfig()
    assert config.profile_name == "generique"
    assert config.log_inputs is True
    assert config.log_outputs is True
    assert config.raise_on_block is False
    assert config.max_text_length == 10_000
