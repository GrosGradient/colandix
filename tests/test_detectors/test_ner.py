# test_ner.py — Tests unitaires pour le détecteur d'entités nommées

import pytest

from colandix.detectors.base import DetectorConfig
from colandix.detectors.ner import FR_CORE_MODEL, NERDetector
from colandix.result import Action, DetectionEvent

spacy = pytest.importorskip("spacy", reason="SpaCy non installé — tests NER ignorés")


@pytest.fixture
def detector_default():
    """Détecteur NER avec paramètres par défaut (combo_threshold=2)."""
    config = DetectorConfig(name="test_ner", action=Action.BLOCK)
    d = NERDetector(config)
    if not d.is_fr_core_model_active:
        pytest.skip(
            "Modèle SpaCy fr_core_news_md requis "
            "(uv run python -m spacy download fr_core_news_md)"
        )
    return d


@pytest.fixture
def detector_combo_1():
    """Détecteur NER qui déclenche sur une seule entité."""
    config = DetectorConfig(
        name="test_ner_solo",
        action=Action.WARN,
        extra={"combo_threshold": 1, "entities": ["PER", "ORG", "LOC"]},
    )
    d = NERDetector(config)
    if not d.is_fr_core_model_active:
        pytest.skip(
            "Modèle SpaCy fr_core_news_md requis "
            "(uv run python -m spacy download fr_core_news_md)"
        )
    return d


def test_combo_per_lieu_detecte(detector_default):
    event = detector_default.analyze(
        "Le patient Jean-Pierre Martin né le 15 mars 1985 à Lyon est admis"
    )
    assert event.matched is True


def test_entite_isolee_ne_declenche_pas(detector_default):
    event = detector_default.analyze("Le patient Martin est admis en urgence")
    assert event.matched is False


def test_organisation_seule_ne_declenche_pas(detector_default):
    event = detector_default.analyze("L'AP-HP a publié un communiqué de presse")
    assert event.matched is False


def test_combo_threshold_1_declenche(detector_combo_1):
    event = detector_combo_1.analyze("Marie Dupont a consulté ce matin")
    assert event.matched is True


def test_keep_per_span_filtre_blacklist(detector_combo_1):
    assert detector_combo_1._keep_per_span("Veuillez") is False
    assert detector_combo_1._keep_per_span("Marie Dupont") is True


def test_keep_per_span_sigle_court_majuscules(detector_combo_1):
    assert detector_combo_1._keep_per_span("FAC") is False
    assert detector_combo_1._keep_per_span("Jean") is True


def test_span_blacklist_extra_yaml_merge():
    config = DetectorConfig(
        name="t",
        action=Action.BLOCK,
        extra={"span_blacklist": ["interne", "confidentiel"]},
    )
    d = NERDetector(config)
    assert "interne" in d._per_span_blacklist
    assert "veuillez" in d._per_span_blacklist


def test_veuillez_seul_ne_declenche_pas_per_combo1():
    if not NERDetector.is_fr_core_model_loaded():
        NERDetector(DetectorConfig(name="warmup", action=Action.BLOCK))
    det = NERDetector(
        DetectorConfig(
            name="per_only",
            action=Action.BLOCK,
            extra={"combo_threshold": 1, "entities": ["PER"]},
        )
    )
    if not det.is_fr_core_model_active:
        pytest.skip("NER inactif")
    ev = det.analyze("Veuillez répondre par courriel.")
    assert ev.matched is False


def test_ner_yaml_block_devient_human_review_sauf_opt_in():
    if not NERDetector.is_fr_core_model_loaded():
        NERDetector(DetectorConfig(name="warmup", action=Action.BLOCK))
    det = NERDetector(
        DetectorConfig(
            name="per_only",
            action=Action.BLOCK,
            extra={"combo_threshold": 1, "entities": ["PER"]},
        )
    )
    if not det.is_fr_core_model_active:
        pytest.skip("NER inactif")
    ev = det.analyze("Patient : Jean Dupont")
    assert ev.matched is True
    assert ev.action == Action.HUMAN_REVIEW


def test_ner_allow_block_conserve_block():
    if not NERDetector.is_fr_core_model_loaded():
        NERDetector(DetectorConfig(name="warmup2", action=Action.BLOCK))
    det = NERDetector(
        DetectorConfig(
            name="per_block",
            action=Action.BLOCK,
            extra={
                "combo_threshold": 1,
                "entities": ["PER"],
                "ner_allow_block": True,
            },
        )
    )
    if not det.is_fr_core_model_active:
        pytest.skip("NER inactif")
    ev = det.analyze("Patient : Jean Dupont")
    assert ev.matched is True
    assert ev.action == Action.BLOCK


def test_get_entities_retourne_dict(detector_default):
    result = detector_default.get_entities(
        "Marie Dupont travaille chez Renault à Paris"
    )
    assert isinstance(result, dict) is True
    assert len(result) > 0
    assert any(key in ["PER", "ORG", "LOC"] for key in result.keys())


def test_extra_model_name_from_yaml():
    det = NERDetector(
        DetectorConfig(
            name="en_ner",
            action=Action.BLOCK,
            extra={"model": "en_core_web_md", "combo_threshold": 1},
        )
    )
    assert det._model_name == "en_core_web_md"


def test_singleton_nlp_partage():
    detector1 = NERDetector(DetectorConfig(name="d1", action=Action.BLOCK))
    if not detector1.is_fr_core_model_active:
        pytest.skip(
            "Modèle SpaCy fr_core_news_md requis "
            "(uv run python -m spacy download fr_core_news_md)"
        )
    detector2 = NERDetector(DetectorConfig(name="d2", action=Action.WARN))
    assert NERDetector._nlp_instances.get(FR_CORE_MODEL) is not None
    assert detector1._nlp is detector2._nlp


def test_texte_long_tronque():
    config = DetectorConfig(
        name="test_court", action=Action.BLOCK, extra={"max_text_length": 10}
    )
    detector_court = NERDetector(config)
    long_text = "Jean Martin à Paris " * 100  # 2000 chars
    event = detector_court.analyze(long_text)
    assert isinstance(event, DetectionEvent) is True


def test_evidence_format(detector_default):
    event = detector_default.analyze("Jean-Pierre Martin est né à Lyon le 3 juin 1982")
    if event.matched:
        assert event.evidence is not None
        assert len(event.evidence) <= 50
        assert ":" in event.evidence


def test_score_plein_quand_match(detector_default):
    event = detector_default.analyze("Jean-Pierre Martin est né à Lyon le 3 juin 1982")
    if event.matched:
        assert event.score == 1.0


def test_modele_fr_core_absent_degrade_sans_exception(capfd, monkeypatch):
    """
    Sans fr_core_news_md : warning stdout et analyse no-op
    (réhydrate le cache après).
    """
    NERDetector.reset_model_cache_for_tests()

    def _fail_load(_name: str):
        raise OSError("[E050] Can't find model 'fr_core_news_md'")

    monkeypatch.setattr("colandix.detectors.ner.spacy.load", _fail_load)

    config = DetectorConfig(name="ner_sans_modele", action=Action.BLOCK)
    detector = NERDetector(config)
    captured = capfd.readouterr()
    combined = captured.out + captured.err
    assert "WARNING" in combined
    assert "fr_core_news_md" in combined
    assert detector.is_fr_core_model_active is False
    assert NERDetector.is_fr_core_model_loaded() is False
    assert detector.analyze("Jean Dupont habite à Lyon").matched is False

    monkeypatch.undo()
    NERDetector.reset_model_cache_for_tests()
    NERDetector(DetectorConfig(name="recharge_modele", action=Action.BLOCK))
