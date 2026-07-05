# test_topic.py — Tests unitaires pour le détecteur de périmètre (topics)

import pytest

from colandix.detectors.base import DetectorConfig
from colandix.detectors.topic import TopicDetector
from colandix.result import Action


@pytest.fixture
def detector_medical():
    config = DetectorConfig(
        name="test_topic_medical",
        action=Action.WARN,
        extra={
            "allowed": ["médical", "patient", "diagnostic", "traitement", "symptôme"]
        },
    )
    return TopicDetector(config)


@pytest.fixture
def detector_sans_restriction():
    config = DetectorConfig(name="test_topic_libre", action=Action.WARN)
    return TopicDetector(config)


def test_topic_dans_perimetre_passe(detector_medical):
    event = detector_medical.analyze("Quel est le diagnostic pour ces symptômes ?")
    assert event.matched is False


def test_topic_hors_perimetre_detecte(detector_medical):
    event = detector_medical.analyze("Comment optimiser mon portefeuille boursier ?")
    assert event.matched is True
    assert event.score == 0.5


def test_topic_bloque_prioritaire():
    config = DetectorConfig(
        name="test_blocked",
        action=Action.BLOCK,
        extra={"allowed": ["médical", "patient"], "blocked": ["juridique", "procès"]},
    )
    detector_blocked = TopicDetector(config)
    event = detector_blocked.analyze("Aide-moi pour mon procès médical")
    assert event.matched is True
    assert event.score == 0.9
    assert "procès" in event.evidence


def test_blocked_prioritaire_sur_allowed():
    config = DetectorConfig(
        name="test_prio",
        action=Action.BLOCK,
        extra={"allowed": ["médical"], "blocked": ["procès"]},
    )
    detector_prio = TopicDetector(config)
    event = detector_prio.analyze("Mon procès médical commence demain")
    assert event.matched is True
    assert event.score == 0.9


def test_sans_restriction_tout_passe(detector_sans_restriction):
    event = detector_sans_restriction.analyze(
        "N'importe quel texte complètement hors sujet"
    )
    assert event.matched is False


def test_get_matched_topics_retourne_dict(detector_medical):
    result = detector_medical.get_matched_topics(
        "Le patient a un diagnostic positif mais un procès en cours"
    )
    assert isinstance(result, dict)
    assert "allowed_found" in result
    assert "blocked_found" in result


def test_get_matched_topics_allowed_found():
    config = DetectorConfig(
        name="test_topics",
        action=Action.WARN,
        extra={"allowed": ["médical", "patient"]},
    )
    detector_t = TopicDetector(config)
    result = detector_t.get_matched_topics("Le patient est en bonne santé")
    assert "patient" in result["allowed_found"]


def test_case_insensitive_par_defaut():
    config = DetectorConfig(
        name="test_case", action=Action.WARN, extra={"blocked": ["INTERDIT"]}
    )
    detector_case = TopicDetector(config)
    event = detector_case.analyze("Ce mot interdit est présent")
    assert event.matched is True


def test_case_sensitive_option():
    config = DetectorConfig(
        name="test_case_s",
        action=Action.WARN,
        extra={"blocked": ["INTERDIT"], "case_sensitive": True},
    )
    detector_cs = TopicDetector(config)
    event = detector_cs.analyze("Ce mot interdit en minuscules")
    assert event.matched is False


def test_allowed_accent_fold_trouve_mot_cle():
    """Le texte sans accent matche les mots-clés YAML accentués."""
    config = DetectorConfig(
        name="fold",
        action=Action.WARN,
        extra={"allowed": ["symptôme"]},
    )
    detector = TopicDetector(config)
    event = detector.analyze("Presence de symptomes legers")
    assert event.matched is False


def test_profil_sante_diabete_protocole_dans_perimetre():
    from colandix.profiles.loader import load_profile

    detectors = load_profile("sante")
    topic = next(d for d in detectors if d.config.name == "perimetre_medical")
    event = topic.analyze(
        "Bonjour, quel est le protocole pour un diabète de type 1 ?"
    )
    assert event.matched is False
