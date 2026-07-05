import pytest

from colandix.compliance import generate_report, print_report
from colandix.detectors.base import DetectorConfig
from colandix.detectors.injection import InjectionDetector
from colandix.detectors.regex import RegexDetector
from colandix.detectors.topic import TopicDetector
from colandix.result import Action


@pytest.fixture
def detectors_sante():
    """Détecteurs représentatifs du profil santé."""
    return [
        RegexDetector(
            DetectorConfig(name="pii_sante", action=Action.BLOCK, anssi_ref="R25")
        ),
        InjectionDetector(
            DetectorConfig(name="injection", action=Action.BLOCK, anssi_ref="R25")
        ),
        TopicDetector(
            DetectorConfig(
                name="perimetre",
                action=Action.WARN,
                anssi_ref="R26",
                extra={"allowed": ["médical"]},
            )
        ),
    ]


def test_rapport_genere_toutes_les_cles(detectors_sante):
    report = generate_report(detectors_sante, "sante")
    assert "titre" in report
    assert "souverain" in report
    assert "exigences" in report
    assert "conformite_globale" in report
    assert "recommandations" in report
    assert "generated_at" in report


def test_souverain_toujours_true(detectors_sante):
    report = generate_report(detectors_sante, "sante")
    assert report["souverain"] is True
    assert report["appels_externes"] == 0


def test_r25_couverte_avec_regex_detector(detectors_sante):
    report = generate_report(detectors_sante, "sante")
    assert report["exigences"]["R25"]["status"] == "CONFORME"
    assert "pii_sante" in report["exigences"]["R25"]["detecteurs"]


def test_r26_couverte_avec_topic_detector(detectors_sante):
    report = generate_report(detectors_sante, "sante")
    assert report["exigences"]["R26"]["status"] == "CONFORME"


def test_r29_couverte_by_design(detectors_sante):
    report = generate_report(detectors_sante, "sante")
    assert report["exigences"]["R29"]["status"] == "CONFORME"
    assert "ColandixLogger" in report["exigences"]["R29"]["detecteurs"]


def test_r34_couverte_by_design(detectors_sante):
    report = generate_report(detectors_sante, "sante")
    assert report["exigences"]["R34"]["status"] == "CONFORME"


def test_sans_detecteurs_non_conforme():
    report = generate_report([], "vide")
    assert report["conformite_globale"] == "NON CONFORME"
    assert report["exigences"]["R25"]["status"] == "NON COUVERT"


def test_r25_manquante_recommandation_presente():
    # Seulement TopicDetector (R26) — R25 manquante
    detectors_sans_r25 = [
        TopicDetector(
            DetectorConfig(
                name="topic_only",
                action=Action.WARN,
                anssi_ref="R26",
                extra={"allowed": ["test"]},
            )
        )
    ]
    report = generate_report(detectors_sans_r25, "test")
    assert report["conformite_globale"] == "NON CONFORME"
    assert len(report["recommandations"]) > 0
    assert any("R25" in r for r in report["recommandations"])


def test_conformite_partielle_si_r27_manquante(detectors_sante):
    report = generate_report(detectors_sante, "sante")
    # R27 (contrôle humain) non couverte dans detectors_sante
    assert report["conformite_globale"] == "PARTIELLE"


def test_conformite_globale_conforme_si_tout_couvert():
    detectors_complets = [
        InjectionDetector(
            DetectorConfig(name="inject", action=Action.BLOCK, anssi_ref="R25")
        ),
        TopicDetector(
            DetectorConfig(
                name="topic",
                action=Action.WARN,
                anssi_ref="R26",
                extra={"allowed": ["test"]},
            )
        ),
        InjectionDetector(
            DetectorConfig(
                name="human_review_detector",
                action=Action.HUMAN_REVIEW,
                anssi_ref="R27",
            )
        ),
    ]
    report = generate_report(detectors_complets, "complet")
    assert report["conformite_globale"] == "CONFORME"
    assert len(report["recommandations"]) == 0


def test_nb_detecteurs_actifs_correct(detectors_sante):
    report = generate_report(detectors_sante, "sante")
    assert report["nb_detecteurs_actifs"] == 3


def test_print_report_ne_plante_pas(detectors_sante):
    report = generate_report(detectors_sante, "sante")
    print_report(report)


def test_profil_nom_correct(detectors_sante):
    report = generate_report(detectors_sante, "mon_profil_test")
    assert report["profil"] == "mon_profil_test"
