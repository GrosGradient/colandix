# test_detection_quality.py — Non-régression : IBAN espacés, types d'entités NER.

import pytest

from colandix.detectors.base import DetectorConfig
from colandix.detectors.ner import NERDetector, entity_trigger_type
from colandix.detectors.regex import RegexDetector
from colandix.pipeline import GuardPipeline
from colandix.result import Action, PipelineConfig


def _regex(patterns):
    return RegexDetector(
        DetectorConfig(name="iban", action=Action.BLOCK, extra={"patterns": patterns})
    )


# --- IBAN -------------------------------------------------------------------


@pytest.mark.parametrize(
    "texte",
    [
        "Virement sur FR76 3000 6000 0112 3456 7890 189 merci",
        "Virement sur FR7630006000011234567890189 merci",
    ],
)
def test_iban_fr_compact_et_espace(texte):
    p = GuardPipeline(
        detectors=[_regex(["IBAN_FR"])], config=PipelineConfig(log_inputs=False)
    )
    r = p.scan_input(texte)
    assert r.sanitized_text == "Virement sur [IBAN_REDACTED] merci"


def test_iban_generique_espace():
    event = _regex(["IBAN_GENERIQUE"]).analyze("IBAN : DE89 3704 0044 0532 0130 00")
    assert event.matched is True
    assert event.match_text.replace(" ", "") == "DE89370400440532013000"


def test_iban_generique_ne_matche_pas_un_mot_minuscule():
    event = _regex(["IBAN_GENERIQUE"]).analyze("le lien ab12cdefghijklmnop")
    assert event.matched is False


# --- NER ----------------------------------------------------------------------


def test_entity_trigger_type():
    assert entity_trigger_type("PER") == "PERSON_NAME"
    assert entity_trigger_type("LOC") == "LOCATION"
    assert entity_trigger_type("ORG") == "ORGANIZATION"
    assert entity_trigger_type("MISC") == "GENERIC"


def _ner(entities, combo=1):
    pytest.importorskip("spacy")
    d = NERDetector(
        DetectorConfig(
            name="ner",
            action=Action.HUMAN_REVIEW,
            extra={"entities": entities, "combo_threshold": combo},
        )
    )
    if not d.is_fr_core_model_active:
        pytest.skip("Modèle fr_core_news_md requis")
    return d


TEXTE = "Marie Dupont travaille chez Airbus à Toulouse."


def test_get_entities_respecte_le_profil():
    d = _ner(["PER"])
    assert set(d.get_entities(TEXTE)) <= {"PER"}
    assert {c["reason"] for c in d.find_all_candidates(TEXTE)} <= {"PER"}


def test_ner_tag_par_type_d_entite():
    d = _ner(["PER", "LOC"])
    p = GuardPipeline(detectors=[d], config=PipelineConfig(log_inputs=False))
    r = p.scan_input(TEXTE)
    assert "[PERSON_REDACTED]" in r.sanitized_text
    assert "[LOCATION_REDACTED]" in r.sanitized_text
    assert "Toulouse" not in r.sanitized_text


def test_ner_sans_personne_n_annonce_pas_person_name():
    d = _ner(["LOC"])
    event = d.analyze("Le colis part de Toulouse vers Lyon.")
    assert event.matched is True
    assert event.trigger_type == "LOCATION"
