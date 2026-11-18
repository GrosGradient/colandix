# test_fail_closed.py — Non-régression : fuites dans les logs, masquage partiel,
# texte non analysé et détecteurs en erreur.

import json

import pytest

from colandix.detectors.base import BaseDetector, DetectorConfig, safe_analyze
from colandix.detectors.entropy import EntropyDetector
from colandix.detectors.ner import NERDetector
from colandix.detectors.regex import RegexDetector
from colandix.pipeline import GuardPipeline
from colandix.result import Action, DetectionEvent, PipelineConfig


def _regex(patterns, action=Action.BLOCK):
    return RegexDetector(
        DetectorConfig(name="pii", action=action, extra={"patterns": patterns})
    )


class _Crash(BaseDetector):
    @safe_analyze
    def analyze(self, text: str) -> DetectionEvent:
        raise RuntimeError(f"boom sur {text}")


def _crash():
    return _Crash(DetectorConfig(name="crash", action=Action.BLOCK))


def _log_lines(capsys) -> list[dict]:
    out = capsys.readouterr().out
    return [json.loads(line) for line in out.splitlines() if line.startswith("{")]


# --- Logs : jamais la valeur détectée -------------------------------------


def test_log_ne_contient_pas_la_valeur_regex(capsys):
    p = GuardPipeline(detectors=[_regex(["EMAIL"])])
    p.scan_input("écrire à test.leak@example.com")
    entries = _log_lines(capsys)
    assert entries
    assert "test.leak@example.com" not in json.dumps(entries)
    assert entries[0]["detections"][0]["evidence"] == "EMAIL"


def test_log_ne_contient_pas_le_secret_entropie(capsys):
    d = EntropyDetector(DetectorConfig(name="secrets", action=Action.BLOCK))
    p = GuardPipeline(detectors=[d])
    p.scan_input("password=Sup3rS3cretValue!!")
    dump = json.dumps(_log_lines(capsys))
    assert "Sup3rS3cretValue" not in dump


def test_reason_ne_contient_pas_la_valeur():
    p = GuardPipeline(
        detectors=[_regex(["EMAIL"])], config=PipelineConfig(log_inputs=False)
    )
    r = p.scan_input("écrire à test.leak@example.com")
    assert "test.leak@example.com" not in (r.reason or "")


# --- Masquage : toutes les correspondances ---------------------------------


def test_toutes_les_occurrences_sont_masquees():
    p = GuardPipeline(
        detectors=[_regex(["EMAIL"])], config=PipelineConfig(log_inputs=False)
    )
    r = p.scan_input("test1@example.com et test2@example.com")
    assert r.sanitized_text == "[EMAIL_REDACTED] et [EMAIL_REDACTED]"


def test_plusieurs_motifs_masques_avec_leur_propre_tag():
    p = GuardPipeline(
        detectors=[_regex(["EMAIL", "TEL_FR"])],
        config=PipelineConfig(log_inputs=False),
    )
    r = p.scan_input("Écris à test@example.com ou au 06 12 34 56 78")
    assert r.sanitized_text == "Écris à [EMAIL_REDACTED] ou au [PHONE_REDACTED]"


def test_secret_entropie_masque():
    d = EntropyDetector(DetectorConfig(name="secrets", action=Action.WARN))
    p = GuardPipeline(detectors=[d], config=PipelineConfig(log_inputs=False))
    r = p.scan_input("mon password=Sup3rS3cretValue!! ok")
    assert "Sup3rS3cretValue" not in r.sanitized_text
    assert "[PASSWORD_REDACTED]" in r.sanitized_text


# --- Texte plus long que max_text_length -----------------------------------


def test_texte_trop_long_bloque_par_defaut():
    p = GuardPipeline(
        detectors=[_regex(["EMAIL"])],
        config=PipelineConfig(log_inputs=False, max_text_length=100),
    )
    r = p.scan_input("a " * 100 + "test@example.com")
    assert r.blocked is True
    assert "max_text_length" in (r.reason or "")


def test_texte_trop_long_mode_truncate_conserve_ancien_comportement():
    p = GuardPipeline(
        detectors=[_regex(["EMAIL"])],
        config=PipelineConfig(
            log_inputs=False, max_text_length=100, on_overflow="truncate"
        ),
    )
    r = p.scan_input("a " * 100 + "test@example.com")
    assert r.action == Action.PASS


def test_on_overflow_invalide():
    with pytest.raises(ValueError):
        PipelineConfig(on_overflow="ignore")


# --- Détecteur en erreur -----------------------------------------------------


def test_erreur_detecteur_fail_open_par_defaut_mais_journalisee(capsys):
    p = GuardPipeline(detectors=[_crash()])
    r = p.scan_input("texte")
    assert r.action == Action.PASS
    assert r.events[0].error == "RuntimeError"
    entries = _log_lines(capsys)
    assert entries[0]["detector_errors"] == ["crash"]


def test_erreur_detecteur_fail_closed_bloque():
    p = GuardPipeline(
        detectors=[_crash()],
        config=PipelineConfig(log_inputs=False, fail_closed=True),
    )
    r = p.scan_input("texte")
    assert r.blocked is True
    assert r.events[0].evidence.startswith("fail_closed")


def test_message_exception_non_affiche(capsys):
    _crash().analyze("donnée sensible")
    assert "donnée sensible" not in capsys.readouterr().out


def test_ner_indisponible_signale_erreur_et_fail_closed_bloque():
    d = NERDetector(DetectorConfig(name="ner", action=Action.HUMAN_REVIEW))
    d._nlp = None
    d._spacy_available = False
    event = d.analyze("texte")
    assert event.matched is False
    assert event.error is not None

    p = GuardPipeline(
        detectors=[d], config=PipelineConfig(log_inputs=False, fail_closed=True)
    )
    assert p.scan_input("texte").blocked is True


# --- NER : toutes les entités, tout le texte (modèle requis) ----------------


@pytest.fixture
def ner_per():
    pytest.importorskip("spacy")
    d = NERDetector(
        DetectorConfig(
            name="ner",
            action=Action.HUMAN_REVIEW,
            extra={"entities": ["PER"], "combo_threshold": 1},
        )
    )
    if not d.is_fr_core_model_active:
        pytest.skip("Modèle fr_core_news_md requis")
    return d


def test_ner_masque_toutes_les_personnes(ner_per):
    p = GuardPipeline(detectors=[ner_per], config=PipelineConfig(log_inputs=False))
    r = p.scan_input("Marie Dupont a rencontré Paul Durand hier.")
    assert "Dupont" not in r.sanitized_text
    assert "Durand" not in r.sanitized_text


def test_ner_analyse_au_dela_de_max_text_length(ner_per):
    ner_per._max_text_length = 200
    texte = "Le comité s'est réuni. " * 20 + "Marie Dupont a signé."
    event = ner_per.analyze(texte)
    assert event.matched is True
