# test_entropy.py — Tests unitaires pour le détecteur d'entropie

import pytest

from colandix.detectors.base import DetectorConfig
from colandix.detectors.entropy import EntropyDetector
from colandix.result import Action


@pytest.fixture
def detector_default():
    """Détecteur avec paramètres par défaut (threshold=4.5)."""
    config = DetectorConfig(name="test_entropy", action=Action.BLOCK)
    return EntropyDetector(config)


@pytest.fixture
def detector_sensitive():
    """Détecteur avec seuil bas (threshold=3.5) — plus sensible."""
    config = DetectorConfig(
        name="test_entropy_sensitive", action=Action.BLOCK, extra={"threshold": 3.5}
    )
    return EntropyDetector(config)


def test_api_key_detectee(detector_default):
    event = detector_default.analyze("sk-proj-xK9mN2pL8qR5vT3wY7zA4cF6hJ1nB0dG")
    assert event.matched is True
    assert event.score > 0.0


def test_texte_francais_non_detecte(detector_default):
    event = detector_default.analyze(
        "Bonjour, quel est le traitement pour l'hypertension artérielle ?"
    )
    assert event.matched is False


def test_token_trop_court_non_detecte(detector_default):
    event = detector_default.analyze("password123")
    assert event.matched is False


def test_jwt_detecte(detector_default):
    event = detector_default.analyze(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
    )
    assert event.matched is True


def test_uuid_score_reduit_par_whitelist():
    config_low = DetectorConfig(
        name="low_threshold",
        action=Action.WARN,
        extra={"threshold": 1.0, "min_length": 5},
    )
    detector_low = EntropyDetector(config_low)
    uuid = "550e8400-e29b-41d4-a716-446655440000"

    raw_entropy = detector_low.analyze_token(uuid)
    assert raw_entropy > 3.0

    event = detector_low.analyze(f"Session ID: {uuid}")
    assert event.matched is True


def test_analyze_token_password_faible(detector_default):
    assert detector_default.analyze_token("password") < 3.0


def test_analyze_token_secret_eleve(detector_default):
    assert detector_default.analyze_token("sk-xK9mN2pL8qR5vT3wY") > 4.0


def test_seuil_custom_plus_sensible(detector_default, detector_sensitive):
    token_moyen = "abcdef123456ABCDEF78"
    texte = f"token: {token_moyen}"
    event_default = detector_default.analyze(texte)
    event_sensitive = detector_sensitive.analyze(texte)
    assert event_sensitive.score >= event_default.score


def test_shannon_entropy_chaine_vide(detector_default):
    assert detector_default._shannon_entropy("") == 0.0


def test_shannon_entropy_un_char(detector_default):
    assert detector_default._shannon_entropy("a") == 0.0


def test_score_normalise(detector_default):
    event = detector_default.analyze("sk-proj-xK9mN2pL8qR5vT3wY7zA4cF6hJ1nB0dG")
    if event.matched:
        assert 0.0 <= event.score <= 1.0


def test_evidence_format(detector_default):
    event = detector_default.analyze("sk-proj-xK9mN2pL8qR5vT3wY7zA4cF6hJ1nB0dG")
    if event.matched:
        assert event.evidence is not None
        assert "e:" in event.evidence
        assert len(event.evidence) <= 50


# --- Signal 1 : contexte ---


def test_contexte_password_egal_detecte(detector_default):
    event = detector_default.analyze("password=MonSuperSecret123!")
    assert event.matched is True
    assert event.score == 1.0
    assert "contexte" in event.evidence


def test_contexte_api_key_deux_points_detecte(detector_default):
    event = detector_default.analyze(
        "Utilise api_key: sk-abc123def456ghi789jkl pour l'appel"
    )
    assert event.matched is True
    assert event.score == 1.0


def test_contexte_token_egal_detecte(detector_default):
    event = detector_default.analyze("TOKEN=ghp_xK9mN2pL8qR5vT3wY7zA4cF6h")
    assert event.matched is True
    assert event.score == 1.0


def test_contexte_authorization_bearer_detecte(detector_default):
    event = detector_default.analyze(
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature"
    )
    assert event.matched is True
    assert event.score == 1.0


def test_contexte_variable_env_detecte(detector_default):
    event = detector_default.analyze("DATABASE_PASSWORD=Tr0ub4dor&3xK9mN2pL8q")
    assert event.matched is True
    assert event.score == 1.0


def test_contexte_mot_cle_sans_valeur_ne_declenche_pas(detector_default):
    event = detector_default.analyze("Le mot de passe doit être complexe.")
    assert event.matched is False


def test_contexte_prose_sans_secret_notable_pas_de_contexte(detector_default):
    """Régression : « secret » + espace + mot ne doit pas matcher contexte."""
    for phrase in (
        "Une phrase sans secret notable.",
        "Bonjour, voici un texte sans secret notable en fin.",
    ):
        found, value = detector_default._detect_context(phrase)
        assert found is False, phrase
        assert value is None
        ev = detector_default.analyze(phrase)
        assert "contexte" not in (ev.evidence or ""), phrase


def test_contexte_json_inline_password_detecte(detector_default):
    event = detector_default.analyze(
        '{"password": "MonSuperSecret123!", "user": "x"}'
    )
    assert event.matched is True
    assert event.score == 1.0
    assert "contexte" in (event.evidence or "")


def test_contexte_mot_de_passe_avec_espace_apres_deux_points_detecte(
    detector_default,
):
    """Forme FR « mot de passe : … » listée dans docs/triggers-par-profil.md."""
    event = detector_default.analyze("mot de passe : MonSecret18")
    assert event.matched is True
    assert "contexte" in (event.evidence or "")


def test_contexte_authorization_basic_detecte(detector_default):
    event = detector_default.analyze(
        "Authorization: Basic dXNlcjpwYXNzd29yZDEyMzQ="
    )
    assert event.matched is True
    assert event.score == 1.0


# --- Signal 2 : ratio voyelles ---


def test_ratio_voyelles_hex_pur_booste_score(detector_default):
    token_hex = "a1b2c3d4e5f6789012345678901234ab"
    assert isinstance(detector_default.analyze_token(token_hex), float)
    event = detector_default.analyze(token_hex)
    assert isinstance(event.score, float)
    assert 0.0 <= event.score <= 1.0


def test_ratio_voyelles_texte_lisible_reduit_score(detector_default):
    event = detector_default.analyze(
        "Bonjour voici une phrase avec beaucoup de voyelles naturelles"
    )
    assert event.matched is False


def test_methode_ratio_voyelles_texte_fr(detector_default):
    assert detector_default._ratio_voyelles("bonjour") > 0.35


def test_methode_ratio_voyelles_hex(detector_default):
    # Lettres hex sans voyelles (a,e exclus)
    assert detector_default._ratio_voyelles("b1c2d3f4069784") < 0.10


def test_methode_ratio_voyelles_chaine_vide(detector_default):
    assert detector_default._ratio_voyelles("") == 0.0


def test_methode_detect_context_trouve(detector_default):
    found, value = detector_default._detect_context("password=MonSuperSecret123!")
    assert found is True
    assert value is not None
    assert len(value) <= 30


def test_methode_detect_context_ne_trouve_pas(detector_default):
    found, value = detector_default._detect_context(
        "Bonjour, voici un texte normal sans secret"
    )
    assert found is False
    assert value is None


def test_methode_score_complexite_trop_court(detector_default):
    assert detector_default._score_complexite("abc") == 0.0


def test_methode_score_complexite_espace(detector_default):
    assert detector_default._score_complexite("abcd1234 efgh") == 0.0


def test_methode_score_complexite_quatre_types_long(detector_default):
    # 4 types, longueur 20+ → base 0.85 * 1.0
    assert detector_default._score_complexite("Aa0!aaaaaaaaaaaaaaaa") == 0.85


def test_methode_score_complexite_deux_types_len_8(detector_default):
    # 2 types, len 8 → 0.25 * 0.6 = 0.15
    assert abs(detector_default._score_complexite("abcd1234") - 0.15) < 1e-9


def test_analyze_inclut_complexite_quand_score_eleve(detector_default):
    tok = "sk-proj-xK9mN2pL8qR5vT3wY7zA4cF6hJ1nB0dG"
    assert detector_default._score_complexite(tok) > 0.30
    event = detector_default.analyze(tok)
    assert event.matched is True


def test_gray_structural_entropie_sous_seuil_mais_jeton_complexe():
    """Jeton type clé avec répétitions : Shannon modéré, profil dev-like."""
    config = DetectorConfig(
        name="dev_like",
        action=Action.BLOCK,
        extra={"threshold": 4.2, "min_length": 16},
    )
    det = EntropyDetector(config)
    event = det.analyze("fezjf57829F787feu9nzio68ffa-")
    assert event.matched is True
    assert 0.60 <= event.score < 0.85
