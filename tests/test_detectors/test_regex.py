# test_regex.py — Tests unitaires pour le détecteur regex.py

import pytest

from colandix.detectors.base import DetectorConfig
from colandix.detectors.regex import RegexDetector
from colandix.result import Action
from colandix.scoring import apply_redactions


@pytest.fixture
def detector_all_patterns():
    """Détecteur avec tous les patterns builtin actifs."""
    config = DetectorConfig(name="test_regex", action=Action.BLOCK)
    return RegexDetector(config)


@pytest.fixture
def detector_nir_only():
    """Détecteur avec uniquement le pattern NIR."""
    config = DetectorConfig(
        name="test_nir", action=Action.BLOCK, extra={"patterns": ["NIR"]}
    )
    return RegexDetector(config)


def test_nir_valide_detecte(detector_all_patterns):
    event = detector_all_patterns.analyze(
        "Le patient 2 85 06 75 056 089 42 est hospitalisé"
    )
    assert event.matched is True
    assert "NIR" in event.evidence


def test_nir_invalide_non_detecte(detector_nir_only):
    event = detector_nir_only.analyze("Le code est 123456789012345")
    assert event.matched is False


def test_siret_detecte(detector_all_patterns):
    event = detector_all_patterns.analyze(
        "La société SIRET 73282932000074 a été contactée"
    )
    assert event.matched is True


def test_email_detecte(detector_all_patterns):
    event = detector_all_patterns.analyze("Contacter dr.martin@aphp.fr pour le suivi")
    assert event.matched is True


def test_email_obfusque_crochet_detecte(detector_all_patterns):
    event = detector_all_patterns.analyze("Écrire john[at]gmail.com pour le sujet")
    assert event.matched is True
    assert "EMAIL_OBFUSQUE" in (event.evidence or "")


def test_email_obfusque_parenthese_detecte(detector_all_patterns):
    event = detector_all_patterns.analyze("Contact john(at)example.org stp")
    assert event.matched is True
    assert "EMAIL_OBFUSQUE" in (event.evidence or "")


def test_tel_intl_detecte(detector_all_patterns):
    ev = detector_all_patterns.analyze("UK +447911123456")
    assert ev.matched is True
    assert "TEL_INTL" in (ev.evidence or "")
    # +33 compact : déjà couvert par TEL_FR (plus spécifique), pas TEL_INTL
    ev_fr = detector_all_patterns.analyze("Mobile +33612345678")
    assert ev_fr.matched is True
    assert "TEL_FR" in (ev_fr.evidence or "")
    ev_de = detector_all_patterns.analyze("Contact +4915123456789")
    assert ev_de.matched is True
    assert "TEL_INTL" in (ev_de.evidence or "")


def test_aws_secret_key_detecte(detector_all_patterns):
    secret = "ABCDEFGHIJ1234567890abcdefghij1234567890"
    event = detector_all_patterns.analyze(
        f"export AWS_SECRET_ACCESS_KEY={secret}"
    )
    assert event.matched is True
    assert "AWS_SECRET_KEY" in (event.evidence or "")


def test_ipv6_compresse_detecte(detector_all_patterns):
    ev = detector_all_patterns.analyze("Routeur 2001:db8::1 actif")
    assert ev.matched is True
    assert "IPV6" in (ev.evidence or "")
    ev2 = detector_all_patterns.analyze("Loopback ::1")
    assert ev2.matched is True
    assert "IPV6" in (ev2.evidence or "")


def test_credential_pwd_detecte(detector_all_patterns):
    event = detector_all_patterns.analyze("fichier pwd=secretpassword")
    assert event.matched is True
    assert "CREDENTIAL" in (event.evidence or "")


def test_credential_login_detecte(detector_all_patterns):
    event = detector_all_patterns.analyze("login=supersecret1 pour test")
    assert event.matched is True
    assert "CREDENTIAL" in (event.evidence or "")


def test_ip_privee_detectee(detector_all_patterns):
    event = detector_all_patterns.analyze("Le serveur est sur 192.168.1.45 port 8080")
    assert event.matched is True


def test_ipv6_documentation_detectee(detector_all_patterns):
    event = detector_all_patterns.analyze(
        "Adresse 2001:0db8:0000:85a3:0000:0000:ac1f:8001 pour les tests"
    )
    assert event.matched is True
    assert "IPV6" in event.evidence


def test_api_key_detectee(detector_all_patterns):
    event = detector_all_patterns.analyze(
        "Utilise api_key=sk-abc123def456ghi789jkl pour l'appel"
    )
    assert event.matched is True


def test_api_key_sk_nue_detectee(detector_all_patterns):
    event = detector_all_patterns.analyze(
        "Ma clé d'API est sk-5p9kR2jL9s1m0p8n7b6v5c4x3z2a1s0d."
    )
    assert event.matched is True
    assert "API_KEY_SK" in event.evidence


def test_carte_bancaire_pan_detectee(detector_all_patterns):
    event = detector_all_patterns.analyze("Paiement CB : 4532 0151 1283 0366")
    assert event.matched is True
    assert "CARD_PAN" in (event.evidence or "")


def test_card_amex_15_digits_detecte(detector_all_patterns):
    event = detector_all_patterns.analyze("Carte Amex 3714 496353 98431")
    assert event.matched is True
    assert "CARD_AMEX" in (event.evidence or "")


def test_card_discover_detecte(detector_all_patterns):
    event = detector_all_patterns.analyze("Paiement 6011 1111 1111 1117")
    assert event.matched is True
    assert "CARD_DISCOVER_UNIONPAY" in (event.evidence or "")


def test_card_unionpay_detecte(detector_all_patterns):
    event = detector_all_patterns.analyze("Carte 6250 9412 3456 7890")
    assert event.matched is True
    assert "CARD_DISCOVER_UNIONPAY" in (event.evidence or "")


def test_card_pan_ne_matche_pas_prefixe_amex_16_groupes():
    """Régression : CARD_PAN = Visa/MC 16 chiffres seulement."""
    det = RegexDetector(
        DetectorConfig(
            name="one", action=Action.BLOCK, extra={"patterns": ["CARD_PAN"]}
        )
    )
    assert det.analyze("3721 1111 1111 1111").matched is False


def test_ssn_us_detecte(detector_all_patterns):
    event = detector_all_patterns.analyze("SSN 078-05-1120 (exemple)")
    assert event.matched is True
    assert "SSN_US" in (event.evidence or "")


def test_ssn_us_invalide_non_detecte():
    det = RegexDetector(
        DetectorConfig(name="one", action=Action.BLOCK, extra={"patterns": ["SSN_US"]})
    )
    assert det.analyze("invalid 000-00-0000").matched is False
    assert det.analyze("invalid 666-12-3456").matched is False


def test_tel_us_detecte():
    det = RegexDetector(
        DetectorConfig(name="one", action=Action.BLOCK, extra={"patterns": ["TEL_US"]})
    )
    assert det.analyze("Call (415) 555-0100").matched is True
    assert det.analyze("Num +1 415-555-0100").matched is True


def test_crypto_eth_detecte(detector_all_patterns):
    event = detector_all_patterns.analyze(
        "Wallet 0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
    )
    assert event.matched is True
    assert "CRYPTO_ETH" in (event.evidence or "")


def test_crypto_btc_legacy_detecte(detector_all_patterns):
    event = detector_all_patterns.analyze(
        "BTC 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    )
    assert event.matched is True
    assert "CRYPTO_BTC" in (event.evidence or "")


def test_crypto_btc_bech32_detecte(detector_all_patterns):
    event = detector_all_patterns.analyze(
        "Addr bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
    )
    assert event.matched is True
    assert "CRYPTO_BTC" in (event.evidence or "")


def test_nino_uk_detecte(detector_all_patterns):
    event = detector_all_patterns.analyze("NINO AB 12 34 56 C")
    assert event.matched is True
    assert "NINO_UK" in (event.evidence or "")
    ev2 = detector_all_patterns.analyze("Réf AB123456C")
    assert ev2.matched is True
    assert "NINO_UK" in (ev2.evidence or "")


def test_db_url_mssql_detecte(detector_all_patterns):
    event = detector_all_patterns.analyze(
        "Conn=mssql://user:passw0rd@db.internal:1433/appdb"
    )
    assert event.matched is True
    assert "DB_URL" in (event.evidence or "")


def test_iban_generique_detecte(detector_all_patterns):
    event = detector_all_patterns.analyze(
        "Virement vers DE89370400440532013000 (Allemagne)."
    )
    assert event.matched is True
    assert "IBAN_GENERIQUE" in (event.evidence or "")


def test_iban_fr_match_avant_generique(detector_all_patterns):
    """IBAN français : motif FR prioritaire (ordre des clés builtin)."""
    event = detector_all_patterns.analyze(
        "Compte FR7630006000011234567890189 nominatif"
    )
    assert event.matched is True
    assert "IBAN_FR" in (event.evidence or "")


def test_passeport_fr_detecte(detector_all_patterns):
    event = detector_all_patterns.analyze(
        "Copie passeport 12AB12345 pour le dossier expatriation."
    )
    assert event.matched is True
    assert "PASSEPORT_FR" in (event.evidence or "")


def test_db_url_detecte(detector_all_patterns):
    event = detector_all_patterns.analyze(
        "DATABASE_URL=postgresql://user:passw0rd@db.internal:5432/appdb"
    )
    assert event.matched is True
    assert "DB_URL" in (event.evidence or "")


def test_connection_string_sql_server_detecte(detector_all_patterns):
    event = detector_all_patterns.analyze(
        "Server=myserver.database.windows.net;Database=mydb;User=myuser;Password=Secret123!"
    )
    assert event.matched is True
    assert "CONNECTION_STRING" in (event.evidence or "")


def test_pem_certificate_header_detecte(detector_all_patterns):
    event = detector_all_patterns.analyze(
        "Coller ici -----BEGIN CERTIFICATE-----\nMIIC..."
    )
    assert event.matched is True
    assert "PRIVATE_KEY_HEADER" in (event.evidence or "")


@pytest.fixture
def detector_alnum_mixed_only():
    config = DetectorConfig(
        name="alnum_only",
        action=Action.BLOCK,
        extra={"patterns": ["ALNUM_MIXED_12"]},
    )
    return RegexDetector(config)


def test_alnum_mixed_12_detecte_jeton_avec_tiret(detector_all_patterns):
    event = detector_all_patterns.analyze("Prompt : fezjf57829F7-87")
    assert event.matched is True
    assert "ALNUM_MIXED_12" in event.evidence


def test_alnum_mixed_12_longueur_min_et_trois_classes(detector_alnum_mixed_only):
    assert detector_alnum_mixed_only.analyze("abcdefghij1A").matched is True  # 12 chars
    assert detector_alnum_mixed_only.analyze("abcdefg1A").matched is False  # trop court


def test_alnum_mixed_12_sans_majuscule_non_detecte(detector_alnum_mixed_only):
    assert detector_alnum_mixed_only.analyze("abcdefghij1234").matched is False


def test_alnum_mixed_12_sans_chiffre_non_detecte(detector_alnum_mixed_only):
    assert detector_alnum_mixed_only.analyze("abcdefghijklAB").matched is False


def test_alnum_mixed_12_lettres_seules_non_detecte(detector_alnum_mixed_only):
    assert detector_alnum_mixed_only.analyze("abcdefghijkl").matched is False


def test_alnum_mixed_12_chiffres_seuls_non_detecte(detector_alnum_mixed_only):
    assert detector_alnum_mixed_only.analyze("123456789012").matched is False


def test_github_token_detecte(detector_all_patterns):
    tok = "ghp_" + ("a" * 36)
    event = detector_all_patterns.analyze(f"export TOKEN={tok}")
    assert event.matched is True
    assert "GITHUB_TOKEN" in (event.evidence or "")


def test_gitlab_token_detecte(detector_all_patterns):
    event = detector_all_patterns.analyze("glpat-abcdefghijklmnopqrst")
    assert event.matched is True
    assert "GITLAB_TOKEN" in (event.evidence or "")


def test_anthropic_api_key_detecte(detector_all_patterns):
    key = "sk-ant-api03-" + ("x" * 40)
    event = detector_all_patterns.analyze(key)
    assert event.matched is True
    assert "ANTHROPIC_API_KEY" in (event.evidence or "")


def test_aws_access_key_id_detecte(detector_all_patterns):
    event = detector_all_patterns.analyze("Clé AKIA0123456789ABCDEF exposée")
    assert event.matched is True
    assert "AWS_ACCESS_KEY_ID" in (event.evidence or "")


def test_jwt_jws_detecte(detector_all_patterns):
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sigpart123xyz"
    event = detector_all_patterns.analyze(f"token={jwt}")
    assert event.matched is True
    assert "JWT_JWS" in (event.evidence or "")


def test_texte_propre_non_detecte(detector_all_patterns):
    event = detector_all_patterns.analyze(
        "Quel est le traitement standard pour l'hypertension artérielle ?"
    )
    assert event.matched is False


def test_pattern_custom_detecte():
    config = DetectorConfig(
        name="custom",
        action=Action.WARN,
        extra={"custom_patterns": {"MON_CODE": r"MON_CODE: [A-Z]{3}-[0-9]{4}"}},
    )
    detector = RegexDetector(config)
    event = detector.analyze("Référence MON_CODE: ABC-1234 dans le dossier")
    assert event.matched is True


def test_pattern_custom_invalide_leve_value_error():
    config = DetectorConfig(
        name="invalid",
        action=Action.BLOCK,
        extra={"custom_patterns": {"MAUVAIS": "[invalid"}},
    )
    with pytest.raises(ValueError):
        RegexDetector(config)


def test_patterns_selectionnes_uniquement():
    config = DetectorConfig(
        name="email_only", action=Action.BLOCK, extra={"patterns": ["EMAIL"]}
    )
    detector = RegexDetector(config)
    assert detector.get_active_patterns() == ["EMAIL"]
    assert detector.analyze("Contacter dr.martin@aphp.fr").matched is True
    assert detector.analyze("192.168.1.45").matched is False


def test_exclude_patterns_retire_builtin():
    config = DetectorConfig(
        name="sans_alnum",
        action=Action.BLOCK,
        extra={"exclude_patterns": ["ALNUM_MIXED_12"]},
    )
    detector = RegexDetector(config)
    assert "ALNUM_MIXED_12" not in detector.get_active_patterns()
    assert "EMAIL" in detector.get_active_patterns()
    assert detector.analyze("Jeton fezjf57829F7-87 seul").matched is False
    assert detector.analyze("Contacter u@example.fr").matched is True


def test_get_active_patterns_tous(detector_all_patterns):
    active = detector_all_patterns.get_active_patterns()
    assert len(active) > 0
    assert "NIR" in active
    assert "EMAIL" in active


def test_evidence_format(detector_all_patterns):
    event = detector_all_patterns.analyze("Contacter dr.martin@aphp.fr")
    assert event.evidence is not None
    assert "EMAIL" in event.evidence
    assert len(event.evidence) <= 50


def test_action_propagee():
    config = DetectorConfig(name="test", action=Action.BLOCK)
    detector = RegexDetector(config)
    event = detector.analyze("Contacter dr.martin@aphp.fr")
    assert event.action == Action.BLOCK
    assert event.matched is True


@pytest.mark.parametrize(
    "patterns,text,expected_key",
    [
        (["TEL_FR"], "Numéro 06 12 34 56 78", "TEL_FR"),
        (["SIREN"], "Référence 123456789 valide", "SIREN"),
        (["TVA_FR"], "TVA FR12345678901 sur facture", "TVA_FR"),
        (["FINESS"], "Établissement 750712345 noté", "FINESS"),
        (["RPPS"], "RPPS 10001234567", "RPPS"),
        (["MARQUAGE_DR"], "Document diffusion restreinte interne", "MARQUAGE_DR"),
        (["IGI_1300"], "Référence igi 1300 appliquée", "IGI_1300"),
        (["CONFIDENTIEL_DEF"], "Pièce confidentiel défense", "CONFIDENTIEL_DEF"),
        (
            ["CREDENTIAL"],
            "connexion password=abcdefgh",
            "CREDENTIAL",
        ),
        (["CREDENTIAL"], "fichier pwd=secretpassword", "CREDENTIAL"),
        (
            ["API_KEY_GENERIC"],
            "x api_key=abcdefghijklmnopqrst1234",
            "API_KEY_GENERIC",
        ),
        (["SSN_US"], "Numéro 078-05-1120", "SSN_US"),
        (["NINO_UK"], "Référence AB123456C", "NINO_UK"),
        (["TEL_US"], "Phone (415) 555-0100", "TEL_US"),
        (["TEL_INTL"], "Contact +33612345678", "TEL_INTL"),
        (["EMAIL_OBFUSQUE"], "spam john[at]spam.com", "EMAIL_OBFUSQUE"),
        (
            ["AWS_SECRET_KEY"],
            "aws_secret=ABCDEFGHIJ1234567890abcdefghij1234567890",
            "AWS_SECRET_KEY",
        ),
        (["IPV6"], "Adresse 2001:db8::1", "IPV6"),
        (["CARD_AMEX"], "Paiement 3714 496353 98431", "CARD_AMEX"),
        (
            ["CARD_DISCOVER_UNIONPAY"],
            "Carte 6011 1111 1111 1117",
            "CARD_DISCOVER_UNIONPAY",
        ),
    ],
)
def test_regex_motifs_documentes_triggers_par_profil(patterns, text, expected_key):
    """Couverture des builtins listés dans docs/triggers-par-profil.md."""
    det = RegexDetector(
        DetectorConfig(name="one", action=Action.BLOCK, extra={"patterns": patterns})
    )
    ev = det.analyze(text)
    assert ev.matched is True
    assert expected_key in (ev.evidence or "")


def test_profil_rh_custom_regex_salaire_syndicat():
    from colandix.profiles.loader import load_profile

    detectors = load_profile("rh")
    rh_custom = next(d for d in detectors if d.config.name == "donnees_sensibles_rh")
    assert rh_custom.analyze("point sur la fiche de paie").matched is True
    assert rh_custom.analyze("réunion du CSE demain").matched is True
    assert rh_custom.analyze("entretien annuel de performance").matched is True


def test_ip_privee_masquage_complet():
    """L'IP entière doit être masquée, pas partiellement."""
    config = DetectorConfig(name="test_ip", action=Action.BLOCK)
    detector = RegexDetector(config)

    cas = [
        "10.0.0.1",
        "192.168.1.10",
        "172.20.0.5",
        "serveur à 10.255.255.254 port 22",
    ]
    for texte in cas:
        event = detector.analyze(texte)
        assert event.matched, f"IP non détectée dans : '{texte}'"

        sanitized = apply_redactions(texte, [event])
        assert "." not in sanitized or "[REDACTED]" in sanitized, (
            f"Masquage partiel pour '{texte}' → '{sanitized}'"
        )
        for octet in ["10.0.0", "192.168", "172.20"]:
            if octet in texte:
                assert octet not in sanitized, (
                    f"IP partiellement visible dans '{sanitized}'"
                )


def test_twilio_sid_detecte():
    """TWILIO_SID doit être détecté."""
    config = DetectorConfig(name="test", action=Action.BLOCK)
    detector = RegexDetector(config)

    cas_valides = [
        "ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "Mon SID Twilio est AC" + "a" * 32,
    ]
    for texte in cas_valides:
        event = detector.analyze(texte)
        assert event.matched, f"TWILIO_SID non détecté dans : '{texte}'"
        assert "TWILIO" in (event.evidence or ""), (
            f"Evidence incorrecte : '{event.evidence}'"
        )


def test_twilio_sid_faux_positifs():
    """TWILIO_SID ne doit pas déclencher sur des séquences similaires."""
    config = DetectorConfig(
        name="test",
        action=Action.BLOCK,
        extra={"patterns": ["TWILIO_SID"]},
    )
    detector = RegexDetector(config)

    cas_invalides = [
        "AC123",
        "ACxxxxxxxxxxxx",
        "BCAC" + "x" * 32,
    ]
    for texte in cas_invalides:
        event = detector.analyze(texte)
        assert not event.matched, (
            f"Faux positif TWILIO_SID sur : '{texte}'"
        )


def test_ssh_key_publique_detectee():
    """Les clés SSH publiques doivent être détectées."""
    config = DetectorConfig(name="test", action=Action.BLOCK)
    detector = RegexDetector(config)

    cas_valides = [
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ",
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVz",
        "Clé publique : ssh-rsa AAAAB3NzaC1yc2EAAAADAQABx user@host",
    ]
    for texte in cas_valides:
        event = detector.analyze(texte)
        assert event.matched, f"Clé SSH non détectée dans : '{texte}'"


def test_ssh_key_profil_strict_bloque():
    """Le profil strict doit bloquer les clés SSH publiques."""
    from colandix import GuardPipeline
    from colandix.result import PipelineConfig

    guard = GuardPipeline(
        profile="strict",
        config=PipelineConfig(log_inputs=False, log_outputs=False),
    )
    result = guard.scan_input(
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ user@machine"
    )
    assert result.blocked, "Clé SSH publique devrait être bloquée"
    assert result.action == Action.BLOCK


def test_profil_juridique_custom_regex_confidentiel_ref():
    from colandix.profiles.loader import load_profile

    detectors = load_profile("juridique")
    clauses = next(d for d in detectors if d.config.name == "clauses_sensibles")
    assert clauses.analyze("clause NDA et secret des affaires").matched is True
    assert clauses.analyze("dossier n° 2024-AB-001").matched is True
