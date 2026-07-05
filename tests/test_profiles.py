import pytest

from colandix.profiles.loader import (
    get_profile_metadata,
    list_profiles,
    load_profile,
    load_profile_from_yaml,
)
from colandix.result import Action


def test_list_profiles_retourne_liste_non_vide():
    profiles = list_profiles()
    assert len(profiles) >= 6
    assert "sante" in profiles
    assert "strict" in profiles
    assert "generique" in profiles

def test_load_profile_sante():
    detectors = load_profile("sante")
    assert len(detectors) > 0
    # Vérifie que ce sont des instances de détecteurs
    from colandix.detectors.base import BaseDetector
    assert all(isinstance(d, BaseDetector) for d in detectors)


def test_load_profile_strict():
    detectors = load_profile("strict")
    assert len(detectors) == 5
    from colandix.detectors.base import BaseDetector
    assert all(isinstance(d, BaseDetector) for d in detectors)
    assert detectors[0].config.name == "pii_complet"


def test_get_profile_metadata_strict():
    meta = get_profile_metadata("strict")
    assert meta["nb_detectors"] == 5

def test_load_tous_les_profils_integres():
    for name in list_profiles():
        detectors = load_profile(name)
        assert len(detectors) > 0, f"Profil {name} vide"

def test_profil_inconnu_leve_value_error():
    with pytest.raises(ValueError):
        load_profile("profil_inexistant_xyz")

def test_load_profile_from_yaml_custom(tmp_path):
    yaml_content = '''
name: "Test Custom"
description: "Profil de test"
version: "1.0"
anssi_refs: ["R25"]
detectors:
  - type: injection
    name: "test_inject"
    action: block
    weight: 1.0
    anssi_ref: "R25"
'''
    yaml_file = tmp_path / "test_custom.yaml"
    yaml_file.write_text(yaml_content)
    detectors = load_profile_from_yaml(str(yaml_file))
    assert len(detectors) == 1
    assert detectors[0].config.name == "test_inject"

def test_load_profile_from_yaml_fichier_inexistant():
    with pytest.raises(FileNotFoundError):
        load_profile_from_yaml("/chemin/inexistant/profil.yaml")

def test_get_profile_metadata_sante():
    meta = get_profile_metadata("sante")
    assert "name" in meta
    assert "description" in meta
    assert "anssi_refs" in meta
    assert meta["nb_detectors"] > 0

def test_detecteur_disabled_ignore(tmp_path):
    yaml_content = '''
name: "Test Disabled"
description: "Test"
version: "1.0"
anssi_refs: ["R25"]
detectors:
  - type: injection
    name: "actif"
    action: block
    weight: 1.0
    enabled: true
  - type: regex
    name: "desactive"
    action: block
    weight: 1.0
    enabled: false
'''
    yaml_file = tmp_path / "test_disabled.yaml"
    yaml_file.write_text(yaml_content)
    detectors = load_profile_from_yaml(str(yaml_file))
    assert len(detectors) == 1  # seul "actif" chargé
    assert detectors[0].config.name == "actif"

def test_yaml_action_redact_depreciee_devient_human_review(tmp_path):

    yaml_content = """
name: "Test Redact"
description: "Legacy"
version: "1.0"
anssi_refs: ["R25"]
detectors:
  - type: injection
    name: "legacy_hr"
    action: redact
    weight: 1.0
    anssi_ref: "R25"
"""
    yaml_file = tmp_path / "test_redact.yaml"
    yaml_file.write_text(yaml_content)
    with pytest.warns(DeprecationWarning, match="redact"):
        detectors = load_profile_from_yaml(str(yaml_file))
    assert len(detectors) == 1
    assert detectors[0].config.action == Action.HUMAN_REVIEW


def test_type_detecteur_inconnu_leve_value_error(tmp_path):
    yaml_content = '''
name: "Test Invalide"
description: "Test"
version: "1.0"
anssi_refs: []
detectors:
  - type: detecteur_qui_nexiste_pas
    name: "test"
    action: warn
    weight: 1.0
'''
    yaml_file = tmp_path / "test_invalid.yaml"
    yaml_file.write_text(yaml_content)
    with pytest.raises(ValueError):
        load_profile_from_yaml(str(yaml_file))
