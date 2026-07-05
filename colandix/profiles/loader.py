# loader.py — Chargement dynamique des détecteurs via profils YAML

import warnings
from pathlib import Path

import yaml

from colandix.detectors.base import BaseDetector, DetectorConfig
from colandix.detectors.entropy import EntropyDetector
from colandix.detectors.injection import InjectionDetector
from colandix.detectors.ner import NERDetector
from colandix.detectors.regex import RegexDetector
from colandix.detectors.topic import TopicDetector
from colandix.result import Action

# Mapping des types YAML vers les classes Python
DETECTOR_MAP: dict[str, type[BaseDetector]] = {
    "regex": RegexDetector,
    "entropy": EntropyDetector,
    "ner": NERDetector,
    "injection": InjectionDetector,
    "topic": TopicDetector,
}

PROFILES_DIR = Path(__file__).parent


def list_profiles() -> list[str]:
    """Retourne la liste des noms des profils disponibles."""
    return sorted([p.stem for p in PROFILES_DIR.glob("*.yaml")])


def load_profile(name: str) -> list[BaseDetector]:
    """
    Charge un profil par son nom depuis le dossier profiles.
    """
    path = PROFILES_DIR / f"{name}.yaml"
    if not path.exists():
        raise ValueError(
            f"Profil '{name}' inconnu. Profils disponibles : {list_profiles()}"
        )
    return _load_from_path(path)


def load_profile_from_yaml(path: str) -> list[BaseDetector]:
    """
    Charge un profil depuis un chemin de fichier arbitraire.
    """
    path_obj = Path(path)
    if not path_obj.exists():
        raise FileNotFoundError(f"Fichier de profil introuvable : {path}")
    return _load_from_path(path_obj)


def _load_from_path(path: Path) -> list[BaseDetector]:
    """Logique interne de chargement et d'instanciation."""
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    detectors: list[BaseDetector] = []
    
    if not data or "detectors" not in data:
        return detectors

    for d in data["detectors"]:
        if not d.get("enabled", True):
            continue

        dtype = d.get("type")
        detector_class = DETECTOR_MAP.get(dtype)
        if not detector_class:
            raise ValueError(
                f"Type de détecteur inconnu : '{dtype}'. Connus : {list(DETECTOR_MAP)}"
            )

        action_raw = d.get("action", "warn")
        if action_raw == "redact":
            warnings.warn(
                "action: redact est déprécié et ignoré dans l'enum ; "
                "utilisez human_review. Traitée comme human_review pour ce chargement.",
                DeprecationWarning,
                stacklevel=3,
            )
            action_raw = "human_review"

        # Création de la configuration normalisée
        config = DetectorConfig(
            name=d["name"],
            action=Action(action_raw),
            weight=float(d.get("weight", 1.0)),
            enabled=d.get("enabled", True),
            anssi_ref=d.get("anssi_ref", "R25"),
            extra=d.get("extra", {}),
        )

        # Instanciation
        detectors.append(detector_class(config))

    return detectors


def get_profile_metadata(name: str) -> dict:
    """
    Lit les métadonnées d'un profil sans instancier les détecteurs.
    """
    path = PROFILES_DIR / f"{name}.yaml"
    if not path.exists():
        raise ValueError(
            f"Profil '{name}' inconnu. Profils disponibles : {list_profiles()}"
        )

    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    return {
        "name": data.get("name", name),
        "description": data.get("description", ""),
        "version": data.get("version", "1.0"),
        "anssi_refs": data.get("anssi_refs", []),
        "nb_detectors": len([
            d for d in data.get("detectors", [])
            if d.get("enabled", True)
        ]),
    }
