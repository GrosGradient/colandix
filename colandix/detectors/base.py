# base.py — Classe de base et interface pour tous les détecteurs

import functools
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

from colandix.result import Action, DetectionEvent


@dataclass
class DetectorConfig:
    """Configuration d'un détecteur individuel, lue depuis le YAML."""
    name: str
    action: Action
    weight: float = 1.0
    enabled: bool = True
    anssi_ref: str = "R25"
    extra: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not (0.0 <= self.weight <= 1.0):
            raise ValueError(f"weight doit être entre 0.0 et 1.0, reçu : {self.weight}")


class DetectorError(Exception):
    """Exception levée en cas d'erreur interne d'un détecteur."""
    def __init__(self, detector_name: str, original_error: Exception):
        self.detector_name = detector_name
        self.original_error = original_error
        super().__init__(
            f"Erreur dans le détecteur '{detector_name}' : {original_error}"
        )


def safe_analyze(func):
    """
    Décorateur qui wrape la méthode analyze() pour capturer les exceptions
    et retourner un événement de secours, évitant ainsi le crash du pipeline.
    """
    @functools.wraps(func)
    def wrapper(self: 'BaseDetector', text: str, *args, **kwargs) -> DetectionEvent:
        try:
            return func(self, text, *args, **kwargs)
        except Exception as e:
            print(f"[colandix] ERREUR détecteur '{self.config.name}': {e}")
            # 7 chars pour "ERROR: " + 43 chars max = 50 chars max
            evidence_msg = "ERROR: " + str(e)[:43]
            return DetectionEvent(
                detector_name=self.config.name,
                detector_type=self.__class__.__name__,
                matched=False,
                score=0.0,
                action=Action.PASS,
                evidence=evidence_msg,
                anssi_ref=self.config.anssi_ref,
            )
    return wrapper


class BaseDetector(ABC):
    """
    Classe de base abstraite pour tous les détecteurs de colandix.
    """
    def __init__(self, config: DetectorConfig):
        self.config = config

    def is_enabled(self) -> bool:
        """Retourne True si le détecteur est activé dans sa configuration."""
        return self.config.enabled

    @abstractmethod
    def analyze(self, text: str) -> DetectionEvent:
        """
        Analyse le texte fourni.
        
        - Appelée sur chaque requête en production : doit être rapide
        - Ne doit JAMAIS faire d'appel réseau (souveraineté colandix)
        - Doit TOUJOURS retourner un DetectionEvent même si rien détecté
        - Le score retourné doit être entre 0.0 et 1.0
        """
        pass

    def find_all_candidates(self, text: str) -> list[dict]:
        """
        Extrait TOUS les candidats potentiels détectés par ce détecteur.
        Retourne une liste de dict : [{"matched": "...", "score": 1.0, "reason": "..."}]
        """
        return []

    def _make_event(
        self,
        matched: bool,
        score: float,
        evidence: Optional[str] = None,
        trigger_type: Optional[str] = None,
        match_text: Optional[str] = None,
    ) -> DetectionEvent:
        """Helper protégé pour construire un DetectionEvent standardisé."""

        if evidence is not None and len(evidence) > 50:
            evidence = evidence[:50]

        action = self.config.action if matched else Action.PASS
        tt = trigger_type if matched else None
        mt = match_text if matched else None

        return DetectionEvent(
            detector_name=self.config.name,
            detector_type=self.__class__.__name__,
            matched=matched,
            score=score,
            action=action,
            evidence=evidence,
            trigger_type=tt,
            anssi_ref=self.config.anssi_ref,
            match_text=mt,
        )

    def __repr__(self) -> str:
        return (f"{self.__class__.__name__}(name='{self.config.name}', "
                f"action='{self.config.action.value}', enabled={self.config.enabled})")

