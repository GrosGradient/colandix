# result.py — Types de retour de colandix (ScanResult, DetectionEvent, Action)

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Action(str, Enum):
    """
    Actions possibles qu'un détecteur peut recommander, par ordre croissant de sévérité.
    Ordre logique : pass → warn → human_review → block.
    """
    PASS = "pass"
    WARN = "warn"
    HUMAN_REVIEW = "human_review"
    BLOCK = "block"


class ScanDirection(str, Enum):
    """
    Sens du flux de données scanné.
    """
    INPUT = "input"
    OUTPUT = "output"


@dataclass
class DetectionEvent:
    """
    Représente le résultat d'un détecteur sur un texte.
    Un événement est créé pour chaque détecteur, qu'il ait matché ou non.
    """
    detector_name: str
    detector_type: str
    matched: bool
    score: float
    action: Action
    evidence: Optional[str] = None
    trigger_type: Optional[str] = None
    anssi_ref: Optional[str] = None
    # Texte exact de la correspondance : masquage correct sans fuite RGPD via
    # evidence tronquée. Ne pas sérialiser ni logger (même statut que le texte brut).
    match_text: Optional[str] = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if not self.matched:
            self.action = Action.PASS
            self.score = 0.0

        if self.evidence is not None and len(self.evidence) > 50:
            self.evidence = self.evidence[:50]

        if not 0.0 <= self.score <= 1.0:
            raise ValueError(
                f"Score invalide ({self.score}). Il doit être entre 0.0 et 1.0."
            )


@dataclass
class ScanResult:
    """
    Représente le résultat global d'un scan 
    (agrégation de tous les détecteurs sur un texte).
    """
    direction: ScanDirection
    original_text: str  # RGPD : ce champ n'est jamais sérialisé
    sanitized_text: str
    blocked: bool
    action: Action
    global_score: float
    events: list[DetectionEvent] = field(default_factory=list)
    reason: Optional[str] = None

    @property
    def is_clean(self) -> bool:
        """True uniquement si action == PASS et blocked == False."""
        return self.action == Action.PASS and not self.blocked

    @property
    def matched_events(self) -> list[DetectionEvent]:
        """Liste filtrée des événements où matched=True uniquement."""
        return [e for e in self.events if e.matched]

    @property
    def anssi_refs_covered(self) -> set[str]:
        """Set des références ANSSI des détecteurs qui ont matché (ignore les None)."""
        return {e.anssi_ref for e in self.matched_events if e.anssi_ref is not None}

    @property
    def has_blocked_action(self) -> bool:
        """True si au moins un event individuel a action=Action.BLOCK."""
        return any(e.action == Action.BLOCK for e in self.matched_events)


@dataclass
class PipelineConfig:
    """
    Configuration globale du pipeline colandix.
    """
    profile_name: str = "generique"
    log_inputs: bool = True
    log_outputs: bool = True
    raise_on_block: bool = False
    max_text_length: int = 10_000

