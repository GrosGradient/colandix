# topic.py — Détecteur de sujets et classification de contenu

import unicodedata

from colandix.detectors.base import BaseDetector, DetectorConfig, safe_analyze
from colandix.result import Action, DetectionEvent


def _strip_accents(text: str) -> str:
    """NFKD puis suppression des signes combinants (accents)."""
    normalized = unicodedata.normalize("NFD", text)
    return "".join(c for c in normalized if unicodedata.category(c) != "Mn")


class TopicDetector(BaseDetector):
    """
    Vérifie que le prompt reste dans le périmètre métier autorisé (R26 ANSSI).
    Approche par mots-clés : transparente et 100% explicable pour l'audit.
    """

    def __init__(self, config: DetectorConfig):
        super().__init__(config)
        self._allowed = self.config.extra.get("allowed", [])
        self._blocked = self.config.extra.get("blocked", [])
        self._case_sensitive = bool(self.config.extra.get("case_sensitive", False))

    def _normalize(self, text: str) -> str:
        """Applique casse puis suppression des accents pour des matches stables."""
        if not self._case_sensitive:
            text = text.lower()
        return _strip_accents(text)

    @safe_analyze
    def analyze(self, text: str) -> DetectionEvent:
        """
        Vérifie le texte contre les listes de mots-clés bloqués et autorisés.
        """
        normalized_text = self._normalize(text)

        # Étape 1 : Topics bloqués (priorité absolue)
        for keyword in self._blocked:
            norm_kw = self._normalize(keyword)
            if norm_kw in normalized_text:
                evidence = f"topic bloqué: {keyword[:30]}"
                return self._make_event(
                    matched=True,
                    score=0.9,
                    evidence=evidence,
                    trigger_type="TOPIC_BLOCKED",
                )

        # Étape 2 : Périmètre autorisé (si restreint)
        if self._allowed:
            allowed_found = [
                kw for kw in self._allowed if self._normalize(kw) in normalized_text
            ]

            if len(allowed_found) == 0:
                score = 0.9 if self.config.action == Action.BLOCK else 0.5
                return self._make_event(
                    matched=True,
                    score=score,
                    evidence="hors périmètre : aucun topic autorisé détecté",
                    trigger_type="TOPIC_BLOCKED",
                )
            else:
                return self._make_event(matched=False, score=0.0)

        # Étape 3 : Si aucune liste restreinte et aucun bloqué
        return self._make_event(matched=False, score=0.0)

    def get_matched_topics(self, text: str) -> dict:
        """
        Retourne un dictionnaire listant les mots-clés trouvés.
        Utile pour le debug et l'audit.
        """
        normalized_text = self._normalize(text)

        allowed_found = [
            kw for kw in self._allowed if self._normalize(kw) in normalized_text
        ]

        blocked_found = [
            kw for kw in self._blocked if self._normalize(kw) in normalized_text
        ]

        return {"allowed_found": allowed_found, "blocked_found": blocked_found}
