# injection.py — Détecteur spécifique aux tentatives de prompt injection

import re
import unicodedata

from colandix.detectors.base import BaseDetector, DetectorConfig, safe_analyze
from colandix.result import DetectionEvent


def _normalize_injection_text(text: str) -> str:
    """Lowercase, sans accents, espaces normalisés (détection stable)."""
    normalized = unicodedata.normalize("NFD", text)
    without_marks = "".join(
        c for c in normalized if unicodedata.category(c) != "Mn"
    )
    collapsed = re.sub(r"\s+", " ", without_marks.lower()).strip()
    return collapsed


class InjectionDetector(BaseDetector):
    """
    Détecteur identifiant les tentatives de prompt injection (R25 ANSSI).
    Calcule un score cumulatif basé sur de multiples patterns matchés.
    """

    INJECTION_PATTERNS = {
        # Catégorie : reset d'instructions (EN/FR + DE/ES/PT/IT après normalisation)
        "IGNORE_INSTRUCTIONS": (
            r"(?:ignore|forget|disregard)\s+(?:all\s+)?(?:previous\s+|your\s+|any\s+)?"
            r"(?:tes\s+|vos\s+)?instructions?"
        ),
        "OUBLIE_INSTRUCTIONS": r"oublie\s+(?:toutes?\s+)?(?:tes\s+)?instructions?|ne\s+tiens?\s+pas\s+compte",  # noqa: E501
        "RESET_DE": (
            r"(?:vergiss|ignoriere)\s+(?:alle?\s+)?(?:vorherigen?\s+)?anweisungen"
        ),
        "RESET_ES": (
            r"(?:ignora|olvida)\s+(?:todas?\s+(?:las\s+)?)?instrucciones|"
            r"olvida\s+todo\s+lo"
        ),
        "RESET_PT": (
            r"(?:ignore|esqueca)\s+(?:todas?\s+as\s+)?instrucoes|esqueca\s+tudo"
        ),
        "RESET_IT": (
            r"(?:ignora|dimentica)\s+(?:tutte\s+le\s+)?istruzioni|dimentica\s+tutto"
        ),
        "NEW_PERSONA": (
            r"(?:tu\s+es\s+maintenant|act\s+as|pretend\s+(?:you\s+are|to\s+be)|"
            r"new\s+persona|you\s+are\s+now|du\s+bist\s+jetzt|eres\s+ahora|sei\s+ora)"
        ),
        # Catégorie : extraction système
        "REVEAL_PROMPT": r"(?:reveal|repeat|affiche|r[eé]v[eè]le|show|montre)\s+.*prompt",  # noqa: E501
        "SYSTEM_PROMPT": r"system\s+prompt|prompt\s+syst[eè]me",
        "EXTRACT_INSTRUCTIONS": r"(?:what\s+are|donne\s+moi|liste|r[eé]v[eè]le)\s+.*instructions?",  # noqa: E501
        "DATA_LEAK": r"(?:liste|donne|show)\s+.*(?:patients?|utilisateurs?|employ[eé]s?)",  # noqa: E501
        "LIST_ACTION": r"liste\s+(?:tous|all|les)",
        "SHOW_CONTEXT": r"(?:montre\s+(?:moi\s+)?le\s+contexte|what\s+is\s+in\s+your\s+context)",  # noqa: E501
        # Catégorie : jailbreak connus
        "DAN_MODE": (
            r"(?:\bDAN\b(?:\s*(?:mode|prompt))?|mode\s+\bDAN\b|\bjailbreak\b)"
        ),
        "ROLEPLAY_ESCAPE": r"(?:in\s+this\s+roleplay|for\s+a\s+(?:story|novel)|dans\s+(?:cette\s+)?fiction|pour\s+(?:une\s+)?histoire)",  # noqa: E501
        # Contournements FR : terminal / levée de garde sécurité (ANSSI R25)
        "LINUX_TERMINAL_FR": (
            r"agis\s+comme\s+(?:un\s+)?(?:terminal|shell)\s+(?:linux|unix|bash)?"
        ),
        "SANS_RESTRICTION_SECURITE_FR": (
            r"sans\s+(?:aucune\s+)?restrictions?\s+(?:de\s+)?s[eé]curit[eé]"
        ),
        "RESTRICTION_SECURITE_PHRASE_FR": (
            r"restriction\s+(?:de\s+)?(?:la\s+)?s[eé]curit[eé]"
        ),
        "CONTEXT_DELIMITER": (
            r"(?:<\|(?:im_start|im_end|system|user|assistant)\|>"
            r"|<s>|</s>|\[INST\]|\[/INST\])"
        ),
        "TRAINING_EXTRACT": (
            r"(?:repeat|rép[eè]te|repete|recopie|reproduis)\s+"
            r"(?:tes|vos|les|ta)\s+"
            r"(?:donn[eé]es|donnees|exemples|training|dataset|documents?)"
        ),
        "PROMPT_STUFFING": (
            r"(?:ignore|oublie|skip|bypass).{0,30}"
            r"(?:filtre|filter|s[eé]curit[eé]|security|restriction|guard)"
        ),
        "CODE_INJECTION": (
            r"(?:eval|exec|subprocess|os\.system|shell_exec)\s*\("
        ),
        "SOCIAL_ENGINEERING": (
            r"(?:fais\s+semblant|pretend|imagine\s+que\s+tu\s+es|"
            r"tu\s+es\s+maintenant\s+libre|sans\s+restrictions|"
            r"mode\s+d[eé]veloppeur|dev\s+mode)"
        ),
        # Catégorie : encodages suspects
        "BASE64_INJECT": r"[a-zA-Z0-9+/]{40,}={0,2}",
        "GZIP_PAYLOAD": r"H4sI[a-zA-Z0-9+/]{20,}={0,2}",
        "URL_ENCODING_OBFUSQUE": r"(?:%[0-9A-Fa-f]{2}){5,}",
        "UNICODE_ESCAPE": r"\\u[0-9a-fA-F]{4}",
        # Catégorie : manipulation de contexte
        "END_INSTRUCTIONS": r"(?:###|\-\-\-|\[/INST\]|</s>|<\|im_end\|>)",
        "SYSTEM_OVERRIDE": r"(?:\[SYSTEM\]|<<SYS>>|<system>)",
    }

    def __init__(self, config: DetectorConfig):
        super().__init__(config)
        self._compiled = {}
        self._score_per_match = float(self.config.extra.get("score_per_match", 1.0))

        # Compilation des patterns builtin
        for name, pattern in self.INJECTION_PATTERNS.items():
            self._compiled[name] = re.compile(pattern, re.IGNORECASE | re.UNICODE)

        # Compilation des patterns custom
        custom_patterns = self.config.extra.get("custom_patterns", {})
        for name, pattern in custom_patterns.items():
            try:
                self._compiled[name] = re.compile(pattern, re.IGNORECASE | re.UNICODE)
            except re.error as e:
                raise ValueError(f"Pattern d'injection custom '{name}' invalide: {e}")

    @safe_analyze
    def analyze(self, text: str) -> DetectionEvent:
        """
        Analyse le texte contre tous les patterns d'injection connus.
        Retourne un score cumulatif si des patterns sont détectés.
        """
        matched_names = self.get_matched_patterns(text)

        if not matched_names:
            return self._make_event(matched=False, score=0.0)

        # Un match suffit pour un score 1.0 (veto BLOCK en agrégation).
        score = min(len(matched_names) * self._score_per_match, 1.0)

        # Formate l'évidence avec max 3 noms
        evidence = ", ".join(matched_names[:3])

        return self._make_event(
            matched=True,
            score=score,
            evidence=evidence,
            trigger_type="PROMPT_INJECTION",
        )

    def get_matched_patterns(self, text: str) -> list[str]:
        """
        Retourne la liste des noms des patterns qui matchent sur le texte.
        """
        norm = _normalize_injection_text(text)
        matched = []
        for name, compiled_regex in self._compiled.items():
            if compiled_regex.search(norm):
                matched.append(name)
        return matched

    def find_all_candidates(self, text: str) -> list[dict]:
        """Retourne TOUTES les occurrences d'injection détectées."""
        norm = _normalize_injection_text(text)
        candidates = []
        for name, compiled_regex in self._compiled.items():
            for m in compiled_regex.finditer(norm):
                candidates.append({
                    "matched": m.group(),
                    "score": self._score_per_match,
                    "reason": name
                })
        return candidates
