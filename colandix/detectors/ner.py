# ner.py — Détecteur basé sur la reconnaissance d'entités nommées via SpaCy

from __future__ import annotations

from typing import Any, Optional

from colandix.detectors.base import BaseDetector, DetectorConfig, safe_analyze
from colandix.result import Action, DetectionEvent

try:
    import spacy

    SPACY_AVAILABLE = True
except ImportError:
    SPACY_AVAILABLE = False
    spacy = None  # type: ignore[assignment,misc]


FR_CORE_MODEL = "fr_core_news_md"

# Formes souvent étiquetées PER à tort par les modèles généralistes (impératifs, etc.).
DEFAULT_PER_SPAN_BLACKLIST = frozenset(
    {
        "veuillez",
        "merci",
        "bonjour",
        "cordialement",
        "monsieur",
        "madame",
        "mademoiselle",
        "cher",
        "chère",
        "salut",
        "bonsoir",
        "notamment",
        "conformément",
        "suite",
        "objet",
        "référence",
        "reference",
        "concerne",
        "ci-joint",
        "ci-jointe",
        "ci-dessous",
        "ci-dessus",
        "fac",
        "ref",
        "doc",
        "info",
    }
)

# Labels SpaCy « personne » selon les pipelines (FR/DE/… vs EN).
PERSON_ENTITY_LABELS = frozenset({"PER", "PERSON"})


class NERDetector(BaseDetector):
    """
    Détecteur basé sur la reconnaissance d'entités nommées (NER) via SpaCy.
    ``combo_threshold`` = nombre minimal de **types** d'entités distincts parmi
    ``entities`` (ex. PER, DATE, LOC) requis pour déclencher. Dès que le seuil
    est atteint, le score est **1.0** ; l'action sur l'événement suit le YAML
    **sauf** pour ``block`` : une alerte NER ne produit **jamais**
    ``Action.BLOCK`` par défaut (contrôle humain / R27) ; elle est ramenée à
    ``human_review``. Pour forcer un blocage explicite depuis le NER, utilisez
    ``extra: { ner_allow_block: true }`` (cas rare).
    Les spans **personne** (`PER`, `PERSON`, …) listés dans la liste noire
    (défaut + ``extra.span_blacklist``)
    sont ignorés.

    Modèle : par défaut ``fr_core_news_md``. Autre pipeline SpaCy via
    ``extra: { model: "en_core_web_md", ... }`` (adapter ``entities`` :
    l'anglais utilise souvent ``PERSON`` au lieu de ``PER``).
    """

    _nlp_instances: dict[str, Any] = {}
    _nlp_load_attempted: set[str] = set()

    @classmethod
    def _try_load_model(cls, model_name: str) -> Optional[Any]:
        """Charge un pipeline SpaCy par nom, une seule fois par modèle."""
        if model_name in cls._nlp_instances:
            return cls._nlp_instances[model_name]
        if model_name in cls._nlp_load_attempted:
            return None
        cls._nlp_load_attempted.add(model_name)
        try:
            nlp = spacy.load(model_name)
            cls._nlp_instances[model_name] = nlp
            return nlp
        except OSError:
            print(
                f"[colandix] WARNING: Modèle SpaCy '{model_name}' introuvable. "
                "NERDetector désactivé pour ce modèle (aucune analyse d'entités). "
                f"Installez : python -m spacy download {model_name}"
            )
            return None

    @classmethod
    def reset_model_cache_for_tests(cls) -> None:
        """Réinitialise le cache NLP (tests uniquement)."""
        cls._nlp_instances.clear()
        cls._nlp_load_attempted.clear()

    @classmethod
    def is_fr_core_model_loaded(cls) -> bool:
        """True si le modèle français par défaut est chargé dans ce processus."""
        return cls._nlp_instances.get(FR_CORE_MODEL) is not None

    @classmethod
    def is_model_loaded(cls, model_name: str) -> bool:
        """True si le pipeline ``model_name`` a été chargé avec succès."""
        return cls._nlp_instances.get(model_name) is not None

    @property
    def is_fr_core_model_active(self) -> bool:
        """True si ce détecteur exécutera réellement le NER (SpaCy + modèle OK)."""
        return self._spacy_available

    def __init__(self, config: DetectorConfig):
        super().__init__(config)
        self._model_name = str(self.config.extra.get("model", FR_CORE_MODEL))
        self._entities = self.config.extra.get("entities", ["PER", "ORG", "LOC"])
        self._combo_threshold = int(self.config.extra.get("combo_threshold", 2))
        self._max_text_length = int(self.config.extra.get("max_text_length", 1000))
        extra_bl = self.config.extra.get("span_blacklist") or []
        if not isinstance(extra_bl, list):
            extra_bl = []
        self._per_span_blacklist = DEFAULT_PER_SPAN_BLACKLIST | frozenset(
            str(x).lower().strip() for x in extra_bl if x
        )

        if not SPACY_AVAILABLE:
            print("[colandix] WARNING: SpaCy non installé. NERDetector désactivé.")
            self._nlp = None
            self._spacy_available = False
        else:
            self._nlp = self._try_load_model(self._model_name)
            self._spacy_available = self._nlp is not None

    def _keep_per_span(self, span_text: str) -> bool:
        """Filtre les faux positifs évidents sur les entités personne."""
        t = span_text.strip()
        if len(t) < 2:
            return False
        if t.lower() in self._per_span_blacklist:
            return False
        # Sigles courts tout en majuscules (souvent faux PER)
        letters_only = "".join(c for c in t if c.isalpha())
        if letters_only.isupper() and len(letters_only) <= 4:
            return False
        return True

    def _apply_ner_action_policy(self, event: DetectionEvent) -> None:
        """
        Le NER identité ne doit pas court-circuiter la revue humaine par un
        ``block`` tant que ``ner_allow_block`` n'est pas demandé explicitement.
        """
        if not event.matched or event.action != Action.BLOCK:
            return
        if self.config.extra.get("ner_allow_block"):
            return
        event.action = Action.HUMAN_REVIEW

    @safe_analyze
    def analyze(self, text: str) -> DetectionEvent:
        """
        Déclenche si au moins ``combo_threshold`` types parmi ``entities`` sont
        présents. Score toujours **1.0** lors d'un match (pas de score fractionné).
        """
        if not self._spacy_available:
            return self._make_event(matched=False, score=0.0)

        nlp = self._nlp
        assert nlp is not None

        truncated_text = text[: self._max_text_length]
        doc = nlp(truncated_text)

        found_types = set()
        evidence_parts = []
        first_per_text: Optional[str] = None

        for ent in doc.ents:
            if ent.label_ not in self._entities:
                continue
            if ent.label_ in PERSON_ENTITY_LABELS and not self._keep_per_span(ent.text):
                continue
            found_types.add(ent.label_)
            evidence_parts.append(f"{ent.label_}:{ent.text[:15]}")
            if ent.label_ in PERSON_ENTITY_LABELS and first_per_text is None:
                first_per_text = ent.text

        matched_types = found_types.intersection(set(self._entities))

        if len(matched_types) >= self._combo_threshold:
            evidence = ", ".join(evidence_parts)
            event = self._make_event(
                matched=True,
                score=1.0,
                evidence=evidence,
                trigger_type="PERSON_NAME",
                match_text=first_per_text,
            )
            self._apply_ner_action_policy(event)
            return event

        return self._make_event(matched=False, score=0.0)

    def get_entities(self, text: str) -> dict[str, list[str]]:
        """
        Retourne TOUTES les entités trouvées sous forme de dict {label: [textes]}.
        Utile pour le debug et les tests.
        """
        if not self._spacy_available:
            return {}

        nlp = self._nlp
        assert nlp is not None

        truncated_text = text[: self._max_text_length]
        doc = nlp(truncated_text)

        entities: dict[str, list[str]] = {}
        for ent in doc.ents:
            if ent.label_ in PERSON_ENTITY_LABELS and not self._keep_per_span(ent.text):
                continue
            if ent.label_ not in entities:
                entities[ent.label_] = []
            entities[ent.label_].append(ent.text)

        return entities
    def find_all_candidates(self, text: str) -> list[dict]:
        """Retourne TOUTES les entités détectées comme candidats."""
        entities = self.get_entities(text)
        candidates = []
        for label, values in entities.items():
            for val in values:
                candidates.append({
                    "matched": val,
                    "score": 1.0,
                    "reason": label
                })
        return candidates
