# scoring.py — Logique de calcul des scores de conformité et de risque

from colandix.redaction import get_redaction_tag
from colandix.result import Action, DetectionEvent

# Constantes de seuils selon le plan de conformité
DECISION_THRESHOLDS = {
    Action.BLOCK: 0.85,
    Action.HUMAN_REVIEW: 0.60,
    Action.WARN: 0.30,
}


def aggregate_score(events: list[DetectionEvent]) -> tuple[float, Action]:
    """
    Agrège les résultats de tous les détecteurs en une décision finale.

    Règles :
    1. Veto immédiat si un événement matché a action ``BLOCK`` et score >= 0,9.
    2. Seuils 0,85 / 0,60 / 0,30 appliqués **par famille d'action** du détecteur :
       d'abord les scores des détecteurs ``BLOCK``, puis ``HUMAN_REVIEW``,
       puis ``WARN``. Un signal ``human_review`` ne fait pas monter seul vers ``BLOCK``.
    3. Sinon, retour du score max observé avec ``PASS``.
    """
    if not events:
        return 0.0, Action.PASS

    matched = [e for e in events if e.matched]
    if not matched:
        return 0.0, Action.PASS

    for event in matched:
        if event.action == Action.BLOCK and event.score >= 0.9:
            return event.score, Action.BLOCK

    def max_score_for(actions: set[Action]) -> float:
        scores = [e.score for e in matched if e.action in actions]
        return max(scores) if scores else -1.0

    ms_block = max_score_for({Action.BLOCK})
    if ms_block >= DECISION_THRESHOLDS[Action.BLOCK]:
        return ms_block, Action.BLOCK

    ms_hr = max_score_for({Action.HUMAN_REVIEW})
    if ms_hr >= DECISION_THRESHOLDS[Action.HUMAN_REVIEW]:
        return ms_hr, Action.HUMAN_REVIEW

    ms_warn = max_score_for({Action.WARN})
    if ms_warn >= DECISION_THRESHOLDS[Action.WARN]:
        return ms_warn, Action.WARN

    return max(e.score for e in matched), Action.PASS


_MIN_MASK_FRAGMENT_LEN = 3


def _add_spans_for_literal(
    text: str,
    literal: str,
    tag: str,
    spans: list[tuple[int, int, str]],
) -> None:
    if len(literal) < _MIN_MASK_FRAGMENT_LEN:
        return
    start = 0
    while True:
        idx = text.find(literal, start)
        if idx == -1:
            break
        spans.append((idx, idx + len(literal), tag))
        start = idx + 1


def _mask_fragments_from_event(event: DetectionEvent) -> list[str]:
    """
    Déduit des sous-chaînes littérales à remplacer depuis ``evidence``.
    Injection / entropie : preuves non fiables pour un replace exact — ignorées.
    """
    if not event.matched or not event.evidence:
        return []
    ev = event.evidence
    if ev.startswith("ERROR:"):
        return []

    dt = event.detector_type
    out: list[str] = []

    if dt == "RegexDetector":
        # Preuve standard : ``MOTIF: valeur`` (souvent ``: `` après le nom de motif).
        if ": " in ev:
            frag = ev.split(": ", 1)[1].strip()
        elif ":" in ev:
            frag = ev.split(":", 1)[1].strip()
        else:
            frag = ""
        if frag:
            out.append(frag)
    elif dt == "NERDetector":
        for part in ev.split(","):
            piece = part.strip()
            if ":" in piece:
                tail = piece.split(":", 1)[1].strip()
                if tail:
                    out.append(tail)
    elif dt == "TopicDetector":
        prefix = "topic bloqué:"
        if ev.lower().startswith(prefix):
            frag = ev[len(prefix) :].strip()
            if frag:
                out.append(frag)

    return out


def apply_redactions(
    text: str,
    events: list[DetectionEvent],
    placeholder: str | None = None,
) -> str:
    """
    Remplace des fragments détectés par des tags typés (ou ``placeholder``).

    - Priorité : ``match_text`` (toutes les occurrences), sinon fragments issus
      de ``_mask_fragments_from_event`` (ex. preuves NER / topic).
    - ``InjectionDetector`` et ``EntropyDetector`` ne modifient pas le texte.
    - Les spans qui se chevauchent sont fusionnés (le plus large l'emporte).
    """
    spans: list[tuple[int, int, str]] = []

    for event in events:
        if not event.matched:
            continue
        if event.detector_type in ("InjectionDetector", "EntropyDetector"):
            continue

        if placeholder is not None:
            tag = placeholder
        else:
            tag = get_redaction_tag(event.trigger_type)

        mt = getattr(event, "match_text", None)
        if mt is not None and len(mt) >= _MIN_MASK_FRAGMENT_LEN:
            _add_spans_for_literal(text, mt, tag, spans)
        else:
            for frag in _mask_fragments_from_event(event):
                _add_spans_for_literal(text, frag, tag, spans)

    if not spans:
        return text

    spans.sort(key=lambda s: s[0])
    merged: list[tuple[int, int, str]] = []
    for start, end, tag in spans:
        if merged and start < merged[-1][1]:
            prev_start, prev_end, prev_tag = merged[-1]
            merged[-1] = (prev_start, max(prev_end, end), prev_tag)
        else:
            merged.append((start, end, tag))

    result = text
    for start, end, tag in reversed(merged):
        result = result[:start] + tag + result[end:]
    return result


def _suffixe_preuve(evidence: str | None) -> str:
    """Ajoute l'extrait / preuve du détecteur (tronquée côté DetectionEvent, max 50)."""
    if evidence:
        return f" | détail : {evidence}"
    return ""


def explain_decision(events: list[DetectionEvent], action: Action) -> str:
    """
    Génère un message lisible expliquant la décision finale pour les audits.
    """
    matched_events = [e for e in events if e.matched]
    if not matched_events or action == Action.PASS:
        return "Aucun problème détecté"

    # On identifie l'événement le plus significatif (score max)
    main_event = max(matched_events, key=lambda e: e.score)

    if action == Action.BLOCK:
        return (
            f"Bloqué : {main_event.detector_name} ({main_event.anssi_ref}) "
            f"avec score {main_event.score:.2f}"
            f"{_suffixe_preuve(main_event.evidence)}"
        )
    elif action == Action.HUMAN_REVIEW:
        # On calcule le score global pour le message
        score, _ = aggregate_score(events)
        return (
            f"Review humaine requise : score agrégé {score:.2f} "
            f"({main_event.detector_name} {main_event.score:.2f})"
            f"{_suffixe_preuve(main_event.evidence)}"
        )
    elif action == Action.WARN:
        return (
            f"Avertissement : {main_event.detector_name} détecté "
            f"(score {main_event.score:.2f})"
            f"{_suffixe_preuve(main_event.evidence)}"
        )

    return "Aucun problème détecté"
