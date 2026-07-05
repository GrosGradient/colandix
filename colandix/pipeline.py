from colandix.compliance import generate_report
from colandix.detectors.base import BaseDetector
from colandix.exceptions import ColandixBlockedError
from colandix.logger import ColandixLogger
from colandix.profiles.loader import load_profile, load_profile_from_yaml
from colandix.result import Action, PipelineConfig, ScanDirection, ScanResult
from colandix.scoring import aggregate_score, apply_redactions, explain_decision


class GuardPipeline:
    """
    Point d'entrée principal pour la protection des flux LLM.
    Orchestre les détecteurs selon un profil métier.
    """

    def __init__(
        self,
        profile: str | None = None,
        profile_path: str | None = None,
        detectors: list[BaseDetector] | None = None,
        config: PipelineConfig | None = None,
        user_id: str | None = None,
    ):
        # Validation des paramètres source
        sources = [s for s in (profile, profile_path, detectors) if s is not None]
        if len(sources) > 1:
            raise ValueError(
                "Spécifiez exactement un parmi : profile=, profile_path=, "
                "ou detectors=. Plusieurs sources fournies simultanément."
            )
        if len(sources) == 0:
            raise ValueError(
                "Spécifiez au moins une source : profile='nom', "
                "profile_path='chemin.yaml', ou detectors=[...]"
            )

        # Chargement des détecteurs
        if profile:
            self.detectors = load_profile(profile)
            self._profile_name = profile
        elif profile_path:
            self.detectors = load_profile_from_yaml(profile_path)
            self._profile_name = profile_path
        else:
            self.detectors = detectors or []
            self._profile_name = "custom"

        # Stockage
        self.config = config if config is not None else PipelineConfig()
        self.user_id = user_id
        self._logger = ColandixLogger(self.config)
        self._scan_count = 0

    def ner_fr_core_status(self) -> list[dict]:
        """
        Indique si le modèle SpaCy demandé par chaque ``NERDetector`` est actif.

        Retourne une liste de dicts :
        ``{"detector_name": str, "model": str, "active": bool}``.
        ``model`` correspond à ``extra.model`` du YAML ou au défaut
        ``fr_core_news_md``. Liste vide si aucun détecteur NER n'est configuré.
        """
        from colandix.detectors.ner import NERDetector

        return [
            {
                "detector_name": d.config.name,
                "model": d._model_name,
                "active": d.is_fr_core_model_active,
            }
            for d in self.detectors
            if isinstance(d, NERDetector)
        ]

    def scan_input(self, text: str, user_id: str | None = None) -> ScanResult:
        """Analyse une requête utilisateur (Input)."""
        result = self._scan(text, ScanDirection.INPUT, user_id or self.user_id)
        if self.config.raise_on_block and result.blocked:
            anssi_ref = "R25"
            if result.anssi_refs_covered:
                anssi_ref = next(iter(result.anssi_refs_covered))

            raise ColandixBlockedError(
                result=result,
                message=result.reason or "Requête bloquée",
                anssi_ref=anssi_ref,
            )
        return result

    def scan_output(self, text: str, user_id: str | None = None) -> ScanResult:
        """Analyse une réponse du modèle (Output)."""
        result = self._scan(text, ScanDirection.OUTPUT, user_id or self.user_id)
        if self.config.raise_on_block and result.blocked:
            anssi_ref = "R25"
            if result.anssi_refs_covered:
                anssi_ref = next(iter(result.anssi_refs_covered))

            raise ColandixBlockedError(
                result=result,
                message=result.reason or "Réponse bloquée",
                anssi_ref=anssi_ref,
            )
        return result

    def _scan(
        self, text: str, direction: ScanDirection, user_id: str | None
    ) -> ScanResult:
        """Logique interne d'orchestration du scan."""
        self._scan_count += 1

        # Tronquer si nécessaire
        text_to_scan = text[: self.config.max_text_length]

        # Lancer tous les détecteurs activés
        events = []
        for detector in self.detectors:
            if detector.is_enabled():
                event = detector.analyze(text_to_scan)
                events.append(event)

        # Décision globale
        global_score, action = aggregate_score(events)
        sanitized_text = apply_redactions(text_to_scan, events)
        reason = explain_decision(events, action)

        # Construire le ScanResult
        result = ScanResult(
            direction=direction,
            original_text=text,  # texte ORIGINAL non tronqué
            sanitized_text=sanitized_text,
            blocked=(action == Action.BLOCK),
            action=action,
            global_score=global_score,
            events=events,
            reason=reason,
        )

        # Journaliser
        self._logger.log(result, user_id=user_id)

        return result
    def find_all_candidates(self, text: str) -> list[dict]:
        """
        Explore le texte et retourne TOUS les candidats détectés par TOUS
        les détecteurs actifs. Utile pour le debug et l'audit.
        """
        all_candidates = []
        for detector in self.detectors:
            if detector.is_enabled():
                candidates = detector.find_all_candidates(text)
                for c in candidates:
                    c["detector"] = detector.config.name
                    all_candidates.append(c)
        return all_candidates

    def compliance_report(self) -> dict:
        """Génère un rapport de conformité technique."""
        return generate_report(self.detectors, self._profile_name)

    def stats(self) -> dict:
        """Retourne les statistiques d'utilisation du pipeline."""
        return {
            "total_scans": self._scan_count,
            "profile": self._profile_name,
            "nb_detectors": len(self.detectors),
            "detector_names": [d.config.name for d in self.detectors],
        }

    def __repr__(self) -> str:
        return (
            f"GuardPipeline(profile='{self._profile_name}', "
            f"detectors={len(self.detectors)}, scans={self._scan_count})"
        )
