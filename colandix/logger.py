import hashlib
import json
import uuid
from datetime import datetime, timezone

from colandix.result import PipelineConfig, ScanDirection, ScanResult


class ColandixLogger:
    """
    Gère la journalisation structurée conforme R29 ANSSI.
    RGPD : Pseudonymisation des user_id et exclusion des textes originaux.
    """

    def __init__(self, config: PipelineConfig):
        self._config = config
        self._file_path: str | None = None

    def log(self, result: ScanResult, user_id: str | None = None):
        """
        Journalise les métadonnées d'un scan si activé dans la config.
        """
        # Filtrage selon la configuration
        if result.direction == ScanDirection.INPUT and not self._config.log_inputs:
            return
        if result.direction == ScanDirection.OUTPUT and not self._config.log_outputs:
            return

        # Construction de l'entrée de log (sans le texte original/sanitized)
        entry = {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "colandix_version": "0.1.0",
            "direction": result.direction.value,
            "user_id_hash": self._hash_user(user_id),
            "blocked": result.blocked,
            "action": result.action.value,
            "global_score": round(result.global_score, 3),
            "detections": [
                {
                    "detector": e.detector_name,
                    "type": e.detector_type,
                    "matched": e.matched,
                    "score": round(e.score, 3),
                    "action": e.action.value,
                    "anssi_ref": e.anssi_ref,
                    "evidence": e.evidence,
                }
                for e in result.events
                if e.matched
            ],
            "nb_detectors_run": len(result.events),
            "anssi_framework": "ANSSI-PA-102",
        }

        self._emit(entry)

    def to_file(self, path: str) -> "ColandixLogger":
        """Configure la sortie vers un fichier JSON Lines."""
        self._file_path = path
        return self

    def _hash_user(self, user_id: str | None) -> str | None:
        """Pseudonymise le user_id via SHA-256 (16 premiers caractères)."""
        if user_id is None:
            return None

        sha = hashlib.sha256(user_id.encode("utf-8")).hexdigest()
        return sha[:16]

    def _emit(self, entry: dict):
        """
        Diffuse l'entrée de log.
        Peut être surchargé pour envoyer vers Loki, OpenSearch, etc.
        """
        line = json.dumps(entry, ensure_ascii=False)

        if self._file_path is None:
            print(line)
        else:
            with open(self._file_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
