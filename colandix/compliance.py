from datetime import datetime, timezone

from colandix.detectors.base import BaseDetector
from colandix.redaction import REDACTION_TAGS
from colandix.result import Action

ANSSI_PA102_REQUIREMENTS: dict[str, dict] = {
    "R25": {
        "titre": "Filtrage des entrées et sorties",
        "description": (
            "Mettre en place des mécanismes de filtrage "
            "des données en entrée et en sortie du modèle"
        ),
        "obligatoire": True,
    },
    "R26": {
        "titre": "Maîtrise des interactions applicatives",
        "description": (
            "Maîtriser les interactions du système d'IA "
            "avec d'autres applications du SI"
        ),
        "obligatoire": True,
    },
    "R27": {
        "titre": "Contrôle humain des actions critiques",
        "description": (
            "Proscrire les actions automatisées critiques " "sans validation humaine"
        ),
        "obligatoire": True,
    },
    "R29": {
        "titre": "Journalisation des interactions",
        "description": (
            "Journaliser les interactions avec le système d'IA générative"
        ),
        "obligatoire": True,
    },
    "R31": {
        "titre": "Sécurisation des accès aux modules critiques",
        "description": (
            "Contrôler les accès aux composants critiques " "du système d'IA"
        ),
        "obligatoire": False,
    },
    "R34": {
        "titre": "Hébergement souverain",
        "description": (
            "Garantir qu'aucune donnée ne transite vers " "un tiers non maîtrisé"
        ),
        "obligatoire": False,
    },
}


def generate_report(
    detectors: list[BaseDetector], profile_name: str, version: str = "0.1.0"
) -> dict:
    """
    Génère un rapport de conformité ANSSI-PA-102 basé sur les détecteurs actifs.
    """
    # Étape 1 — Construire la carte de couverture
    coverage: dict[str, list[str]] = {}
    for detector in detectors:
        ref = detector.config.anssi_ref
        if ref not in coverage:
            coverage[ref] = []
        coverage[ref].append(detector.config.name)

    # Étape 2 — R29 est couverte par le logger (by design)
    if "R29" not in coverage:
        coverage["R29"] = ["ColandixLogger"]

    # Étape 3 — R34 est couverte par conception (zéro appel externe)
    if "R34" not in coverage:
        coverage["R34"] = ["by design — zéro appel externe"]

    # Étape 4 — R27 est couverte si au moins un détecteur a Action.HUMAN_REVIEW
    human_review_detectors = [
        d.config.name for d in detectors if d.config.action == Action.HUMAN_REVIEW
    ]
    if human_review_detectors and "R27" not in coverage:
        coverage["R27"] = human_review_detectors

    # Étape 5 — Construire les exigences
    exigences = {}
    for ref, req in ANSSI_PA102_REQUIREMENTS.items():
        detecteurs_couvrants = coverage.get(ref, [])
        exigences[ref] = {
            "titre": req["titre"],
            "description": req["description"],
            "obligatoire": req["obligatoire"],
            "status": "CONFORME" if detecteurs_couvrants else "NON COUVERT",
            "detecteurs": detecteurs_couvrants,
        }

    # Étape 6 — Conformité globale
    if exigences["R25"]["status"] == "NON COUVERT":
        conformite_globale = "NON CONFORME"
    elif all(
        exigences[ref]["status"] == "CONFORME"
        for ref, req in ANSSI_PA102_REQUIREMENTS.items()
        if req["obligatoire"]
    ):
        conformite_globale = "CONFORME"
    else:
        conformite_globale = "PARTIELLE"

    # Étape 7 — Recommandations
    recommandations = []
    for ref, req in ANSSI_PA102_REQUIREMENTS.items():
        if req["obligatoire"] and exigences[ref]["status"] == "NON COUVERT":
            if ref == "R27":
                recommandations.append(
                    "R27 non couverte : ajouter un détecteur avec "
                    "action=human_review dans le profil YAML"
                )
            elif ref == "R25":
                recommandations.append(
                    "R25 non couverte : ajouter au minimum un détecteur "
                    "de type regex ou injection"
                )
            else:
                recommandations.append(
                    f"{ref} non couverte : voir ANSSI-PA-102 pour les "
                    f"mesures requises"
                )

    return {
        "titre": "Rapport de conformité ANSSI-PA-102",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "colandix_version": version,
        "profil": profile_name,
        "appels_externes": 0,
        "souverain": True,
        "nb_detecteurs_actifs": len([d for d in detectors if d.config.enabled]),
        "exigences": exigences,
        "conformite_globale": conformite_globale,
        "recommandations": recommandations,
        "sanitization": {
            "tags_typés": True,
            "tags_disponibles": list(REDACTION_TAGS.keys()),
            "injection_sanitizable": False,
            "entropy_sanitizable": False,
        },
    }


def print_report(report: dict):
    """Affiche le rapport lisiblement dans le terminal."""
    print("═" * 50)
    print("  RAPPORT DE CONFORMITÉ ANSSI-PA-102")
    print(f"  colandix v{report['colandix_version']} — Gros Gradient")
    print("═" * 50)
    print(f"Profil        : {report['profil']}")
    print(
        f"Souverain     : {'✓' if report['souverain'] else '✗'} "
        f"({report['appels_externes']} appel externe)"
    )
    print(f"Détecteurs    : {report['nb_detecteurs_actifs']} actifs")
    print("\nEXIGENCES :")

    for ref, req in report["exigences"].items():
        icon = "✓" if req["status"] == "CONFORME" else "-"
        # Tronquage des détecteurs
        detects = req["detecteurs"]
        if not detects:
            detects_str = "[non couvert]"
        else:
            if len(detects) > 3:
                detects_str = f"[{', '.join(detects[:3])}, ...]"
            else:
                detects_str = f"[{', '.join(detects)}]"

        print(f"  {ref} {icon}  {req['titre']:<30} {detects_str}")

    print(f"\nCONFORMITÉ GLOBALE : {report['conformite_globale']}")
    print("─" * 50)

    if report["recommandations"]:
        print("RECOMMANDATIONS :")
        for rec in report["recommandations"]:
            print(f"  • {rec}")
        print("═" * 50)
    else:
        print("═" * 50)
