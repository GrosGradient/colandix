class ColandixBlockedError(Exception):
    """
    Levée par GuardPipeline quand raise_on_block=True et qu'une
    requête est bloquée par un détecteur.

    Attributs :
        result : ScanResult — le résultat complet du scan
        message : str — message lisible du blocage
        anssi_ref : str — référence ANSSI concernée
    """

    def __init__(self, result, message: str, anssi_ref: str = "R25"):
        self.result = result
        self.message = message
        self.anssi_ref = anssi_ref
        super().__init__(f"[colandix] Requête bloquée ({anssi_ref}) : {message}")
