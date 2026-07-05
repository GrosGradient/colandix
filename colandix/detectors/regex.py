# regex.py — Détecteur basé sur des expressions régulières

import re

from colandix.detectors.base import BaseDetector, DetectorConfig, safe_analyze
from colandix.result import DetectionEvent


class RegexDetector(BaseDetector):
    """
    Détecteur cherchant des motifs précis via des expressions régulières.
    Fournit des motifs par défaut pour la conformité française.
    """

    BUILTIN_PATTERNS = {
        # Identifiants personnes (France)
        "NIR": r"\b[12]\s*[0-9]{2}\s*(?:0[1-9]|1[0-2]|20)\s*[0-9]{2}\s*[0-9]{3}\s*[0-9]{3}\s*[0-9]{2}\b",  # noqa: E501
        # US SSN (forme XXX-XX-XXXX uniquement ; plages invalides exclues)
        "SSN_US": r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b",
        # UK National Insurance Number
        "NINO_UK": (
            r"\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z](?:\s*[0-9]{2}){3}\s*[A-D]\b"
            r"|\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z][0-9]{6}[A-D]\b"
        ),
        # Avant EMAIL : URL DB souvent user:pass@host (faux positif email sinon)
        "DB_URL": (
            r"\b(?:postgresql|postgres|mysql|mongodb(?:\+srv)?|redis|mssql|sqlserver|"
            r"elasticsearch|amqps?|clickhouse)://[^\s'\"<>]{8,}\b"
        ),
        "EMAIL": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
        # Obfuscation type john[at]domain.tld (contournement filtre email)
        "EMAIL_OBFUSQUE": (
            r"\b[a-zA-Z0-9._%+-]+"
            r"(?:\s*\[at\]\s*|\s*\(at\)\s*|\s+at\s+)"
            r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
        ),
        "TEL_FR": r"(?<!\w)(?:(?:\+|00)33|0)\s*[1-9](?:[\s.-]*\d{2}){4}\b",
        # NANP (US/CA) — profil strict recommandé (faux positifs possibles ailleurs)
        "TEL_US": (
            r"(?<!\w)(?:\+?1[-.\s]?)?"
            r"\(?[2-9][0-9]{2}\)?[-.\s][2-9][0-9]{2}[-.\s][0-9]{4}\b"
        ),
        # TEL_INTL : E.164 sans espaces ; évite chevauchement +33 espacé (TEL_FR)
        "TEL_INTL": r"(?<!\d)\+[1-9][0-9]{7,14}(?!\d)",
        # Identifiants entreprises (France)
        "SIRET": r"\b[0-9]{14}\b",
        "SIREN": r"\b[0-9]{9}\b",
        "IBAN_FR": r"\bFR[0-9]{2}[0-9A-Z]{23}\b",
        # Twilio Account SID (AC + 32) — avant IBAN_GENERIQUE
        # (sinon "AC12…" matche IBAN)
        "TWILIO_SID": r"\bAC[a-zA-Z0-9]{32}\b",
        # IBAN hors France (ISO 13616 simplifié : pays + clé + BBAN alphanumérique)
        "IBAN_GENERIQUE": r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b",
        # Passeport français (2 chiffres + 2 lettres + 5 chiffres)
        "PASSEPORT_FR": r"\b[0-9]{2}[A-Z]{2}[0-9]{5}\b",
        # PAN 16 : Visa / Mastercard ; Amex 15 ch. → CARD_AMEX ;
        # Discover / UnionPay → CARD_DISCOVER_UNIONPAY
        "CARD_PAN": (
            r"\b(?:4[0-9]{3}|5[1-5][0-9]{2})"
            r"(?:[ -]?[0-9]{4}){3}\b"
        ),
        "CARD_AMEX": r"\b3[47][0-9]{2}[ -]?[0-9]{6}[ -]?[0-9]{5}\b",
        "CARD_DISCOVER_UNIONPAY": (
            r"\b(?:6011|65[0-9]{2}|62[0-9]{2})"
            r"(?:[ -]?[0-9]{4}){3}\b"
        ),
        "TVA_FR": r"\bFR[0-9A-Z]{2}[0-9]{9}\b",
        # Identifiants santé (France)
        "FINESS": r"\b[0-9]{9}\b",
        "RPPS": r"\b[0-9]{11}\b",
        # Sécurité technique
        "API_KEY_GENERIC": r"\b(?:api[_-]?key|apikey|api[_-]?token)\s*[:=]\s*['\"]?[a-zA-Z0-9\-_]{20,}['\"]?\b",  # noqa: E501
        # Préfixes type OpenAI / fournisseurs cloud (clé nue dans le texte)
        "API_KEY_SK": r"\bsk-[a-zA-Z0-9]{20,}\b",
        "GITHUB_TOKEN": r"\bghp_[a-zA-Z0-9]{36}\b",
        "GITLAB_TOKEN": (
            r"\bglpat-[a-zA-Z0-9\-_]{20,}\b"
        ),
        "ANTHROPIC_API_KEY": (
            r"\bsk-ant-[a-zA-Z0-9\-_]{40,}\b"
        ),
        "AWS_ACCESS_KEY_ID": r"\bAKIA[0-9A-Z]{16}\b",
        "AWS_SECRET_KEY": (
            r"\b(?:aws[_-]?secret[_-]?access[_-]?key|aws[_-]?secret)\s*[:=]\s*['\"]?"
            r"[A-Za-z0-9/+=]{40}"
            r"['\"]?"
        ),
        "SLACK_TOKEN": r"\bxoxb-[0-9A-Za-z\-]{50,}\b",
        "HUGGINGFACE_TOKEN": r"\bhf_[a-zA-Z0-9]{20,}\b",
        "STRIPE_SK": r"\bsk_live_[a-zA-Z0-9]{20,}\b",
        "STRIPE_PK": r"\bpk_live_[a-zA-Z0-9]{20,}\b",
        "GOOGLE_API_KEY": r"\bAIza[0-9A-Za-z\-_]{30,}\b",
        "NPM_TOKEN": r"\bnpm_[a-zA-Z0-9]{30,}\b",
        "JWT_JWS": (
            r"\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b"
        ),
        # Avant CREDENTIAL (sinon "Password=" matche d'abord le motif générique)
        "CONNECTION_STRING": (
            r"\bServer=[^;]{5,};Database=[^;]{3,};"
            r"(?:User\s+Id|User|Uid)=[^;]{3,};"
            r"(?:Password|Pwd)=[^;\s]+"
        ),
        "CREDENTIAL": (
            r"\b(?:password|passwd|pwd|pass|secret|token|key|login|username)\s*[:=]\s*"
            r"['\"]?\S{8,}['\"]?"
        ),
        # PEM : clé privée (RSA/EC/DSA/OpenSSH) ou certificat
        "PRIVATE_KEY_HEADER": (
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?(?:PRIVATE KEY|CERTIFICATE)-----"
        ),
        "SSH_KEY": (
            r"\bssh-(?:rsa|ed25519|ecdsa|dss)\s+AAAA[a-zA-Z0-9+/]{20,}"
        ),
        # Défense / Institutionnel
        "MARQUAGE_DR": r"\b(?:diffusion\s+restreinte|dr\s+[0-9]|igi\s+1300)\b",
        "IGI_1300": r"\bigi\s*1300\b",
        "CONFIDENTIEL_DEF": r"\bconfidentiel\s+d[eé]fense\b",
        # Réseau
        "IP_PRIVE": (
            r"\b(?:10\.[0-9]{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)"
            r"\.[0-9]{1,3}\.[0-9]{1,3}\b"
        ),
        # IPv6 : formes complètes et compressées (::), cf. RFC 4291 usages courants
        "IPV6": (
            r"(?<![:\w])"
            r"(?:"
            r"(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}"
            r"|(?:[0-9A-Fa-f]{1,4}:){1,7}:"
            r"|:(?::[0-9A-Fa-f]{1,4}){1,7}"
            r"|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}"
            r"|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}"
            r"|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}"
            r")"
            r"(?![:\w])"
        ),
        # Ethereum / Bitcoin (avant ALNUM_MIXED_12 pour priorité sur adresses)
        "CRYPTO_ETH": r"\b0x[0-9a-fA-F]{40}\b",
        "CRYPTO_BTC": (
            r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\b"
        ),
        # Jeton sans espace (≥12) avec minuscule ASCII, majuscule ASCII et chiffre.
        # Lookaheads (?-i:…) : le détecteur compile avec IGNORECASE ; il faut forcer
        # la casse pour distinguer vraiment a–z vs A–Z.
        "ALNUM_MIXED_12": (
            r"(?:^|(?<=\s))"
            r"(?=\S{12,})"
            r"(?=(?-i:\S*[a-z]))"
            r"(?=(?-i:\S*[A-Z]))"
            r"(?=\S*\d)"
            r"\S{12,}"
        ),
    }

    PATTERN_TO_TRIGGER: dict[str, str] = {
        "NIR": "NIR",
        "SSN_US": "NIR",
        "NINO_UK": "NIR",
        "EMAIL": "EMAIL",
        "EMAIL_OBFUSQUE": "EMAIL",
        "TEL_FR": "PHONE",
        "TEL_US": "PHONE",
        "TEL_INTL": "PHONE",
        "PASSEPORT_FR": "PASSPORT",
        "CARD_PAN": "CARD",
        "CARD_AMEX": "CARD",
        "CARD_DISCOVER_UNIONPAY": "CARD",
        "SIRET": "SIRET",
        "SIREN": "SIRET",
        "IBAN_FR": "IBAN",
        "IBAN_GENERIQUE": "IBAN",
        "TVA_FR": "SIRET",
        "FINESS": "HEALTH_ID",
        "RPPS": "HEALTH_ID",
        "API_KEY_GENERIC": "API_KEY",
        "API_KEY_SK": "API_KEY",
        "GITHUB_TOKEN": "TOKEN",
        "GITLAB_TOKEN": "TOKEN",
        "ANTHROPIC_API_KEY": "API_KEY",
        "AWS_ACCESS_KEY_ID": "API_KEY",
        "AWS_SECRET_KEY": "API_KEY",
        "SLACK_TOKEN": "TOKEN",
        "HUGGINGFACE_TOKEN": "TOKEN",
        "STRIPE_SK": "API_KEY",
        "STRIPE_PK": "API_KEY",
        "GOOGLE_API_KEY": "API_KEY",
        "NPM_TOKEN": "TOKEN",
        "TWILIO_SID": "TWILIO_SID",
        "JWT_JWS": "JWT",
        "SSH_KEY": "SSH_KEY",
        "CONNECTION_STRING": "DB_URL",
        "DB_URL": "DB_URL",
        "CREDENTIAL": "PASSWORD",
        "PRIVATE_KEY_HEADER": "PRIVATE_KEY",
        "IP_PRIVE": "IP_ADDRESS",
        "IPV6": "IP_ADDRESS",
        "CRYPTO_ETH": "CRYPTO",
        "CRYPTO_BTC": "CRYPTO",
        "ALNUM_MIXED_12": "TOKEN",
        "MARQUAGE_DR": "GENERIC",
        "IGI_1300": "GENERIC",
        "CONFIDENTIEL_DEF": "GENERIC",
    }

    def __init__(self, config: DetectorConfig):
        super().__init__(config)
        self._compiled = {}

        # Étape 1 — Déterminer quels patterns builtin activer
        requested_patterns = self.config.extra.get("patterns", [])
        if not requested_patterns:
            active_builtin = dict(self.BUILTIN_PATTERNS)
            for name in self.config.extra.get("exclude_patterns", []):
                active_builtin.pop(name, None)
        else:
            active_builtin = {}
            for name in requested_patterns:
                if name in self.BUILTIN_PATTERNS:
                    active_builtin[name] = self.BUILTIN_PATTERNS[name]
                else:
                    print(
                        f"[colandix] WARNING: Pattern builtin demandé inconnu '{name}'"
                    )

        # Étape 2 — Récupérer les patterns custom
        custom_patterns = self.config.extra.get("custom_patterns", {})

        # Étape 3 — Compiler tous les patterns
        all_patterns = {**active_builtin, **custom_patterns}
        for name, pattern in all_patterns.items():
            try:
                self._compiled[name] = re.compile(
                    pattern, re.IGNORECASE | re.UNICODE
                )
            except re.error as e:
                raise ValueError(f"Pattern regex invalide '{name}' : {e}")

    @safe_analyze
    def analyze(self, text: str) -> DetectionEvent:
        """
        Analyse le texte à la recherche de correspondances Regex.
        S'arrête et retourne au premier match trouvé.
        """
        for name, compiled_regex in self._compiled.items():
            match = compiled_regex.search(text)
            if match:
                evidence = f"{name}: {match.group()[:30]}"
                trigger = self.PATTERN_TO_TRIGGER.get(name, "GENERIC")
                return self._make_event(
                    matched=True,
                    score=1.0,
                    evidence=evidence,
                    trigger_type=trigger,
                    match_text=match.group(),
                )

        return self._make_event(matched=False, score=0.0)

    def find_all_candidates(self, text: str) -> list[dict]:
        """Retourne TOUS les matches de TOUS les motifs configurés."""
        candidates = []
        for name, compiled_regex in self._compiled.items():
            for match in compiled_regex.finditer(text):
                candidates.append({
                    "matched": match.group(),
                    "score": 1.0,
                    "reason": name
                })
        return candidates

    def get_active_patterns(self) -> list[str]:
        """Retourne la liste des patterns actifs."""
        return list(self._compiled.keys())
