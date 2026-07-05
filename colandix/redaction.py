# redaction.py — Tags de masquage typés pour la sanitization

REDACTION_TAGS: dict[str, str] = {
    # Secrets / Credentials
    "API_KEY": "[API_KEY_REDACTED]",
    "TOKEN": "[TOKEN_REDACTED]",
    "PASSWORD": "[PASSWORD_REDACTED]",
    "PRIVATE_KEY": "[PRIVATE_KEY_REDACTED]",
    "DB_URL": "[DB_URL_REDACTED]",
    "JWT": "[JWT_REDACTED]",
    "SSH_KEY": "[SSH_KEY_REDACTED]",
    "TWILIO_SID": "[TWILIO_SID_REDACTED]",
    # PII
    "EMAIL": "[EMAIL_REDACTED]",
    "PHONE": "[PHONE_REDACTED]",
    "NIR": "[NIR_REDACTED]",
    "IBAN": "[IBAN_REDACTED]",
    "SIRET": "[SIRET_REDACTED]",
    "CARD": "[CARD_REDACTED]",
    "PASSPORT": "[PASSPORT_REDACTED]",
    "IP_ADDRESS": "[IP_REDACTED]",
    "PERSON_NAME": "[PERSON_REDACTED]",
    # Données métier
    "RH_DATA": "[RH_DATA_REDACTED]",
    "LEGAL_CLAUSE": "[LEGAL_REDACTED]",
    "HEALTH_ID": "[HEALTH_ID_REDACTED]",
    "TOPIC_BLOCKED": "[TOPIC_REDACTED]",
    "CRYPTO": "[CRYPTO_REDACTED]",
    # Fallback
    "GENERIC": "[REDACTED]",
}

DEFAULT_TAG = "[REDACTED]"


def get_redaction_tag(trigger_type: str | None) -> str:
    """Retourne le tag de remplacement pour un trigger_type donné."""
    if trigger_type is None:
        return DEFAULT_TAG
    return REDACTION_TAGS.get(trigger_type, DEFAULT_TAG)
