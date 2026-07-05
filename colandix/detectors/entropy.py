# entropy.py — Détecteur basé sur l'entropie (ex: obfuscation, clés crypto)

import math
import re
from typing import Optional

from colandix.detectors.base import BaseDetector, DetectorConfig, safe_analyze
from colandix.result import DetectionEvent


class EntropyDetector(BaseDetector):
    """
    Détecteur identifiant des secrets par analyse d'entropie de Shannon.
    Un secret aléatoire (clé API, token) a une distribution de caractères
    uniforme, ce qui donne une entropie élevée (ex: > 4.5 bits).
    Complété par détection de contexte (mot-clé + valeur) et ratio voyelles.
    """

    VOYELLES = frozenset("aeiouyAEIOUYàâéèêëîïôùûüœæ")
        
    CONTEXT_PATTERNS = [
        # Mot-clé + := ou = uniquement (pas d'espace seul comme séparateur).
        # Aligné spec « secrets » : séparateur structurel ; jeton / identifiant / mdp et
        # « mot de passe » (tiret, underscore ou espace) en bonus FR.
        re.compile(
            r"\b(?:password|passwd|pwd|secret|token|api[_-]?key|apikey"
            r"|access[_-]?key|private[_-]?key|client[_-]?secret"
            r"|auth[_-]?token|refresh[_-]?token|bearer|passphrase"
            r"|credential|mdp|mot[_\s]de[_\s]passe|clef?|jeton|identifiant)\s*[:=]\s*"
            r'["\']?(\S{8,})["\']?',
            re.IGNORECASE | re.UNICODE,
        ),
        re.compile(
            r"\bAuthorization\s*:\s*(?:Bearer|Token|Basic)\s+(\S{8,})",
            re.IGNORECASE | re.UNICODE,
        ),
        re.compile(
            r'["\'](?:password|secret|token|api_key|apikey|credential)'
            r'["\']\s*:\s*["\'](\S{8,})["\']',
            re.IGNORECASE | re.UNICODE,
        ),
        # Variable d'environnement SCREAMING_SNAKE (au moins 3 car. après la 1re lettre)
        re.compile(
            r"\b[A-Z][A-Z0-9_]{2,}(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD"
            r"|CREDENTIAL|AUTH|API|PWD)\s*=\s*[\"\']?(\S{8,})[\"\']?"
        ),
    ]

    ENTROPY_WHITELIST_PATTERNS = [
        re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}", re.IGNORECASE),  # UUID
        re.compile(r"^https?://", re.IGNORECASE),  # URL
        re.compile(r"^[0-9a-f]{32}$", re.IGNORECASE),  # MD5 pur
    ]

    def __init__(self, config: DetectorConfig):
        super().__init__(config)
        self._threshold = float(self.config.extra.get("threshold", 4.5))
        self._min_length = int(self.config.extra.get("min_length", 20))
        self._max_length = int(self.config.extra.get("max_length", 500))

        # Construit le pattern d'extraction de tokens
        self._token_pattern = re.compile(
            rf"[a-zA-Z0-9+/=_\-\.]{{{self._min_length},{self._max_length}}}", re.UNICODE
        )

    def _shannon_entropy(self, s: str) -> float:
        """Calcule l'entropie de Shannon d'une chaîne de caractères."""
        if not s or len(s) <= 1:
            return 0.0

        counts: dict[str, int] = {}
        for char in s:
            counts[char] = counts.get(char, 0) + 1

        length = len(s)
        entropy = 0.0
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)

        return entropy

    def _extract_tokens(self, text: str) -> list[str]:
        """Extrait les tokens candidats du texte."""
        tokens = []
        for match in self._token_pattern.finditer(text):
            token = match.group(0)
            if self._min_length <= len(token) <= self._max_length:
                tokens.append(token)
        return tokens

    def _detect_context(self, text: str) -> tuple[bool, Optional[str]]:
        """
        Mot-clé de secret suivi d'une valeur.
        Retourne (True, valeur[:30]) ou (False, None).
        """
        for pattern in self.CONTEXT_PATTERNS:
            m = pattern.search(text)
            if m:
                val = m.group(1)
                if val:
                    return True, val[:30]
        return False, None

    def _ratio_voyelles(self, s: str) -> float:
        """
        Ratio voyelles / lettres totales. 0.0 si aucune lettre.
        """
        lettres = [c for c in s if c.isalpha()]
        if not lettres:
            return 0.0
        return sum(1 for c in lettres if c in self.VOYELLES) / len(lettres)

    def _score_complexite(self, token: str) -> float:
        """
        Score de complexité structurelle (types de caractères × longueur).
        """
        if len(token) < 8 or " " in token:
            return 0.0

        has_lower = any("a" <= c <= "z" for c in token)
        has_upper = any("A" <= c <= "Z" for c in token)
        has_digit = any("0" <= c <= "9" for c in token)
        has_special = any(
            not (("a" <= c <= "z") or ("A" <= c <= "Z") or ("0" <= c <= "9"))
            for c in token
        )

        n_types = sum([has_lower, has_upper, has_digit, has_special])
        if n_types <= 1:
            score_base = 0.0
        elif n_types == 2:
            score_base = 0.25
        elif n_types == 3:
            score_base = 0.60
        else:
            score_base = 0.85

        ln = len(token)
        if ln <= 11:
            mult = 0.6
        elif ln <= 19:
            mult = 0.8
        else:
            mult = 1.0

        return score_base * mult

    def analyze_token(self, token: str) -> float:
        """Retourne l'entropie brute de Shannon d'un token."""
        return self._shannon_entropy(token)

    @safe_analyze
    def analyze(self, text: str) -> DetectionEvent:
        """
        Détecte les secrets en combinant plusieurs signaux :
        1. Contexte (mot-clé + valeur) — signal le plus fiable
        2. Entropie de Shannon — signal principal existant
        4. Complexité structurelle (types de caractères × longueur)
        5. Zone « grise » : entropie légèrement sous le seuil mais jeton long
           et forte complexité (clés avec caractères répétés, Shannon modéré)

        Ne fait jamais d'appel réseau. 100% local.
        """
        context_found, context_value = self._detect_context(text)
        if context_found and context_value is not None:
            return self._make_event(
                matched=True,
                score=1.0,
                evidence=f"contexte: {context_value}",
                trigger_type="PASSWORD",
            )

        tokens = self._extract_tokens(text)
        best_score = 0.0
        best_evidence: Optional[str] = None

        # Entropie Shannon sous le seuil mais proche : jeton long avec forte
        # hétérogénéité (types de caractères) — ex. clés avec répétitions
        # (entropie mesurée basse) mais toujours « random-looking ».
        gray_entropy_delta = 0.75
        gray_min_complexity = 0.60

        for token in tokens:
            entropy = self._shannon_entropy(token)

            for whitelist_pattern in self.ENTROPY_WHITELIST_PATTERNS:
                if whitelist_pattern.search(token):
                    entropy = entropy / 2.0
                    break

            score_complexite = self._score_complexite(token)
            rv = self._ratio_voyelles(token)

            gray_structural = (
                entropy > self._threshold - gray_entropy_delta
                and entropy <= self._threshold
                and len(token) >= self._min_length
                and score_complexite >= gray_min_complexity
            )

            if entropy <= self._threshold:
                if not gray_structural:
                    continue
                score_final = 0.75
                best_evidence = (
                    f"token:{token[:15]}.. e:{entropy:.2f} "
                    f"c:{score_complexite:.2f} gray"
                )
                best_score = max(best_score, score_final)
                continue

            score_entropie = min(
                (entropy - self._threshold) / (6.0 - self._threshold),
                1.0,
            )
            score_entropie = max(score_entropie, 0.0)

            if rv < 0.10:
                score_final = min(score_entropie * 1.20, 1.0)
            elif rv > 0.35:
                score_final = score_entropie * 0.60
            else:
                score_final = score_entropie

            score_combine = max(
                score_final,
                score_complexite,
                (score_final + score_complexite) / 2,
            )
            score_final = min(score_combine, 1.0)

            # Au-dessus du seuil d'entropie + jeton hétérogène (ex. clé sans préfixe
            # sk-) : le score combiné restait ~0,6 (review) malgré un signal fort.
            if (
                entropy > self._threshold
                and score_complexite >= 0.55
                and len(token) >= self._min_length
            ):
                score_final = max(score_final, 0.90)

            if score_final > best_score:
                best_score = score_final
                # Format compact pour tenir dans les 50 chars d'evidence
                best_evidence = f"token:{token[:15]}.. e:{entropy:.2f} v:{rv:.2f}"
                if score_complexite > 0.30:
                    best_evidence += f" c:{score_complexite:.2f}"

        if best_score > 0 and best_evidence:
            return self._make_event(
                matched=True,
                score=best_score,
                evidence=best_evidence,
                trigger_type="TOKEN",
            )

        return self._make_event(matched=False, score=0.0)
    def find_all_candidates(self, text: str) -> list[dict]:
        """Retourne TOUS les candidats détectés (contexte et entropie)."""
        candidates = []
        
        # 1. Contexte
        for pattern in self.CONTEXT_PATTERNS:
            for m in pattern.finditer(text):
                val = m.group(1)
                if val:
                    candidates.append({
                        "matched": val,
                        "score": 1.0,
                        "reason": "contexte"
                    })
        
        # 2. Tokens (Entropie)
        tokens = self._extract_tokens(text)
        gray_entropy_delta = 0.75
        gray_min_complexity = 0.60
        
        for token in tokens:
            entropy = self._shannon_entropy(token)
            for whitelist_pattern in self.ENTROPY_WHITELIST_PATTERNS:
                if whitelist_pattern.search(token):
                    entropy = entropy / 2.0
                    break
            
            score_complexite = self._score_complexite(token)
            rv = self._ratio_voyelles(token)
            
            gray_structural = (
                entropy > self._threshold - gray_entropy_delta
                and entropy <= self._threshold
                and len(token) >= self._min_length
                and score_complexite >= gray_min_complexity
            )
            
            score_final = 0.0
            reason = "entropie"
            
            if entropy <= self._threshold:
                if gray_structural:
                    score_final = 0.75
                    reason = "gray_structural"
            else:
                score_entropie = min(
                    (entropy - self._threshold) / (6.0 - self._threshold), 1.0
                )
                score_entropie = max(score_entropie, 0.0)
                if rv < 0.10:
                    score_final = min(score_entropie * 1.20, 1.0)
                elif rv > 0.35:
                    score_final = score_entropie * 0.60
                else:
                    score_final = score_entropie
                
                score_combine = max(
                    score_final, score_complexite, (score_final + score_complexite) / 2
                )
                score_final = min(score_combine, 1.0)
                
                if (
                    entropy > self._threshold
                    and score_complexite >= 0.55
                    and len(token) >= self._min_length
                ):
                    score_final = max(score_final, 0.90)
            
            if score_final > 0:
                candidates.append({
                    "matched": token,
                    "score": score_final,
                    "reason": reason,
                    "entropy": round(entropy, 2),
                    "vowels": round(rv, 2),
                    "complexity": round(score_complexite, 2)
                })
                
        return candidates
