# Architecture

This document describes `colandix` components. The core path is self-contained: no external services in main orchestration (`result.py`, `base.py`, `scoring.py`, `redaction.py`).

The **colandix** library does more than block: it **rewrites** text so you can still call the LLM with cleaned content. **`action`** (decision) and **`sanitized_text`** (rewrite) are separate pipeline outputs.

---

## 1. Data contract (`result.py`)

Central to the pipeline.

### Enums

#### `Action` — two meanings

1. **In YAML** (`action:` per detector): category of signal when that detector **matches**. Copied to **`DetectionEvent.action`** (if no match: `PASS`, score 0).
2. **On pipeline result**: **`ScanResult.action`** comes only from **`aggregate_score()`** over **all** matched events. Integrators typically branch on this with [`Action`](https://github.com/GrosGradient/colandix/blob/main/colandix/result.py).

Enum values (severity hint):

| Value | Role |
| :--- | :--- |
| `PASS` | No alert at this level (unmatched event) or global decision: threshold not reached. |
| `WARN` | Light alert; aggregation uses **warn tier** only (global threshold **0.30** on max warn scores). |
| `HUMAN_REVIEW` | Human queue (R27); **HR tier** threshold **0.60**. Typical: NER / entropy on **`strict`**, **`sante`**, **`rh`**. |
| `BLOCK` | Hard stop; **veto** if matched event has **`Action.BLOCK`** and **score ≥ 0.90**, else max **block** scores **≥ 0.85** → **`ScanResult.action == BLOCK`**, **`ScanResult.blocked is True`**. |

#### `ScanDirection`
**INPUT** (user → model) or **OUTPUT** (model → user).

### Main dataclasses

* **`DetectionEvent`**: one per detector; audit fields: `detector_type`, `matched`, `score`, `action` (from YAML when matched), `evidence`, **`trigger_type`** (semantic family for redaction tag), `anssi_ref`.
    * **GDPR**: `evidence` **truncated to 50 chars** in `__post_init__`.
    * **`match_text`** (optional): full span for masking (regex; first **person** span for NER: **`PER`** or **`PERSON`**). Not truncated, **not logged**.
* **`ScanResult`**: **`action`** and **`global_score`** from aggregator; **`blocked`** ≡ **`action == BLOCK`** ([`pipeline.py`](https://github.com/GrosGradient/colandix/blob/main/colandix/pipeline.py)). **`original_text`**: argument to `scan_*` **without** truncation. **`sanitized_text`**: analyzed slice (`text[:max_text_length]`) after **`apply_redactions`** (masking runs regardless of per-event `action`). Derived: `is_clean`, `matched_events`, `anssi_refs_covered`, `has_blocked_action`.

---

## 2. Detector architecture (`base.py`, `regex.py`)

### `DetectorConfig` and `BaseDetector` (`base.py`)
* **`DetectorConfig`**: business config (name, recommended action, weight); weight clamped 0.0–1.0.
* **`BaseDetector`**: abstract base with **`_make_event()`** for standard alerts.
* **`@safe_analyze`**: wraps `analyze()`; catches detector exceptions so inference **never** crashes on a bad regex.

### `RegexDetector` (`regex.py`)
Regex-first detector for ANSSI-PA-102 style sovereign filtering.
* **Builtins** (order matters: e.g. **`DB_URL`** before **`EMAIL`** for `user:pass@host`; **`TWILIO_SID`** before **`IBAN_GENERIQUE`**; **`CONNECTION_STRING`** before **`CREDENTIAL`**, …): NIR, **SSN_US**, **NINO_UK**, **DB_URL** (Postgres, MySQL, MongoDB, Redis, SQL Server, Elasticsearch, AMQP(S), ClickHouse, …), EMAIL, **EMAIL_OBFUSQUE**, FR phone (+33, E.164 **`+336…`** before **`TEL_INTL`**), **`TEL_INTL`**, **`TEL_US`** (exhaustive profiles, not **`generique`**), SIRET/SIREN, **IBAN_FR**, **TWILIO_SID**, **IBAN_GENERIQUE**, **PASSEPORT_FR**, **CARD_PAN**, **CARD_AMEX**, **CARD_DISCOVER_UNIONPAY**, VAT, FINESS, RPPS, API keys and tokens (GitHub, GitLab, Anthropic, AWS access + secret, Slack, HF, Stripe, Google, npm, JWT, …), **CONNECTION_STRING**, **CREDENTIAL**, **PRIVATE_KEY_HEADER**, **SSH_KEY**, markings, **IP_PRIVE**, **IPv6**, **CRYPTO_ETH** / **CRYPTO_BTC** (before **`ALNUM_MIXED_12`**), **ALNUM_MIXED_12**, etc.
* Each match sets **`match_text`** and **`trigger_type`** for `apply_redactions` / [`redaction.py`](https://github.com/GrosGradient/colandix/blob/main/colandix/redaction.py).
* Human-readable summary: [triggers-par-profil.md](triggers-par-profil.md).
* **`exclude_patterns`**: when **`patterns`** is omitted (all builtins), optional list of keys to drop — e.g. **`strict`**: **`pii_complet`** drops **`ALNUM_MIXED_12`**, handled by second **`jeton_alnum_mixed`** **`RegexDetector`** in **`human_review`**.
* **First match return**: stops after first hit for latency.

### `EntropyDetector` (`entropy.py`)
Heuristic secret detection without a static dictionary.
* **Context (`CONTEXT_PATTERNS`)**: keyword + value with **`:` or `=`** (EN/FR secret vocabulary), **`Authorization: Bearer|Token|Basic`**, inline JSON `"password": "…"`, sensitive **SCREAMING_SNAKE** env with **≥3** chars after first letter before suffix → score **1.0** if match.
* **Shannon entropy** on extracted tokens; configurable threshold (e.g. > 4.5).
* **Vowel ratio** modulates entropy score.
* **Whitelist**: UUID, URL, bare MD5 halves analyzed entropy.
* **`analyze_token`**: raw Shannon only (no composite score).
* **Structural complexity (`_score_complexite`)**: charset mix + length multiplier. **Final** non-context score combines modulated entropy and complexity (**`max(score_final, score_complexite, mean)`**); **`complexity=…`** in evidence past ~0.30.
* **`gray_structural`**: entropy slightly below threshold but long heterogeneous token → score **0.75** (avoids pure entropy **BLOCK** near **`ALNUM_MIXED_12`**); high entropy + high complexity can reach **≥ 0.90**.
* Matched events: **`trigger_type`** **`PASSWORD`** (context) or **`TOKEN`** (entropy/complexity). **No** **`sanitized_text`** effect (`apply_redactions` skips **`EntropyDetector`**).

### `NERDetector` (`ner.py`)
SpaCy NER. Default model **`fr_core_news_md`**; override **`extra.model`** (e.g. **`en_core_web_md`**, **`de_core_news_md`**). Per-model caches in one process.

**Download (one package per command):**

| Language | Model | Command |
| :--- | :--- | :--- |
| French (default) | `fr_core_news_md` | `python -m spacy download fr_core_news_md` |
| English | `en_core_web_md` | `python -m spacy download en_core_web_md` |
| German | `de_core_news_md` | `python -m spacy download de_core_news_md` |
| Spanish | `es_core_news_md` | `python -m spacy download es_core_news_md` |
| Italian | `it_core_news_md` | `python -m spacy download it_core_news_md` |
| Portuguese | `pt_core_news_md` | `python -m spacy download pt_core_news_md` |

* **Person label**: **`xx_core_news_*`** → **`PER`**; **`en_core_web_*`** → **`PERSON`**. Set **`entities`** in YAML accordingly.
* **Masking**: first **person** span in **`match_text`**; tag **`[PERSON_REDACTED]`** (see [`redaction.py`](https://github.com/GrosGradient/colandix/blob/main/colandix/redaction.py)).
* **Combo**: fires if at least **`combo_threshold`** distinct **`entities`** types appear. **`strict`** / **`sante`**: identity-focused **`PER`**; **`rh`**: **`PER`** + **`ORG`**. Internal score **1.0** on match; final scan action from YAML + **`aggregate_score`**.
* **Advanced tuning**: e.g. **`combo_threshold: 2`** with **`entities: ["PER", "LOC"]`** for person+place (not default shipped YAML).
* **Person span filter**: default blacklist + **`extra.span_blacklist`**; ignores short ALLCAPS acronyms.
* **Graceful degradation**: missing SpaCy or model: **WARNING** on first load for that model, then NER no-op (no pipeline crash).
* **Diagnostics**: `GuardPipeline.ner_fr_core_status()`; `NERDetector.is_fr_core_model_loaded()`; `NERDetector.is_model_loaded(name)`.
* **Action policy**: NER **`block`** in YAML becomes **`human_review`** unless **`extra.ner_allow_block: true`**.
* On match: **`trigger_type="PERSON_NAME"`**, **`match_text`** = first retained **person** span.

English NER YAML example:

```yaml
- type: NERDetector
  name: identite_ner_en
  action: human_review
  extra:
    model: en_core_web_md
    entities: ["PERSON", "ORG"]
    combo_threshold: 1
```

### `InjectionDetector` (`injection.py`)
Prompt manipulation patterns.
* **Categories**: reset phrases EN/FR (**`ignore`**, **`forget`**, **`disregard`**, …) and **DE/ES/PT/IT** (**`RESET_*`**), multilingual **`NEW_PERSONA`**, jailbreak **`DAN_MODE`** (word-boundary limits), **`CONTEXT_DELIMITER`**, training / stuffing / eval, Base64, gzip **`H4sI…`**, URL **`%XX`** runs, `\uXXXX`, block endings, **`[SYSTEM]`** / **`<<SYS>>`**, … Details: [triggers-par-profil.md](triggers-par-profil.md).
* **Score**: default **1.0 per category** on normalized text; **`trigger_type="PROMPT_INJECTION"`**; no masking in `apply_redactions`.

### `TopicDetector` (`topic.py`)
Keeps exchanges in a defined domain (R26 angle).
* **`allowed`** / **`blocked`** keyword lists.
* **Scores**: **`blocked`** match → **0.9**; **`allowed`** non-empty and **no** allowed keyword → **0.9** if YAML **`action: block`**, else **0.5** (warn path; alone may not yield aggregate **BLOCK**).
* **`trigger_type`**: **`TOPIC_BLOCKED`**; literal masking only when evidence looks like **`topic bloqué:`** …
* **Accent-insensitive** matching.
* **Explainability**: evidence names the keyword or missing allowed terms.

## 3. Rewriting and sanitization

### Tags (`redaction.py`)

**`REDACTION_TAGS`** and **`get_redaction_tag(trigger_type)`** map semantic families to placeholders (e.g. `EMAIL` including **EMAIL_OBFUSQUE**, `PHONE`, `NIR` including **SSN_US** / **NINO_UK**, `CRYPTO` for ETH/BTC). Unknown or missing **`trigger_type`** → **`[REDACTED]`**. Package exports: `from colandix import get_redaction_tag, REDACTION_TAGS`.

### Masking scope (`apply_redactions` in `scoring.py`)

`apply_redactions` walks **matched** events and replaces spans with **`get_redaction_tag(event.trigger_type)`** unless **`placeholder`** is set (single replacement string). Result → **`ScanResult.sanitized_text`**; **`original_text`** unchanged.

**Detectors that feed masking:**

| Detector | Masks? | Extraction |
| :--- | :--- | :--- |
| `RegexDetector` | Yes | **`match_text`** (all literal occurrences); else fragments from evidence |
| `NERDetector` | Yes | **`match_text`** (first **person**); else NER segments in evidence |
| `TopicDetector` | Yes (blocked topic) | Suffix after `topic bloqué:` |
| `InjectionDetector` | No | |
| `EntropyDetector` | No | |

**Rules:**

- Only **matched** events count (any `action`).
- **Injection** and **entropy** skipped for sanitization.
- Fragments **< 3** chars ignored.
- Evidence prefixed **`ERROR:`** ignored.
- Spans sorted, **merged** if overlapping, applied **end to start**.
- Masking uses `text[:PipelineConfig.max_text_length]` only.

**Practical:** `sanitized_text` is safe to send for structured PII/secrets/crypto and **explicitly blocked** topic keywords. **Typed tags** tell the model what was removed. **Out of scope** (`allowed` with no hit) drives **`action`** but supplies **no** literal for `apply_redactions`. Injection affects **`action`** only; text unchanged for injection hits.

---

## 4. Orchestration (`scoring.py`, `loader.py`)

### Risk aggregation (`scoring.py`)

Computes **`ScanResult.action`** and **`global_score`**.

* **Veto**: any matched event with **`Action.BLOCK`** and **score ≥ 0.9** → **`BLOCK`**.
* **Block tier**: max of **`block`** event scores; if **≥ 0.85** → **`BLOCK`**.
* **Human review tier**: max **HR** scores; if **≥ 0.60** → **`HUMAN_REVIEW`**.
* **Warn tier**: max **warn** scores; if **≥ 0.30** → **`WARN`**.
* Else **`PASS`**; **`global_score`** = max matched score.

Thresholds: **`DECISION_THRESHOLDS`**. Pure **`human_review`** at 1.0 **does not** become **`BLOCK`**.

* **`apply_redactions`**: see § Rewriting above. **`placeholder`** forces one string for all spans.
* **`explain_decision`**: fills **`ScanResult.reason`** (highest-score detector, ANSSI ref, truncated detail).

### Profile loader (`profiles/loader.py`)

* **`DETECTOR_MAP`**: YAML `type` → detector class.
* **`action: redact`** (legacy) → **`human_review`** + **`DeprecationWarning`**.
* **Shipped profiles** (summary):
    - **`strict`**: **`pii_complet`** all builtins except **`ALNUM_MIXED_12`** (`exclude_patterns`) **`block`**; **`jeton_alnum_mixed`** only **`ALNUM_MIXED_12`** **`human_review`**; entropy **`block`**; injection **`block`**; NER identity **`human_review`**; **no** `TopicDetector`.
    - **`sante`**: NIR, FINESS, RPPS, patient identity; **`TopicDetector`** **`perimetre_medical`** **`block`** (**`allowed`**).
    - **`juridique`**: enterprise PII **`block`**; **`clauses_sensibles`** **`block`**; entropy + injection **`block`**.
    - **`dev`**: **`credentials_code`** list in YAML (SSH pubkey not in default list; add in YAML if needed); **`jeton_alnum_mixed`**; entropy **`block`**; injection **`block`**; **`TopicDetector`** **`modules_critiques`** **`block`** (**`blocked`**).
    - **`rh`**: HR patterns; **`donnees_sensibles_rh`** **`block`**.
    - **`generique`**: core PII + intl patterns; no **`TEL_US`**; injection; entropy.

### Orchestrator (`pipeline.py`)

`GuardPipeline`: load by profile name, YAML path, or detector list; truncate; run detectors; aggregate; **`apply_redactions`**; build **`ScanResult`**. **`scan_input`** / **`scan_output`**. **`raise_on_block`** → `ColandixBlockedError`. **`find_all_candidates`** for debug (all hits).

### Logger (`logger.py`)

Security logging without raw content (R29 angle). SHA-256 pseudonymization for user IDs; detection metadata only; JSON Lines for SIEM.

### Compliance (`compliance.py`)

Maps config to ANSSI-oriented report; **`generate_report()`** includes **`sanitization`** (typed tags, available keys, non-sanitizable injection/entropy).

---

## 5. Tests

See **[testing.md](testing.md)** (`pytest`, ~362 collected): GDPR **`evidence`**, scoring, YAML profiles, pipeline, every detector family (international PII, multilingual injection, NER policy, topics, compliance).
