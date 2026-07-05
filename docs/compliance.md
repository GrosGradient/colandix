# ANSSI-PA-102 mapping for colandix

This document explains how colandix maps to the ANSSI guide for secure generative AI deployment.

**Two outputs per scan.** Each `scan_input` or `scan_output` call yields:

- **`ScanResult.sanitized_text`**: rewritten text ready for the model (PII, secrets, and **blocked topic keywords** masked via `DetectionEvent.match_text` for regex; NER / blocked-topic evidence otherwise; “out of scope” `allowed` drives the decision without a dedicated mask span in `apply_redactions`). For **NER**, masking uses the **first person span** (**`PER`** or **`PERSON`** per SpaCy and `entities`). Each replacement uses a **typed tag** from `DetectionEvent.trigger_type` (e.g. `[EMAIL_REDACTED]` including **EMAIL_OBFUSQUE**, `[PHONE_REDACTED]` for **TEL_FR** / **TEL_US** / **TEL_INTL**, `[NIR_REDACTED]` including **SSN_US** and **NINO_UK**, `[CRYPTO_REDACTED]`, `[TOPIC_REDACTED]`) via [`redaction.py`](https://github.com/GrosGradient/colandix/blob/main/colandix/redaction.py); unknown or unmapped types fall back to **`[REDACTED]`**. Optional **`placeholder=`** on `apply_redactions` forces one string for all spans.
- **`ScanResult.action`**: aggregate decision (`pass`, `warn`, `human_review`, `block`). **`ScanResult.blocked`** means `action == block`.

YAML **`action`** qualifies each **detector**; **`aggregate_score`** applies thresholds per detector **action** family (see [README](https://github.com/GrosGradient/colandix/blob/main/README.md) and [architecture.md](architecture.md), scoring). Tests: [testing.md](testing.md), “Scoring, redaction, and masking”. Triggers: [triggers-par-profil.md](triggers-par-profil.md).

## R25: Input and output filtering and rewriting

**ANSSI expectation (paraphrased):**  
Filter model inputs and outputs to detect and block malicious or unauthorized content.

**colandix:**

The main R25 artifact is **`ScanResult.sanitized_text`**: PII, structured secrets (regex / NER), and (when masking applies) **blocked topic** fragments replaced with **typed tags** (see [`redaction.py`](https://github.com/GrosGradient/colandix/blob/main/colandix/redaction.py) and `get_redaction_tag`). **Out of scope** (`TopicDetector` with `allowed`) mostly drives **`ScanResult.action`** (`block` on shipped profiles) without a dedicated `apply_redactions` fragment. Detection also feeds **`ScanResult.action`** for block or human review.

Active detectors:

- `RegexDetector`: sensitive data (NIR, **SSN_US**, **NINO_UK**, SIRET, IBAN FR / generic IBAN, French passport, **`CARD_PAN`** / **`CARD_AMEX`** / **`CARD_DISCOVER_UNIONPAY`**, DB URLs, markings, private and **IPv6** IPs, FR phone (+33, E.164 **`+336…`** as **`TEL_FR`**), E.164 international (**`TEL_INTL`**), US NANP on exhaustive profiles, **`EMAIL`** / **`EMAIL_OBFUSQUE`**, known secrets (**`API_KEY_SK`**, tokens, **`AWS_*`**, Slack, HF, Stripe, Google, npm, **`TWILIO_SID`**, JWT, **`CRYPTO_*`**, **`CONNECTION_STRING`**, **`CREDENTIAL`**, PEM, …). Each regex event carries **`match_text`** and **`trigger_type`**. **`ALNUM_MIXED_12`**: **`strict`** / **`dev`** use **`jeton_alnum_mixed`** in **`human_review`**. **`dev`** uses explicit **`credentials_code`** in YAML; other **`strict`** coverage follows **`pii_complet`** **`block`** (builtins minus **`ALNUM_MIXED_12`**, `exclude_patterns`). **`juridique`**: **`clauses_sensibles`** **`block`**.
- `EntropyDetector`: **context** (`password=`, JSON `"password":`, Authorization, env **SCREAMING_SNAKE**) → score **1.0**; on **`strict`** YAML **`block`**. **No context**: Shannon + complexity; **`gray_structural`** capped at **0.75**. `analyze_token()` is Shannon-only, see [architecture.md](architecture.md).
- `NERDetector`: SpaCy, default **`fr_core_news_md`**; other pipeline via **`extra.model`**. **`PER`** on shipped profiles; **`PERSON`** on English **`en_core_web_*`**. **`action: block`** on NER is coerced to **`human_review`** unless `extra.ner_allow_block: true`. `GuardPipeline.ner_fr_core_status()` lists each NER **`model`** name.
- `InjectionDetector`: normalized text; **1.0 per category by default** (one pattern can veto **BLOCK** ≥ 0.9). Includes EN/DE/ES/PT/IT resets and **`NEW_PERSONA`**, jailbreak, gzip `H4sI…`, URL-encoding, etc. See [triggers-par-profil.md](triggers-par-profil.md).
- **`apply_redactions`** ([`scoring.py`](https://github.com/GrosGradient/colandix/blob/main/colandix/scoring.py)): prefers **`match_text`**; merges overlaps; **injection** and **entropy** do not mask. Independent of **`ScanResult.action`**. **`original_text`** is full input; **`sanitized_text`** is the analyzed slice after masking.

**Example:**

```python
guard = GuardPipeline(profile="generique")
res_in = guard.scan_input(user_prompt)

response = call_llm(res_in.sanitized_text)

guard.scan_output(response)

# stricter profile (all builtins, NER, entropy):
# guard = GuardPipeline(profile="strict")
```

**Validation tests:**  
`tests/test_detectors/test_regex.py`, `test_entropy.py`, `test_injection.py`, `test_ner.py`, `tests/test_pipeline.py`, `tests/test_redaction.py`. Full suite: [testing.md](testing.md) (~362 collected; NER tests **skip** if the expected SpaCy model, usually **`fr_core_news_md`**, is missing).

`compliance_report()` / `generate_report()` include a **`sanitization`** section (typed tags, `REDACTION_KEYS`, injection / entropy not sanitizable).

**Shapes intentionally not in builtins:** UK sort code, US EIN bare, Spanish DNI/NIE, Italian codice fiscale, Dutch BSN, bare 9-digit US SSN, generic MRZ line, see [triggers-par-profil.md](triggers-par-profil.md#patterns-not-builtins); use **`custom_pattern`** with context when needed.

---

## R26: Control of application interactions

**ANSSI expectation (paraphrased):**  
Limit privileges and control data exchanged between the AI system and other applications.

**colandix:**

- `TopicDetector`: **`allowed`** (whitelist) or **`blocked`** (blacklist); accent-insensitive comparison; auditable evidence (`topic bloqué: …` / out-of-scope message).
- **Out of scope** (`allowed` non-empty, no allowed keyword): score **0.5** if detector YAML is not **`block`**; **0.9** if **`action: block`** (can participate in aggregate veto).
- **`sante`**: **`perimetre_medical`** **`block`** with **`allowed`** list.
- **`dev`**: **`modules_critiques`** **`block`** with **`blocked`** list.

**Note:** **`strict`** has no `TopicDetector`. For explicit R26 conversational scope, use a domain profile (`sante`, `dev`, custom YAML). See [triggers-par-profil.md](triggers-par-profil.md).

---

## R27: Human control of critical actions

**ANSSI expectation (paraphrased):**  
Avoid critical automated actions without prior human validation.

**colandix:**

- `Action.HUMAN_REVIEW`: per-detector YAML; after aggregation, **`human_review`** when max score of **`human_review`** events exceeds the threshold (0.60). NER **`block`** becomes **`human_review`** unless `extra.ner_allow_block: true`. Legacy YAML **`redact`** loads as **`human_review`** with `DeprecationWarning`.

---

## R29: Logging interactions

**ANSSI expectation (paraphrased):**  
Log interactions with the generative AI system for audit and incident detection.

**colandix:**

- `ColandixLogger`: logs detections with SHA-256 user pseudonymization; no raw user content (GDPR-oriented).
- **Scope:** reflects `scan_input` / `scan_output` metadata (direction, scores, truncated evidence); not plugin calls, RAG retrieval, or every filtering step. Extend **in the application** for full guide-style logging. See [Scope R25–R35](#scope-r25-r35).

---

## R31: Securing access to critical modules

**ANSSI expectation (paraphrased):**  
Control access to critical AI system components.

**colandix:**

- Segmented profiles: **`dev`**, **`juridique`**, **`strict`**, **`sante`**, **`rh`** (see [README](https://github.com/GrosGradient/colandix/blob/main/README.md), [triggers-par-profil.md](triggers-par-profil.md), `colandix/profiles/*.yaml`).

**Clarification:** This mapping is a **product reading** (conversation scope, secrets, topics). It does **not** replace guide §5.5 **code generation** process controls (no auto-run of generated code, commit policy, IDE hygiene). See [Scope R25–R35](#scope-r25-r35).

---

## R34: Sovereign hosting and data transit

**ANSSI expectation (paraphrased):**  
Ensure sensitive data does not transit to unmanaged third parties.

**colandix:**

- **No network calls** in orchestration; regex, scoring, and optional local SpaCy **`fr_core_news_md`**. Alert **`evidence`** truncated (50 chars); **`match_text`** is not logged. Sending sensitive data to a **third-party LLM** remains an **organizational** R34 decision; the library does not choose the provider.

---

<a id="scope-r25-r35"></a>

## Scope: R25–R35 (guide excerpt vs library)

The [official ANSSI guide (PDF)](https://messervices.cyber.gouv.fr/documents-guides/Recommandations_de_s%C3%A9curit%C3%A9_pour_un_syst%C3%A8me_d_IA_g%C3%A9n%C3%A9rative.pdf) mixes **R25**–**R35** items: controls around the model and broader IT / organizational measures. The library **colandix** targets **filtering and rewriting** at model input and output. TLS, isolation, DDoS, **generated code** lifecycle, training, consumer-facing services, and **collaboration-tool access reviews** stay with the **integrator / organization**.

### Summary table

| Ref | Theme (official guide) | Role |
| :--- | :--- | :--- |
| **R25** | I/O filtering; response size limits | **Core** (detectors, `sanitized_text`, `scan_output`). Nuance: [below](#integrator-notes). |
| **R26** | Inter-app / network interaction | **Partial**: `TopicDetector` for **dialog scope** only; not TLS or SI-wide flow logging ([R26](#r26-control-of-application-interactions)). |
| **R27** | Limit automation on untrusted input | **Partial**: `human_review`, aggregation; not email/plugins/SI cut-through. |
| **R28** | Isolation; user request vs text sent to model | **Isolation**: out of scope. **Dual trace** before/after app preprocessing: not in `ColandixLogger`; app-side. |
| **R29** | Fine-grained logging (plugins, filters, responses) | **Partial**: scan metadata, no raw text. No dedicated plugin/context events ([R29](#r29-logging-interactions)). |
| **R30** | Generated code: execution, repos, hygiene tools | **Out of scope** |
| **R31** | Do not use AI to generate critical-module code (§5.5) | **Out of scope** for **code-gen procedure**; [R31](#r31-securing-access-to-critical-modules) here means **profile segmentation**, not IDE/CI policy. |
| **R32** | Developer awareness | **Out of scope** |
| **R33** | Consumer-facing exposure | **Out of scope** (auth, DDoS, front door, response validation process). |
| **R34** | Sensitive data to public/third-party AI | **Orchestration** has no outbound calls; “do not send to ChatGPT” remains organizational ([R34](#r34-sovereign-hosting-and-data-transit)). |
| **R35** | Review AI tool rights on business apps | **Out of scope** (governance). |

<a id="integrator-notes"></a>

### Integrator notes

1. **R25 size:** `PipelineConfig.max_text_length` truncates the **analyzed slice** (default 10_000 in [`result.py`](https://github.com/GrosGradient/colandix/blob/main/colandix/result.py)), not a full product-level prompt/response cap. Enforce stricter limits at API/gateway.
2. **R25 model-internal leakage:** [`InjectionDetector`](https://github.com/GrosGradient/colandix/blob/main/colandix/detectors/injection.py) covers common **request-side** phrasing. Model **replies** that leak internals without those patterns have no dedicated family; extend with `custom_patterns` or human review.
3. **R28:** log raw request vs **text actually sent to the LLM** outside the current logger surface (see [`logger.py`](https://github.com/GrosGradient/colandix/blob/main/colandix/logger.py)).
4. **R29:** no structured log of **plugin calls** or **context fetch** in the library; add downstream if audit requires it.
5. **R26, R27, R30–R33, R35:** infra, process, governance; **out of library scope** but not hidden from an audit.
6. **R31:** separate **colandix** profile segmentation from guide §5.5 **generated code** measures ([R31](#r31-securing-access-to-critical-modules)).
