# Triggers and examples (human-readable)

This page lists what fires each detector, with fake examples. For exact regex, see the source: [`regex.py`](https://github.com/GrosGradient/colandix/blob/main/colandix/detectors/regex.py), [`entropy.py`](https://github.com/GrosGradient/colandix/blob/main/colandix/detectors/entropy.py), [`injection.py`](https://github.com/GrosGradient/colandix/blob/main/colandix/detectors/injection.py), [`topic.py`](https://github.com/GrosGradient/colandix/blob/main/colandix/detectors/topic.py), [`ner.py`](https://github.com/GrosGradient/colandix/blob/main/colandix/detectors/ner.py).

**Rewrite vs decision only?** A match can do two different things:

| Detector | Feeds `sanitized_text` | Feeds `action` |
| :--- | :--- | :--- |
| `RegexDetector` | Yes: masks via **`match_text`** (full match substring); typed tag from **`trigger_type`** (e.g. `[EMAIL_REDACTED]`, `[PHONE_REDACTED]`, …) — see [`redaction.py`](https://github.com/GrosGradient/colandix/blob/main/colandix/redaction.py); unmapped custom patterns → `[REDACTED]`; falls back to fragments from `evidence` if **`match_text`** is missing | Yes |
| `NERDetector` | Yes: masks first **person** span (`PER` or `PERSON` per SpaCy, via **`match_text`**); tag **`[PERSON_REDACTED]`** | Yes |
| `TopicDetector` (blocked topic or out of scope) | Yes: **only** if evidence starts with `topic bloqué:` (keyword masked, **`[TOPIC_REDACTED]`**); “out of scope” (`allowed`) **does not** give a span to `apply_redactions` | Yes |
| `InjectionDetector` | No | Yes |
| `EntropyDetector` | No | Yes |

Injection and entropy only affect the decision. There is no reliable replacement for prompt injection or a partial secret fragment. Optional **`placeholder=`** on `apply_redactions` replaces every typed tag with one string. See [Architecture](architecture.md) (redaction section).

---

## Built-in regex (`RegexDetector`)

Each line: **YAML key** — idea — *example*.

- **NIR** — French social security number, spaced form, birth month 01–12 or 20 — *e.g.* `2 85 06 75 056 089 42`
- **SSN_US** — US SSN **`XXX-XX-XXXX`** (invalid ranges excluded) — *e.g.* `078-05-1120`
- **NINO_UK** — UK National Insurance: two letters + six digits + A–D (optional spacing) — *e.g.* `AB123456C`
- **DB_URL** — `postgresql`, `mysql`, `mongodb` (+ `mongodb+srv`), `redis`, `mssql`, `sqlserver`, `elasticsearch`, `amqp` / `amqps`, `clickhouse`, ≥8 chars after `://` — *e.g.* `postgresql://app:pass@db:5432/prod`
- **EMAIL** — standard email — *e.g.* `contact@example.org`
- **EMAIL_OBFUSQUE** — `[at]`, `(at)`, or ` at ` — *e.g.* `john[at]gmail.com`
- **TEL_FR** — French phone: `0` + 9 digits, or `+33` / `0033`; after `+33`, `(?<!\w)` avoids sticking to alnum — *e.g.* `06 12 34 56 78`, `+33612345678` *(compact FR → **`TEL_FR`**, before **`TEL_INTL`** in builtin order)*
- **TEL_US** — NANP — *e.g.* `(415) 555-0100` *(on **`strict`**, not **`generique`**)*
- **TEL_INTL** — E.164 `+` + 8–15 digits, no spaces, excluding the `+33…` block covered by **`TEL_FR`** — *e.g.* `+447911123456`
- **SIRET** — **14** digits as a word — *e.g.* `73282932000074`
- **SIREN** — **9** digits — *e.g.* `123456789`
- **IBAN_FR** — `FR` + check + 23 alnum — *e.g.* `FR7630006000011234567890189`
- **TWILIO_SID** — `AC` + 32 alnum; **before** **`IBAN_GENERIC`** in builtins — *e.g.* `ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`
- **IBAN_GENERIQUE** — two-letter country + two-digit key + BBAN 11–30 alnum — *e.g.* `DE89370400440532013000`
- **PASSEPORT_FR** — 2 digits + 2 letters + 5 digits — *e.g.* `12AB12345`
- **CARD_PAN** — 16-digit Visa/MC — *e.g.* `4532 0151 1283 0366`
- **CARD_AMEX** — Amex 15 digits — *e.g.* `3714 496353 98431`
- **CARD_DISCOVER_UNIONPAY** — Discover (`6011`, `65xx`) or UnionPay `62xx`, 16 digits — *e.g.* `6011 1111 1111 1117`
- **TVA_FR** — French VAT — *e.g.* `FR12345678901`
- **FINESS** — 9 digits — *e.g.* `750712345`
- **RPPS** — 11 digits — *e.g.* `10001234567`
- **API_KEY_GENERIC** — `api_key` / `apikey` / `api_token` + `:` or `=` + token ≥20 — *e.g.* `api_key=abcdefghijklmnopqrst1234`
- **API_KEY_SK** — `sk-` + ≥20 alnum — *e.g.* `sk-12345678901234567890`
- **GITHUB_TOKEN** — `ghp_` + **36** alnum
- **GITLAB_TOKEN** — `glpat-` + ≥20 chars
- **ANTHROPIC_API_KEY** — `sk-ant-` + ≥40 chars
- **AWS_ACCESS_KEY_ID** — `AKIA` + 16 alnum
- **AWS_SECRET_KEY** — keyword + `:` or `=` + 40-char AWS secret — *e.g.* `AWS_SECRET_ACCESS_KEY=…` *(**`dev`** + **`strict`**)*
- **SLACK_TOKEN** — `xoxb-` …
- **HUGGINGFACE_TOKEN** — `hf_` …
- **STRIPE_SK** / **STRIPE_PK** — `sk_live_…` / `pk_live_…`
- **GOOGLE_API_KEY** — `AIza` + ≥30 chars
- **NPM_TOKEN** — `npm_` + ≥36 chars
- **JWT_JWS** — `xxx.yyy.zzz` JWT shape
- **CONNECTION_STRING** — SQL Server style `Server=…;…Password=` — *e.g.* `Server=x;Database=y;User=u;Password=Secret123!`
- **CREDENTIAL** — `password` / `pwd` / `login` / … + `:` or `=` + value ≥8 — *e.g.* `password=hunter2secret`
- **PRIVATE_KEY_HEADER** — PEM private key or cert start — *e.g.* `-----BEGIN CERTIFICATE-----`
- **SSH_KEY** — OpenSSH **public** key `ssh-rsa` / `ssh-ed25519` / … + base64 — *e.g.* `ssh-rsa AAAAB3NzaC1yc2E…`
- **MARQUAGE_DR** — “diffusion restreinte”, `dr` + digit, `igi 1300`
- **IGI_1300** — `igi 1300`
- **CONFIDENTIEL_DEF** — “confidentiel défense”
- **IP_PRIVE** — private IPv4 four octets — *e.g.* `10.0.0.1`
- **IPV6** — long or short (`::`) — *e.g.* `2001:db8::1`
- **CRYPTO_ETH** — `0x` + 40 hex
- **CRYPTO_BTC** — legacy or bech32 — *e.g.* `bc1q…`
- **ALNUM_MIXED_12** — no spaces, length ≥12, mixed case + digit — *e.g.* `fezjf57829F787feu9nzio`; shipped profiles use dedicated **`jeton_alnum_mixed`** in **`human_review`** (**`strict`** / **`dev`**), not **`block`** alone.

### Profile-specific custom regex

**`rh` — `donnees_sensibles_rh`** (shipped YAML: **`action: block`**)

- **SALAIRE** — payroll / salary wording
- **SYNDICAT** — union, CSE, staff rep
- **EVALUATION** — review, performance, annual interview

**`juridique` — `clauses_sensibles`** (shipped YAML: **`action: block`**)

- **CONFIDENTIEL** — NDA, confidentialité
- **REF_DOSSIER** — dossier / affaire + ref like `n°`

On match: **`RegexDetector`** at **1.0** with **`block`** in YAML tends to yield aggregate **`BLOCK`** (veto ≥ **0.9**), with **`match_text`** masked in `sanitized_text`.

---

## Patterns not shipped as builtins {#patterns-not-builtins}

Some international IDs are **intentionally absent**: without surrounding context the false-positive rate would be high next to FR/EU numeric patterns. Add a **`custom_pattern`** in the regex detector YAML when you need one.

| Candidate | Why not a builtin |
| :--- | :--- |
| UK sort code (`XX-XX-XX`) | Collides with dates and other triplets. |
| US EIN (`XX-XXXXXXX`) | Same issue. |
| Spanish DNI / NIE | Eight digits + check letter overlaps other EU-style numbers. |
| Italian Codice fiscale | 16 alnum matches generic IDs too often. |
| Dutch BSN | Nine digits: same risk as bare SSN vs FR nine-digit IDs. |
| Bare US SSN (`XXXXXXXXX`, no dashes) | Collides with SIREN, FINESS, etc. |
| Generic MRZ line | 44-char `[A-Z0-9<]` too broad; very random strings may still hit **entropy** if needed. |

---

## Entropy (`EntropyDetector`)

- **Keyword context** — `password`, `api_key`, `mdp`, `mot de passe`, … + **`:` or `=`** + value ≥8 (no “space-only” separator between keyword and value) — *e.g.* `password=MonSuperSecret123!`
- **JSON context** — `"password"`, `"token"`, … + quoted string — *e.g.* `"token": "abcdefgh"`
- **Authorization header** — `Authorization:` + `Bearer` / `Token` / `Basic` + token ≥8
- **Env var** — `SCREAMING_SNAKE` ending in `KEY`, `SECRET`, … + ≥3 chars after first letter + `=` — *e.g.* `DATABASE_PASSWORD=x`
- **No context** — tokens from text (default min length **20**); score if Shannon entropy above threshold (~4.5), or **`gray_structural`** cap **0.75** when entropy is slightly low but the token is long and heterogeneous.

*Non-match to remember:* plain prose with no structural `=` / `:` after a secret keyword does **not** fire context mode.

---

## Injection (`InjectionDetector`)

Normalized text (lowercase, no accents, collapsed spaces). **Default score 1.0 per distinct pattern**; one hit can drive aggregate veto **BLOCK** (≥ 0.9). Illustrative examples:

- **IGNORE_INSTRUCTIONS** — *e.g.* `ignore all previous instructions`; also `forget` / `disregard` (EN)
- **OUBLIE_INSTRUCTIONS** — *e.g.* `oublie tes instructions`
- **RESET_DE**, **RESET_ES**, **RESET_PT**, **RESET_IT** — German / Spanish / Portuguese / Italian reset phrases
- **NEW_PERSONA** — *e.g.* `you are now`, `Du bist jetzt`, `Eres ahora`, …
- **REVEAL_PROMPT**, **SYSTEM_PROMPT**, **EXTRACT_INSTRUCTIONS**, **DATA_LEAK**, **LIST_ACTION**, **SHOW_CONTEXT**
- **DAN_MODE** — word boundaries limit false positives on *dans*, *dandys*, etc.
- **ROLEPLAY_ESCAPE**, **LINUX_TERMINAL_FR**, **SANS_RESTRICTION_SECURITE_FR**, **RESTRICTION_SECURITE_PHRASE_FR**
- **CONTEXT_DELIMITER** — *e.g.* `<|im_start|>`
- **TRAINING_EXTRACT**, **PROMPT_STUFFING**, **CODE_INJECTION**, **SOCIAL_ENGINEERING**
- **BASE64_INJECT**, **GZIP_PAYLOAD** (`H4sI…`), **URL_ENCODING_OBFUSQUE** (≥5 `%XX` in a row)
- **UNICODE_ESCAPE**, **END_INSTRUCTIONS**, **SYSTEM_OVERRIDE**

---

## Topic (`TopicDetector`)

- **`blocked`** list (**`dev`**, **`action: block`**) — substring match, accent-insensitive, score **0.9**
- **`allowed`** list (**`sante`**, **`action: block`**) — if non-empty and **no** allowed keyword in text → “out of scope”, score **0.9** (vs **0.5** when the same detector is **`warn`** in custom YAML)

---

## NER (`NERDetector`)

SpaCy pipeline: default **`fr_core_news_md`**, override with **`extra.model`** in YAML.

**Model install (one download per package):**

| Language | Model | Command |
| :--- | :--- | :--- |
| French (default) | `fr_core_news_md` | `python -m spacy download fr_core_news_md` |
| English | `en_core_web_md` | `python -m spacy download en_core_web_md` |
| German | `de_core_news_md` | `python -m spacy download de_core_news_md` |
| Spanish | `es_core_news_md` | `python -m spacy download es_core_news_md` |
| Italian | `it_core_news_md` | `python -m spacy download it_core_news_md` |
| Portuguese | `pt_core_news_md` | `python -m spacy download pt_core_news_md` |

- **Entity types**: count labels in **`entities`**; English uses **`PERSON`**, not **`PER`**.
- Match when distinct types present ≥ **`combo_threshold`**, after person-span filters (`PER` / **`PERSON`**, blacklist, short ALLCAPS acronyms).
- **Action**: YAML usually **`human_review`**; if **`block`**, code downgrades to **`human_review`** unless `extra.ner_allow_block: true`.

---

## Which profile enables what?

- **`generique`**: `EMAIL`, `EMAIL_OBFUSQUE`, `TEL_FR`, `TEL_INTL`, `NIR`, `SSN_US`, `NINO_UK`, `IBAN_FR`, `IBAN_GENERIQUE`, `PASSEPORT_FR`, `CARD_PAN`, `CARD_AMEX`, `CARD_DISCOVER_UNIONPAY`, `IP_PRIVE`, `CREDENTIAL`; entropy; injection.
- **`strict`**: **`pii_complet`** (all builtins except `ALNUM_MIXED_12` via `exclude_patterns`) + **`jeton_alnum_mixed`**; entropy **`block`**; injection; NER `PER` threshold 1.
- **`sante`**: `NIR`, `FINESS`, `EMAIL`, `RPPS`; injection; topic `allowed` **`block`**; NER `PER` threshold 1.
- **`rh`**: built-in list + custom SALAIRE / SYNDICAT / EVALUATION **`block`**; injection; NER `PER` + `ORG` threshold 1.
- **`dev`**: **`credentials_code`** explicit list in `dev.yaml` (no **`SSH_KEY`** by default; add in YAML if needed) + **`jeton_alnum_mixed`**; entropy; injection; topic **`blocked`** **`block`**.
- **`juridique`**: `SIRET`, `IBAN_FR`, `EMAIL` + CONFIDENTIEL / REF_DOSSIER **`block`**; entropy; injection.

---

## Test coverage vs this page

- **Regex**: `test_regex_motifs_documentes_triggers_par_profil`, **`test_exclude_patterns_retire_builtin`**, **`test_ip_privee_masquage_complet`**, Twilio / SSH tests, international PII, cards, crypto, `DB_URL`, `EMAIL_OBFUSQUE`, `TEL_INTL`, `AWS_SECRET_KEY`, compressed IPv6, extended **`CREDENTIAL`**, RH / legal profile loads in [`test_regex.py`](https://github.com/GrosGradient/colandix/blob/main/tests/test_detectors/test_regex.py).
- **Injection**: `test_injection_motifs_documentes`, gzip / URL-encoding, DAN word-boundary tests in [`test_injection.py`](https://github.com/GrosGradient/colandix/blob/main/tests/test_detectors/test_injection.py); pipeline injection in [`test_pipeline.py`](https://github.com/GrosGradient/colandix/blob/main/tests/test_pipeline.py).
- **Topic / RH / legal**: [`test_pipeline.py`](https://github.com/GrosGradient/colandix/blob/main/tests/test_pipeline.py), [`test_topic.py`](https://github.com/GrosGradient/colandix/blob/main/tests/test_detectors/test_topic.py).
- **ALNUM / entropy / redaction / NER**: matching tests in [`test_pipeline.py`](https://github.com/GrosGradient/colandix/blob/main/tests/test_pipeline.py), [`test_entropy.py`](https://github.com/GrosGradient/colandix/blob/main/tests/test_detectors/test_entropy.py), [`test_scoring.py`](https://github.com/GrosGradient/colandix/blob/main/tests/test_scoring.py), [`test_redaction.py`](https://github.com/GrosGradient/colandix/blob/main/tests/test_redaction.py), [`test_ner.py`](https://github.com/GrosGradient/colandix/blob/main/tests/test_detectors/test_ner.py); NER skips if SpaCy model missing.

---

## See also

- [architecture.md](architecture.md)
- [testing.md](testing.md)
- [Patterns not shipped as builtins](#patterns-not-builtins)
