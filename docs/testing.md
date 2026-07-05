# Testing

Automated tests cover both pipeline outputs: **rewrite** (`sanitized_text`, `apply_redactions`) and **decision** (`action`, `aggregate_score`). Each detector family has unit tests, then integration in the pipeline.

## Prerequisites

- **Python** ≥ 3.10 (see `.python-version`).
- Dependencies: `uv sync --all-groups` (or equivalent) so the package and **dev** group install (`pytest`, `ruff`, `mypy`, …).
- **SpaCy**: optional for some tests. NER scenarios **skip** if the expected model is missing (default **`fr_core_news_md`**). At least:

  ```bash
  uv run python -m spacy download fr_core_news_md
  ```

  Other models (`en_core_web_md`, `de_core_news_md`, …) are only needed for extra tests or profiles using **`extra.model`**.

## Running tests

From the repo root:

```bash
uv run pytest tests/
```

Useful variants:

| Command | Purpose |
| :--- | :--- |
| `uv run pytest tests/ -q` | Quiet |
| `uv run pytest tests/ -k "name"` | Filter by name |
| `uv run pytest tests/test_scoring.py` | Single file |
| `uv run pytest tests/ --collect-only -q` | List without running |

About **362** tests are collected (`uv run pytest tests/ --collect-only -q`); the count moves with commits.

## Scoring, redaction, and masking

[`tests/test_scoring.py`](https://github.com/GrosGradient/colandix/blob/main/tests/test_scoring.py):

- **`aggregate_score`**: **`block`** veto from **0.9**; thresholds **0.85 / 0.60 / 0.30** applied **per action family** (**`block`**, **`human_review`**, **`warn`**); mixed cases; **`PASS`** when no tier fires despite matches.
- **`apply_redactions`**: **`RegexDetector`** prefers **`match_text`** (all literal occurrences); else regex evidence (`": "` / `":"`), **NER** segments, **blocked topic**; typed tags via `trigger_type` and [`get_redaction_tag`](https://github.com/GrosGradient/colandix/blob/main/colandix/redaction.py); overlapping span merge; **no** masking from injection/entropy; fragments **<3** chars ignored; **`ERROR:`** evidence ignored; **`placeholder=`** forces one replacement string.
- **`explain_decision`**: audit strings per decision level.

[`tests/test_redaction.py`](https://github.com/GrosGradient/colandix/blob/main/tests/test_redaction.py): `REDACTION_TAGS`, `get_redaction_tag` (e.g. **`CRYPTO`** → **`[CRYPTO_REDACTED]`**), `match_text`, merge, pipeline (typed email/IP/NIR, injection leaves text unchanged, dual **`RegexDetector`** for NIR + email).

[`tests/test_pipeline.py`](https://github.com/GrosGradient/colandix/blob/main/tests/test_pipeline.py): **`GuardPipeline`**, health profile + NER → **`human_review`** without **`blocked`** when only NER matches; **`strict`** / **`dev`** + **`ALNUM_MIXED_12`** → **`human_review`** via **`jeton_alnum_mixed`**; **dev** + gray entropy → **`human_review`**; single-sentence injection → **`block`** on **`generique`**; **strict** + JSON password → entropy **`block`**; **`+33`**, **AWS**, full **`DB_URL`** mask (**`[DB_URL_REDACTED]`**); health / dev topics → **`block`** when out of scope or keyword blocked; HR **`donnees_sensibles_rh`** → **`block`**; legal **`clauses_sensibles`** → **`block`**; **`test_rh_salaire_human_review`** expects **`Action.BLOCK`** on salary ; **`find_all_candidates`**.

[`tests/test_profiles.py`](https://github.com/GrosGradient/colandix/blob/main/tests/test_profiles.py): YAML **`action: redact`** → **`human_review`** + **`DeprecationWarning`**.

[`tests/test_compliance.py`](https://github.com/GrosGradient/colandix/blob/main/tests/test_compliance.py): compliance report; **`sanitization`** key (typed tags, key list, injection/entropy not sanitizable).

Readable trigger list [triggers-par-profil.md](triggers-par-profil.md) is covered by: `test_regex_motifs_documentes_triggers_par_profil`, **`test_ip_privee_masquage_complet`**, Twilio/SSH tests, international PII and review-gap cases in [`test_regex.py`](https://github.com/GrosGradient/colandix/blob/main/tests/test_detectors/test_regex.py); `test_injection_motifs_documentes` (multilingual), gzip/URL-encoding/DAN tests in [`test_injection.py`](https://github.com/GrosGradient/colandix/blob/main/tests/test_detectors/test_injection.py); health/dev/HR + **`test_juridique_nda_bloque`** in [`test_pipeline.py`](https://github.com/GrosGradient/colandix/blob/main/tests/test_pipeline.py); entropy in [`test_entropy.py`](https://github.com/GrosGradient/colandix/blob/main/tests/test_detectors/test_entropy.py); **`test_apply_redactions_prefere_match_text`**, **`test_redaction.py`**, NER in [`test_ner.py`](https://github.com/GrosGradient/colandix/blob/main/tests/test_detectors/test_ner.py) (multi-model cache; **skip** if SpaCy model missing).

## Coverage by file

| File | Role |
| :--- | :--- |
| `tests/test_result.py` | `DetectionEvent`, `ScanResult`, `Action`; **GDPR** `evidence` truncation (50 chars); **`match_text`**, **`trigger_type`**. |
| `tests/test_scoring.py` | `aggregate_score`, `apply_redactions` (**`match_text`** first, typed tags, **`placeholder`**), **`explain_decision`**. |
| `tests/test_redaction.py` | Tags, spans, merge, pipeline integrations. |
| `tests/test_profiles.py` | Embedded YAML profiles, detector wiring, **`action: redact`**. |
| `tests/test_pipeline.py` | `GuardPipeline`: scans, exceptions, NER HR, topics, **`ALNUM_MIXED_12`**, gray entropy, injection, strict JSON secret + SSH pubkey **`block`**, **`+33`**, **`DB_URL`**, private IP, HR/legal **`block`**, AWS **dev**. |
| `tests/test_logger.py` | `ColandixLogger`: structure, no raw text leak. |
| `tests/test_compliance.py` | `compliance_report`, ANSSI mapping, **`sanitization`**. |
| `tests/test_detectors/test_base.py` | `BaseDetector`, **`@safe_analyze`**. |
| `tests/test_detectors/test_regex.py` | Builtins (NIR, **SSN_US**, **NINO_UK**, `DB_URL`, **EMAIL_OBFUSQUE**, **TEL_INTL**, Twilio, SSH, IBAN, passport, cards, **TEL_US**, **AWS_SECRET_KEY**, crypto, **IPv6** `::`, tokens, **`CREDENTIAL`**, PEM, **`ALNUM_MIXED_12`**, …); **`exclude_patterns`** (**strict**); parametrized vs [triggers-par-profil.md](triggers-par-profil.md). |
| `tests/test_detectors/test_entropy.py` | Context, Authorization, JSON, env; prose “no notable secret”; Shannon; **`gray_structural`** (cap **0.75**); `analyze_token`. |
| `tests/test_detectors/test_ner.py` | Combo entities, person blacklist (`PER` / **`PERSON`**), **`extra.model`**, **`block`** → **`human_review`** unless `ner_allow_block`; **skip** if **`fr_core_news_md`** missing. |
| `tests/test_detectors/test_injection.py` | Jailbreak, delimiters, gzip, URL-encoding, **`RESET_*`**, …; aligned with [triggers-par-profil.md](triggers-par-profil.md). |
| `tests/test_detectors/test_topic.py` | `allowed` / `blocked`, accent normalization; out-of-scope **0.5** vs **0.9** by YAML **`action`**. |

Utilities: `tests/conftest.py`, `tests/__init__.py`.

## Static checks (not pytest)

```bash
uv run ruff check colandix tests
uv run mypy colandix
```

(Exact invocations may follow `pyproject.toml`.)

## Pre-deployment checklist

Run before tagging a release, merging to `main`, or publishing to PyPI.

### Automated checks

```bash
uv run pytest tests/ -q
uv run ruff check colandix tests
uv run mypy colandix
uv run mkdocs build
uv build
```

All five must exit 0.

### Manual checks

| Check | How |
| :--- | :--- |
| NER with model | `uv run pytest tests/test_detectors/test_ner.py -v` with **`fr_core_news_md`** installed: tests run, not skipped. |
| NER without model | Remove model, rerun: NER tests skip, no crash. |
| Tests notebook | Run all cells in `notebooks/tests_colandix.ipynb` |
| Version sync | `pyproject.toml` `version` matches `colandix/__init__.py` `__version__`. |
| ANSSI mapping | Reread [compliance.md](compliance.md) if you changed detectors or R25–R35 scope. |
| Docs preview | `uv run mkdocs serve` at `http://127.0.0.1:8000`, nav works. |
| CI | Push a branch; confirm `docs.yml` passes before merging. |

## See also

- [triggers-par-profil.md](triggers-par-profil.md) — triggers by profile and pytest mapping.
- [architecture.md](architecture.md) — detectors and scoring.
- [README](https://github.com/GrosGradient/colandix/blob/main/README.md) — install, profiles, usage.
- [compliance.md](compliance.md) — ANSSI-PA-102 mapping (single source of truth).
