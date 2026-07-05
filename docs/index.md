# colandix

**Sanitize text before and after your LLM. Runs locally. No network calls.**

Designed to implement [**ANSSI-PA-102**](https://messervices.cyber.gouv.fr/documents-guides/Recommandations_de_s%C3%A9curit%C3%A9_pour_un_syst%C3%A8me_d_IA_g%C3%A9n%C3%A9rative.pdf), the [**French national security**](https://cyber.gouv.fr/) authority's guide for generative AI, at the content filtering and rewriting layer.

---

## What it does

The **colandix** library sits between your application and the model. It intercepts every prompt before it reaches the LLM and every response before it reaches the user.

```python
guard = GuardPipeline(profile="generique")

res_in  = guard.scan_input(user_prompt)
response = call_llm(res_in.sanitized_text)   # cleaned text, not the raw input
res_out = guard.scan_output(response)
```

Each scan returns two things:

| | |
|:---|:---|
| **`sanitized_text`** | Rewritten text with PII, secrets, and blocked keywords replaced by typed tags: `[EMAIL_REDACTED]`, `[PERSON_REDACTED]`, `[API_KEY_REDACTED]`, … |
| **`action`** | Aggregate decision: `pass`, `warn`, `human_review`, or `block`. |

Injection and entropy signals drive the **decision** only; they do not alter `sanitized_text`.

---

## ANSSI-PA-102

The library implements the controls from the guide that apply at the model boundary:

| Ref | Requirement | In colandix |
|:---|:---|:---|
| **R25** | Filter and rewrite model inputs and outputs | Regex, NER, entropy, injection; `sanitized_text` + `action` |
| **R26** | Control application interactions | `TopicDetector` with `allowed` / `blocked` keyword lists |
| **R27** | Require human validation before critical actions | `Action.HUMAN_REVIEW`; NER never auto-blocks without `ner_allow_block` |
| **R29** | Log interactions without exposing raw content | `ColandixLogger`: SHA-256 pseudonymization, no raw text stored |
| **R31** | Restrict access to critical modules | Segmented profiles (`dev`, `juridique`, `strict`, …) |
| **R34** | Keep sensitive data away from uncontrolled third parties | No outbound calls in the library; SpaCy runs locally |

Controls that require infra or process (TLS, IAM, code review, org policy) stay outside this package. See [ANSSI compliance](compliance.md) for the full mapping.

---

## Profiles

Shipped profiles cover common sectors. Each is a YAML file you can extend or replace.

| Profile | Covers |
|:---|:---|
| `generique` | Core PII (email, phone, NIR, IBAN, passport, cards, …) + injection + entropy. |
| `strict` | All built-in patterns + NER identity detection + entropy block. |
| `sante` | Healthcare PII (RPPS, FINESS, NIR) + medical topic guardrails. |
| `dev` | Secrets and credentials (API keys, tokens, DB URLs, …) + code-related topics. |
| `rh` | HR-sensitive data (payroll, union, performance reviews). |
| `juridique` | NDA / confidentiality clauses + legal document references. |

---

## What is Colandix?

**Colandix** is a filtering layer that sits at the boundary between your application and the model. Safe content passes through. PII, secrets, and injection attempts do not reach the model.

---

## Install

```bash
uv add colandix          # or: pip install colandix
uv add "colandix[ner-fr]"  # + French SpaCy pipeline (matches shipped profiles)
```

[Quick start](quickstart.md) · [Profiles & triggers](triggers-par-profil.md) · [Architecture](architecture.md) · [ANSSI compliance](compliance.md)
