# Quick start

## Install

```bash
uv add colandix
```

Or with pip:

```bash
pip install colandix
```

Development setup (includes docs, tests, linters):

```bash
uv sync --all-groups
```

### NER / SpaCy (optional)

SpaCy pipelines are optional. Without them, regex, entropy, injection, and topic detectors still run; NER stays inactive.

| Extra | Installs |
| :--- | :--- |
| `ner-fr` | `fr_core_news_md` via PyPI (matches shipped profiles) |
| `ner-de`, `ner-en`, `ner-es`, `ner-it`, `ner-pt` | `spacy` only; then `uv run python -m spacy download de_core_news_md` (etc.) |
| `ner` | `spacy` only; use `uv run python -m spacy download <model>` for any pipeline |
| `ner-all` | `fr_core_news_md` wheel only |

```bash
uv add "colandix[ner-fr]"
# German example:
uv add "colandix[ner-de]" && uv run python -m spacy download de_core_news_md
```

Shipped profiles default to `fr_core_news_md`. For another language set `extra.model` and `entities` in your YAML (English uses `PERSON`, not `PER`).

---

## Minimal example

```python
from colandix import GuardPipeline

guard = GuardPipeline(profile="generique")
res_in = guard.scan_input("my prompt")

response = call_llm(res_in.sanitized_text)

res_out = guard.scan_output(response)
```

Replace `call_llm` with your client (OpenAI, Ollama, Mistral, etc.).

Tutorial notebook: [`notebooks/demo_colandix.ipynb`](https://github.com/GrosGradient/colandix/blob/main/notebooks/demo_colandix.ipynb).

---

## Key concepts

1. **One guard, one profile.** `GuardPipeline(profile="strict")` loads a built-in YAML set of detectors.
2. **Benign text returns `pass`.** Ordinary messages get `Action.PASS`.
3. **Secrets return `block`.** An `sk-…` key pattern yields `Action.BLOCK` with a reason string (truncated in logs).
4. **Branch on `action`.** Use `if res.action == Action.BLOCK:` (or `res.blocked`) before calling the LLM.
5. **`sanitized_text` is always computed.** Even when not blocked, sensitive spans get typed tags like `[EMAIL_REDACTED]`.
6. **Profiles change behavior.** `sante` adds medical topic guardrails and NER (if SpaCy is installed).

---

## Next steps

- [Profiles and triggers](triggers-par-profil.md)
- [Architecture and scoring](architecture.md)
- [Testing](testing.md)
