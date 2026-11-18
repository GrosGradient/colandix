# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Logs, `ScanResult.reason` and `ColandixBlockedError` no longer contain detected values: regex evidence is the pattern name(s), NER evidence is entity counts (`PER:2, LOC:1`), entropy evidence is the token length and scores.
- `sanitized_text` now masks **every** match (all occurrences of all regex patterns, each with its own tag; all NER entities; entropy secrets), not only the first one.
- Texts longer than `max_text_length` are now blocked by default (`PipelineConfig.on_overflow="block"`), since the tail was never scanned. Use `on_overflow="truncate"` for the previous behaviour.
- NER now analyses the whole text in chunks of `max_text_length` instead of only the first chunk.

### Added

- `PipelineConfig.fail_closed`: a detector that raises, or a `NERDetector` without spaCy / model, blocks the request instead of being skipped.
- `DetectionEvent.matches` (all values to mask, never serialised) and `DetectionEvent.error`.
- `detector_errors` field in log entries.

### Fixed

- `IBAN_FR` / `IBAN_GENERIQUE` detect IBANs written in groups separated by spaces. Both patterns are now uppercase-only to limit false positives.
- `NERDetector.get_entities()` / `find_all_candidates()` only return the entity types configured in `entities` (they returned `MISC`, `LOC`… for a `PER`-only profile).
- NER masking uses one tag per entity type (`[PERSON_REDACTED]`, `[LOCATION_REDACTED]`, `[ORG_REDACTED]`), and the event no longer reports `PERSON_NAME` when no person was found.

## [0.1.0] - 2026-05-06

### Added

- `GuardPipeline` and scanner API for input/output text, aligned with **ANSSI-PA-102**-style guidance
- Detectors: regex (PII, secrets, identifiers), entropy, prompt-injection heuristics, optional spaCy NER, topic checks
- YAML profiles (`generique`, `strict`, domain variants) and compliance helpers
- Redaction, scoring, and structured scan results
- Documentation site (MkDocs Material) and test suite

[Unreleased]: https://github.com/GrosGradient/colandix/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/GrosGradient/colandix/releases/tag/v0.1.0
