# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-05-06

### Added

- `GuardPipeline` and scanner API for input/output text, aligned with **ANSSI-PA-102**-style guidance
- Detectors: regex (PII, secrets, identifiers), entropy, prompt-injection heuristics, optional spaCy NER, topic checks
- YAML profiles (`generique`, `strict`, domain variants) and compliance helpers
- Redaction, scoring, and structured scan results
- Documentation site (MkDocs Material) and test suite

[Unreleased]: https://github.com/GrosGradient/colandix/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/GrosGradient/colandix/releases/tag/v0.1.0
