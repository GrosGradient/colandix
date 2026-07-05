# Contributing and releases

## Issues and pull requests

- Use [GitHub Issues](https://github.com/GrosGradient/colandix/issues) for bugs and feature ideas.
- **Fork** the repository, push a branch on your fork, and open a **pull request** into `main`.
- Public forks: the first time a new contributor opens a PR, a maintainer may need to **approve** workflow runs on GitHub (default security behavior).

Non-members cannot push directly to this repo; they read, fork, and propose changes via PR.

## Local development

```bash
uv sync --all-groups
pytest
```

Build the docs locally:

```bash
uv run mkdocs serve
```

## Documentation site (GitHub Pages)

The [`Docs` workflow](https://github.com/GrosGradient/colandix/blob/main/.github/workflows/docs.yml) builds with MkDocs and deploys on every push to `main`.

One-time repository setup (maintainers):

1. **Settings → Pages**
2. Set **Source** to **GitHub Actions** (not “Deploy from a branch”).
3. After the next successful run on `main`, the site is available at the URL shown under Pages (default: `https://grosgradient.github.io/colandix/`).

If you add a **custom domain** later:

1. Add a `CNAME` at the repo root (one line: your hostname, e.g. `docs.example.com`).
2. In DNS, point that hostname to `grosgradient.github.io` with a **CNAME** record.
3. Enter the same hostname under **Settings → Pages → Custom domain** and wait for the TLS certificate.
4. Set `site_url` in [`mkdocs.yml`](https://github.com/GrosGradient/colandix/blob/main/mkdocs.yml) (and optional `project.urls` in [`pyproject.toml`](https://github.com/GrosGradient/colandix/blob/main/pyproject.toml)) to the live docs URL.

## PyPI releases (Trusted Publisher)

Publishing uses [`release.yml`](https://github.com/GrosGradient/colandix/blob/main/.github/workflows/release.yml): it runs only when a **GitHub Release is published**, builds the package with `uv build`, and uploads with [pypa/gh-action-pypi-publish](https://github.com/pypa/gh-action-pypi-publish) via **OIDC** — no PyPI token in GitHub secrets.

One-time PyPI setup (project owner):

1. Create or claim the `colandix` project on [PyPI](https://pypi.org/).
2. **Publishing → Add a trusted publisher** (preferred) or equivalent:
   - **Owner**: GitHub organization (e.g. `GrosGradient`)
   - **Repository**: `colandix`
   - **Workflow name**: `release.yml`
   - **Environment**: leave default unless you use a named GitHub Environment

### Maintainer release checklist

1. Update [`CHANGELOG.md`](https://github.com/GrosGradient/colandix/blob/main/CHANGELOG.md) and bump `version` in [`pyproject.toml`](https://github.com/GrosGradient/colandix/blob/main/pyproject.toml) following [SemVer](https://semver.org/).
2. Merge to `main`.
3. Create a **GitHub Release** with a tag **`vX.Y.Z`** matching the version (e.g. `v0.1.0`).
4. Confirm the **Release** workflow succeeds and the new version appears on PyPI.
5. Confirm docs deployed as expected (Pages workflow on `main`).

## Org-level notes (outside this repo)

- Organization profile README: must live at **[org]/.github** repository under **`profile/README.md`** (not `.github/README.md` at the root of that repo).
- Repo access: add teams or people under **Settings → Collaborators** with **Write** or **Maintain** as needed; consider **branch protection** on `main`.
