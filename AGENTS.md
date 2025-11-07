# Repository Guidelines

## Project Structure & Module Organization
Core Python services live in `openhands/` (FastAPI server, runtimes, integrations) while the Remix/Vite UI lives in `frontend/`. Supporting workspaces include `microagents/` and `enterprise/` for specialized agents, `tests/` and `frontend/__tests__` for coverage, `scripts/` for tooling, and `containers/` for dev images. Generate `config.toml` from `config.template.toml` or run `make setup-config` before launching.

## Build, Test, and Development Commands
Run `make build` after cloning or dependency updates to install Poetry + npm packages and create the production frontend bundle. Use `make run` for the full developer stack, or `make start-backend`, `make start-frontend`, and `poetry run uvicorn openhands.server.listen:app --reload --port 3000` when isolating tiers. Frontend loops rely on `npm run dev` against the live backend or `npm run dev:mock` for MSW; rerun `make setup-config` whenever workspace paths or API keys change.

## Coding Style & Naming Conventions
Backend code is linted/formatted by Ruff (see `dev_config/python/ruff.toml`) and type-checked with mypy; prefer single quotes, double-quoted docstrings, snake_case modules, and PascalCase classes. Frontend code follows Airbnb + Prettier via `npm run lint` / `lint:fix`; components stay PascalCase, hooks begin with `use`, Redux slices end with `Slice`, and localization files come from `npm run make-i18n`. Update lock files only through Poetry or npm and keep generated artifacts (translations, VSIX bundles) in sync with their source changes.

## Testing Guidelines
Backend unit suites reside in `tests/unit`; run `poetry run pytest ./tests/unit/test_*.py`, keeping fixtures near their consumers. UI coverage uses Vitest and Playwright via `npm run test`, `npm run test:coverage`, and `npm run test:e2e`, with specs named `<component>.test.tsx` or `<hook>.test.ts`. Execute `make test` (frontend wrapper) plus any backend suites you touched, and perform a manual `make run` smoke test when adjusting orchestration or networking.

## Commit & Pull Request Guidelines
Follow the repository’s `type(scope): summary (#issue)` convention (`feat(frontend): …`, `fix(llm): …`) and keep messages imperative with a linked issue or PR. PR descriptions should cover motivation, validation commands, linked issues, and screenshots or GIFs for UI changes, noting any config or migration impact. Before requesting review, ensure `make build`, `npm run lint`, and the relevant tests pass, no secrets are staged, and docs/configs reflect the change.

## Configuration & Security Tips
Keep secrets out of git by copying `config.template.toml` or `.env.sample`, storing real values locally, and rotating them with `make setup-config`. When reusing runtime images, set `SANDBOX_RUNTIME_CONTAINER_IMAGE`, and enable `DEBUG=1` only briefly because the resulting `logs/llm/<date>` files may contain sensitive prompts.
