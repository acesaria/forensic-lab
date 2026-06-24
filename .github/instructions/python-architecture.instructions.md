---
description: "Path-scoped Python architecture guidance for VM lifecycle and orchestration code."
applyTo: ["cli.py", "orchestrator/core/**/*.py", "infra/**/*.py"]
---
# Python Architecture

- Read `PROJECT_CONTEXT.md` before editing these paths.
- Keep orchestration, VM lifecycle, acquisition, and offline analysis boundaries explicit.
- Preserve the VM power-state contract: memory acquisition requires VM ON; disk acquisition requires VM OFF.
- Do not change the VM mutation mechanism unless the task explicitly asks for VM lifecycle refactor.
- Prefer dependency injection through constructors over new globals.
- When changing constructor signatures, update all affected call sites and list them in the response.
- Use existing constants and `ProjectPaths` instead of adding hardcoded paths.
- Add Python type hints to all new or changed signatures.
