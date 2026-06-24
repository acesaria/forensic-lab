---
description: "Use when refactoring the Python codebase into the Orchestrator -> VMManager -> Provider layered architecture, including constructor changes, dependency injection, and config usage."
applyTo: ["orchestrator/**/*.py", "infra/**/*.py"]
---
# Layered Architecture Refactor

- Orchestrator talks only to VMManager; VMManager only to Provider (Law of Demeter).
- Prefer dependency injection via __init__ parameters; avoid global state or config dicts.
- When constructor signatures change, identify all affected call sites, update them, and list them in the response.
- Use constants from orchestrator/core/config.py instead of hardcoded strings or paths.
- Add Python type hints to all new or changed signatures.
