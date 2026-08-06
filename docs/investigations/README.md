# Investigation documents

New investigation notebooks use the exact manifest identifiers:

```text
docs/investigations/<scenario_id>/<run_id>/
  runme_disk_investigation.md
  runme_memory_investigation.md
  runme_timeline_investigation.md
```

Create only the notebooks that exist. A run-specific notebook pins `RUN_ID`
once, derives other case paths and parameters from the run metadata, and writes
new output beneath:

```text
shared/investigations/<run_id>/derived/<source>/
```

Acquired evidence and raw exports remain under `shared/experiments/<run_id>/`
and are never copied into `docs/`. The ignored `shared/investigations/` tree is
the analyst workspace; `docs/investigations/` holds versioned notebooks and
accepted narrative records.

Do not create a separate scenario template until at least one reconstructed
run has completed and the reusable cells have been reviewed. Existing flat
reports remain in place until they are deliberately superseded.
