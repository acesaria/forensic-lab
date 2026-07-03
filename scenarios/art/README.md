# Atomic Red Team Calibration

Atomic Red Team is scoped here as a calibration layer for single techniques:

- ATT&CK-mapped atomic baseline;
- single-observable calibration;
- comparison against standard atomic tests;
- not the basis for realistic multi-stage scenarios.

`catalog.lock.yml` records the source and selected techniques. `selected_tests.yml`
is the executable subset used by the `art_calibration` scenario. The full ART
corpus is not required for the thesis claim; only the selected atomics need to be
kept reproducible.
