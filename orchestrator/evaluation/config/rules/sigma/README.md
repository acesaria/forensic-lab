# Community Sigma rules

This directory holds the pinned Linux Sigma rule set used by the Plaso Sigma
detector (Detector A). The exact rules are NOT vendored here; they are pulled at
a pinned git ref recorded in `framework/config/pipeline.yaml`
(`rulesets.sigma_ref`) so the ruleset hash is reproducible.

To populate locally:

    git clone https://github.com/SigmaHQ/sigma
    cd sigma && git checkout <rulesets.sigma_ref from pipeline.yaml>
    cp -r rules/linux <repo>/framework/config/rules/sigma/linux

Rules placed here are treated as `rule_layer: community`. Rules under
`../custom/` are `rule_layer: custom`. Both are evaluated by
`framework/detect/plaso_sigma.py`; metrics report recall with and without the
custom layer.

Every rule file is scanned by `framework/tests/test_rule_leakage.py`: no rule
may contain a verbatim instance constant from any run's `gt_manifest.json`.
