# Synthetic desktop fixtures

These files contain invented cases, evidence, and reports for the development preview and regression tests. They are not investigation results.

`report.json` uses deterministic synthetic case/report/evidence identifiers, a synthetic analyst identity, fixed example timestamps, and placeholder fingerprints. Repeated identifiers are kept consistent across its records. No application-local actor identifier is retained. Fingerprints in this fixture are display examples, not evidence integrity assertions.

`core.json` is generated from temporary synthetic evidence by `tools/generate_desktop_fixtures.py`.
