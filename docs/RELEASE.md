# Release workflow

All development and review happen in the private check-smart-hub-dev repository.
Do not create development branches or pull requests in check-smart-hub.
After final approval, export only the publication files below and create one
fresh root commit in the publication repository. Do not copy development Git
history, refs, pull requests, site configuration or build/cache files.

PROVENANCE.md remains private development documentation and is excluded from
publication. End-user security guidance is maintained in the README.

Publication allowlist:
- `.github/workflows/tests.yml`
- `.gitignore`
- `CHANGELOG.md`
- `LICENSE`
- `README.md`
- `check_smart_hub.py`
- `docs/RELEASE.md`
- `examples/dirigera.json.example`
- `examples/hue.json.example`
- `examples/somfy.json.example`
- `scripts/setup-smart-hub.py`
- `tests/test_smart_hub.py`
- `examples/nagios.cfg.example`

Before publishing a stable release:

- Run the test suite and check CI on every supported Python version.
- Verify the three Hue status checks and device monitoring for IKEA DIRIGERA and Somfy TaHoma.
- Verify enrollment separately when changing credential or pairing behavior.
- Review the publication tree and Git history for credentials and site data.
- Review the changelog, README security guidance and license.
- Tag the reviewed commit and attach release notes only after those checks.

Tests use mocked transports. A passing test suite does not replace local hub
verification. Normal monitoring is read-only; enrollment can create credentials.
Do not replace working private configuration merely to test enrollment.
