# Changelog

## 1.0.0 — Unreleased

Initial standalone release candidate:

- Read-only device reachability checks for Philips Hue, IKEA DIRIGERA and Somfy TaHoma.
- Reviewed device baselines, stable IDs and explicit offline/missing-device results.
- Certificate pinning before credentials are sent, bounded responses and no redirects.
- Private JSON configuration with root:monitoring-group ownership and mode 0640.
- Hidden Hue and Somfy credential input; DIRIGERA PKCE pairing.
- Configurable enrollment output path, monitoring group and DIRIGERA client name.
- Python 3.10+ with no third-party dependencies; automated regression tests.

Somfy one-way RTS reachability cannot be established and reports UNKNOWN.
The monitoring plugin is unchanged from the extracted, production-tested source.
