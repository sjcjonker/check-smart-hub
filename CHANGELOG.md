# Changelog

## 1.2.0 - 2026-11-20

- Add consistent `hue-`, `ikea-` and `somfy-` prefixed `hub`, `devices`,
  `inventory` and `validate` modes.
- Reject a provider/mode mismatch with UNKNOWN before network access.
- Keep existing unprefixed modes, default behavior and Hue status modes compatible.
- Extend generic multi-hub Nagios examples for Hue, DIRIGERA and Somfy.

## 1.1.0

Previous published baseline; see the `v1.1.0` tag for its complete contents.

## 1.0.0

Initial standalone release:

- Read-only device reachability checks for Philips Hue, IKEA DIRIGERA and Somfy TaHoma.
- Reviewed device baselines, stable IDs and explicit offline/missing-device results.
- Certificate pinning before credentials are sent, bounded responses and no redirects.
- Private JSON configuration with root:monitoring-group ownership and mode 0640.
- Hidden Hue and Somfy credential input; DIRIGERA PKCE pairing.
- Configurable enrollment output path, monitoring group and DIRIGERA client name.
- Python 3.10+ with no third-party dependencies; automated regression tests.

Somfy one-way RTS reachability cannot be established and reports UNKNOWN.
The monitoring plugin is unchanged from the extracted, production-tested source.
