# check-smart-hub

Read-only Nagios monitoring for Philips Hue, IKEA DIRIGERA and Somfy TaHoma.
Checks a reviewed baseline of device IDs for reachability. A light being switched
off is not a fault. Python 3.10+ on Linux; standard library only.

## Philips Hue usage and response time

The author uses Hue only for backup status (`hue-backup`), internet connectivity
(`hue-internet`) and remote access (`hue-remote-access`). Polling the device
inventory appeared to increase Hue response times in the author's installation.
This is an observation, not a measured or confirmed causal relationship.

Device monitoring remains available, but is not used by the author for Hue.
Choose one of the status modes explicitly for routine Hue checks: the default
`devices` mode polls the device inventory. The `hub` and `inventory` modes, and
interactive enrollment, also retrieve the inventory. The three Hue status modes
read local bridge status without retrieving the device inventory.

## Installation and enrollment

Install `check_smart_hub.py` and keep the setup script in the repository layout
(it imports the plugin from its parent directory). Run setup locally on the
monitoring server as root. No cloud credentials or SSH access are required.

```sh
sudo install -d -o root -g nagios -m 0750 /etc/nagios4/private
sudo python3 scripts/setup-smart-hub.py --provider hue --host 192.0.2.10
```

The default files are `/etc/nagios4/private/smart-hubs/hue-bridge.json`,
`ikea-bridge.json` and `somfy-bridge.json`. Setup creates the final directory;
its parent must already exist. Files use root:nagios ownership and mode 0640,
the new directory mode 0750. Existing files are never overwritten.
Use `--output /private/path/hub.json` and `--group monitoring` for other layouts.
Provide a dedicated private directory, root-owned and not group/world writable.

Setup displays the certificate fingerprint before sending credentials. Verify
it through a trusted local source before accepting it. It then asks for:

- Hue: an existing application key using hidden terminal input, with no Nagios macro dependency.
- Somfy: a Developer Mode token using hidden input, not the hub PIN.
- DIRIGERA: a brief press of the action button for PKCE pairing. The default
  client name is `Nagios Smart Hub`; change it with `--client-name`.

Select each device to monitor. Empty inventories and empty baselines are
rejected. An initial non-OK baseline requires explicit confirmation.
Example JSON files are templates, not working credentials; never commit live files.

## Nagios invocation

```sh
sudo -u nagios python3 check_smart_hub.py \
  --config /etc/nagios4/private/smart-hubs/hue-bridge.json --mode hue-backup
```

```text
# Shared command: define once in your Nagios commands file.
define command {
    command_name check_hue_backup
    command_line /usr/bin/python3 /usr/local/lib/nagios/plugins/check_smart_hub.py --config '$_HOSTKEYFILE$' --mode hue-backup
}

# Each host has its own private JSON configuration.
define host {
    use generic-host
    host_name hue-bridge
    address 192.0.2.10
    _KEYFILE /etc/nagios4/private/smart-hubs/hue-bridge.json
}

define host {
    use generic-host
    host_name hue-bridge-2
    address 192.0.2.20
    _KEYFILE /etc/nagios4/private/smart-hubs/hue-bridge-2.json
}

# The shared command resolves KEYFILE separately for each host.
define service {
    use generic-service
    host_name hue-bridge,hue-bridge-2
    service_description Backup status
    check_command check_hue_backup
    check_interval 60
    retry_interval 5
    max_check_attempts 3
}
```

Put shared commands in your commands file and host/service definitions in the
corresponding device files. `_KEYFILE` is a host custom variable; Nagios exposes
it as `$_HOSTKEYFILE$` for that host's service checks. It contains only the
absolute JSON path. Reuse the command for additional hubs, with a separate JSON
and `_KEYFILE` per host. Each JSON contains that hub's actual host address,
provider, token, certificate pin and device baseline; `$HOSTADDRESS$` does not
override the JSON address. Use enrollment `--output` to create a second file.

For the other Hue status checks, define shared commands with `--mode hue-internet`
and `--mode hue-remote-access`. DIRIGERA and Somfy use `--mode hub` or `--mode devices`
with the same host macro. See [examples/nagios.cfg.example](examples/nagios.cfg.example).
The example assumes your standard `generic-host` and `generic-service` templates
and the usual 60-second Nagios interval unit; adapt these to your installation.

Use administrator-managed absolute `_KEYFILE` paths containing only letters,
digits, `/`, `_`, `-` and `.`. Do not put quotes or shell expressions in the
variable value: Nagios trusts custom macros and does not shell-escape them.
The command quotes the macro to pass the path as a single argument.

Adjust the installed plugin path and monitoring account. Credentials belong in
JSON, never command definitions, process arguments, environment variables or Git.
Hue uses TCP 443; DIRIGERA and TaHoma use TCP 8443. Monitoring pins the leaf
certificate before sending the token, rejects redirects, and bounds responses.
A certificate change requires local investigation and a verified new pin.

Available `--mode` values:

| Mode | Behavior |
| --- | --- |
| `devices` (default) | Check the reviewed device baseline |
| `hub` | Check authenticated API access; does not evaluate the device baseline |
| `inventory` | Print device IDs, names and states; treat output as private site data |
| `validate` | Validate the local private JSON without a network request |
| `hue-backup` | Check reported backup error/status; does not verify backup freshness or restoreability |
| `hue-internet` | Check the Hue bridge's reported internet connectivity |
| `hue-remote-access` | Check the Hue bridge's reported remote-access connectivity |

Hue status modes use the pinned local v1 API. A missing or unrecognized field
returns UNKNOWN. Use `devices` for actual device reachability monitoring.

Exit codes: 0 OK, 2 CRITICAL (offline/missing devices or transport failure),
3 UNKNOWN (invalid configuration, ambiguous state or unobservable reachability).
Somfy one-way RTS presence cannot prove radio reachability and remains UNKNOWN.
Device selection is a fixed baseline: newly discovered devices are not silently
added. Review the private JSON when deliberately adding or removing devices.

## Security

Keep credential JSON files root-owned, readable only by the monitoring group
(mode 0640), in a private directory (0750). Never share tokens, private JSON or
raw hub responses in issues. Hub tokens may grant more access than this plugin
uses. Verify the first-use certificate fingerprint independently; investigate
certificate changes before accepting a new pin. A compromised host or hub is
outside the protection offered by pinning. Report vulnerabilities privately
through GitHub when available; otherwise request a private contact without
posting secrets or exploit details.

## Development and release

```sh
python3 -m unittest discover -s tests -v
```

Tests use mocked transports and synthetic credentials; no live hub is contacted.
CI covers Python 3.10 through 3.14. See [docs/RELEASE.md](docs/RELEASE.md) and
[CHANGELOG.md](CHANGELOG.md) for release
notes. Enrollment never deploys the plugin or changes Nagios configuration.

Licensed under GPL-3.0-or-later; see [LICENSE](LICENSE).
