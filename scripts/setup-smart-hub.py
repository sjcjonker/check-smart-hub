#!/usr/bin/env python3
# Interactively enroll a local smart hub and write private credentials.
# Author: Stijn Jonker (sjcjonker) | https://github.com/sjcjonker
# Usage: sudo python3 scripts/setup-smart-hub.py --provider hue --host 192.0.2.10
# Verify the TLS fingerprint; creates root:nagios 0640 config, never overwrites. Help: --help.
# SPDX-License-Identifier: GPL-3.0-or-later
"""Interactive local-only hub enrollment; writes root:nagios 0640 credentials."""
from __future__ import annotations

import argparse
import base64
import getpass
import grp
import hashlib
import importlib.util
import json
import os
import stat
from pathlib import Path
import secrets
import socket
import ssl
import sys
import warnings
from urllib.parse import urlencode

PLUGIN = Path(__file__).resolve().parents[1] / "check_smart_hub.py"
spec = importlib.util.spec_from_file_location("smart_hub", PLUGIN)
hub = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hub)



def hidden_token(prompt):
    # Never allow getpass to fall back to echoed stdin.
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            return getpass.getpass(prompt).strip()
        except getpass.GetPassWarning:
            raise hub.CheckError("hidden input requires a terminal") from None


def enroll(provider, address, *, client_name="Nagios Smart Hub"):

    # First connection has no token. Explicit local TOFU acceptance is required.
    port = hub.port({"provider": provider})
    with socket.create_connection((address, port), timeout=8) as raw:
        with hub.context().wrap_socket(raw, server_hostname=address) as tls:
            fingerprint = hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()
    print("Hub: %s:%d\nCertificate SHA256: %s" % (address, port, fingerprint))
    print("First-use trust: verify this is your hub on your trusted local network.")
    if input("Type the final 12 fingerprint characters to trust it: ").strip() != fingerprint[-12:]:
        raise hub.CheckError("certificate trust not confirmed")
    config = {"provider": provider, "host": address,
              "certificate_sha256": fingerprint, "expected_devices": []}
    if provider == "hue":
        config["token"] = hidden_token("Hue application key (hidden): ")
    elif provider == "somfy":
        config["token"] = hidden_token("TaHoma Developer Mode token (hidden; not the PIN): ")
    else:
        verifier = secrets.token_urlsafe(72)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        query = urlencode({"audience": "homesmart.local", "response_type": "code",
                           "code_challenge": challenge, "code_challenge_method": "S256"})
        response = hub.request(config, "/v1/oauth/authorize?" + query, authenticated=False)
        code = response.get("code") if isinstance(response, dict) else None
        if not isinstance(code, str) or not code:
            raise hub.CheckError("hub did not return a pairing code")
        input("Press the DIRIGERA action button once (do not hold reset), then press Enter: ")
        body = urlencode({"code": code, "name": client_name, "grant_type": "authorization_code",
                          "code_verifier": verifier})
        response = hub.request(config, "/v1/oauth/token", method="POST", body=body, authenticated=False)
        config["token"] = response.get("access_token") if isinstance(response, dict) else None
    hub.validate(config)
    devices = hub.inventory(provider, hub.request(config, hub.PATHS[provider]))
    if not devices:
        raise hub.CheckError("empty device inventory; no baseline saved")
    # Explicit review: do not quietly baseline unknown or sleeping devices.
    for identity, device in devices.items():
        print("%s\t%s\t%s" % (hub.clean(identity), device["name"], device["state"]))
        if device["state"] == "unobservable":
            print("  One-way RTS: presence is known, radio reachability cannot be checked.")
        if input("Monitor this device? [y/N]: ").strip().lower() == "y":
            config["expected_devices"].append(identity)
    if not config["expected_devices"]:
        raise hub.CheckError("no devices selected; configuration not saved")
    status, output = hub.evaluate(devices, config["expected_devices"])
    print("Initial device result: " + output)
    if status and input("Initial state is not OK. Type SAVE to keep this reviewed baseline: ") != "SAVE":
        raise hub.CheckError("baseline not confirmed")
    return config


def save_config(path, config, group_name="nagios"):
    group = grp.getgrnam(group_name).gr_gid
    parent = path.parent
    if not parent.exists():
        parent.mkdir(mode=0o750)
        os.chown(parent, 0, group)
    metadata = parent.lstat()
    if parent.is_symlink() or metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise hub.CheckError("private directory must be root-owned and not group/world writable")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "w") as output:
            os.fchown(output.fileno(), 0, group)
            json.dump(config, output, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
            os.fchmod(output.fileno(), 0o640)
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", required=True, choices=("somfy", "dirigera", "hue"))
    parser.add_argument("--host", required=True)
    parser.add_argument("--output", type=Path, help="private JSON path (default: provider file under /etc/nagios4/private/smart-hubs)")
    parser.add_argument("--group", default="nagios", help="monitoring group (default: nagios)")
    parser.add_argument("--client-name", default="Nagios Smart Hub", help="DIRIGERA pairing name")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("run locally as root to save root:nagios credentials")
    # Validate address before connecting; only IPs, never URL input.
    import ipaddress
    ipaddress.ip_address(args.host)
    name = {"somfy": "somfy-bridge", "dirigera": "ikea-bridge", "hue": "hue-bridge"}[args.provider]
    path = args.output or Path("/etc/nagios4/private/smart-hubs") / (name + ".json")
    if path.exists() or path.is_symlink():
        parser.error("private configuration already exists; refusing to overwrite")
    try:
        config = enroll(args.provider, args.host, client_name=args.client_name)
        save_config(path, config, args.group)
        print("Saved %s; token never printed. Test as the nagios account next." % path)
    except hub.CheckError as exc:
        print("Enrollment failed: " + str(exc) + ". No credentials logged.", file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, EOFError, hub.http.client.HTTPException) as exc:
        # Never print arbitrary exception text: it may contain response/token data.
        reason = type(exc).__name__
        if isinstance(exc, OSError) and exc.errno is not None:
            reason += " (errno %d)" % exc.errno
        print("Enrollment failed: " + reason + "; check root API access (Hue TCP 443; others TCP 8443), TLS and local file permissions. No credentials logged.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

