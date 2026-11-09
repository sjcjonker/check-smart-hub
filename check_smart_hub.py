#!/usr/bin/env python3
# Read-only local monitoring for Hue, DIRIGERA and TaHoma hubs.
# Author: Stijn Jonker (sjcjonker) | https://github.com/sjcjonker
# Usage: python3 check_smart_hub.py --config /private/hub.json --mode devices
# Default mode: devices (polls inventory); credentials stay in private config. Help: --help.
# Nagios exit codes: 0 OK, 1 WARNING, 2 CRITICAL, 3 UNKNOWN.
"""Read-only local TaHoma/DIRIGERA/Hue monitoring; Python standard library only."""
from __future__ import annotations

import argparse
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import re
import signal
import ssl
import stat
import sys

LIMIT = 1024 * 1024
PATHS = {"somfy": "/enduser-mobile-web/1/enduserAPI/setup/devices",
         "dirigera": "/v1/devices", "hue": "/clip/v2/resource"}


def port(config):
    return 443 if config["provider"] == "hue" else 8443


class CheckError(Exception):
    def __init__(self, message, code=3):
        super().__init__(message)
        self.code = code


def clean(value):
    return re.sub(r"[\x00-\x1f\x7f|]", " ", str(value))[:120]


def validate(config):
    if not isinstance(config, dict) or config.get("provider") not in PATHS:
        raise CheckError("invalid provider")
    try:
        ipaddress.ip_address(config["host"])
    except (KeyError, ValueError, TypeError):
        raise CheckError("host must be a literal IP address")
    token = config.get("token")
    if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9._~+/=-]+", token):
        raise CheckError("missing or invalid token")
    pin = config.get("certificate_sha256")
    if not isinstance(pin, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", pin):
        raise CheckError("certificate_sha256 must contain 64 hexadecimal characters")
    expected = config.get("expected_devices", [])
    if (not isinstance(expected, list) or
            any(not isinstance(x, str) or not x or len(x) > 512 for x in expected) or
            len(set(expected)) != len(expected)):
        raise CheckError("expected_devices must be a list of unique nonempty IDs")
    return config


def load_config(filename):
    # No symlink following, and do not expose private file contents on failure.
    fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd) as source:
        metadata = os.fstat(source.fileno())
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o037 or
                metadata.st_uid != 0):
            raise CheckError("config must be a regular root-owned file, mode 0640 or stricter")
        raw = source.read(65537)
    if len(raw) > 65536:
        raise CheckError("config exceeds size limit")
    try:
        config = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CheckError("invalid private JSON: %s at line %d, column %d" % (
            exc.msg, exc.lineno, exc.colno))
    return validate(config)


def context():
    # Authentication is explicit leaf-certificate SHA256 pinning before HTTP.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def request(config, path, *, method="GET", body=None, authenticated=True):
    connection = http.client.HTTPSConnection(config["host"], port(config), timeout=8,
                                              context=context())
    try:
        connection.connect()
        certificate = connection.sock.getpeercert(binary_form=True)
        digest = hashlib.sha256(certificate).hexdigest()
        if not hmac.compare_digest(digest, config["certificate_sha256"].lower()):
            raise CheckError("TLS certificate changed; verify hub and renew pin locally", 2)
        headers = {"Accept": "application/json", "Connection": "close"}
        if authenticated:
            if config["provider"] == "hue":
                headers["hue-application-key"] = config["token"]
            else:
                headers["Authorization"] = "Bearer " + config["token"]
        if body is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        if response.status in (401, 403):
            raise CheckError("API authentication rejected; renew local token")
        if response.status != 200:
            raise CheckError("API returned HTTP %d" % response.status)
        # http.client does not follow redirects or use environment proxies.
        data = response.read(LIMIT + 1)
        if len(data) > LIMIT:
            raise CheckError("API response exceeds 1 MiB")
        try:
            return json.loads(data)
        except (ValueError, UnicodeError):
            raise CheckError("API returned invalid JSON")
    finally:
        connection.close()


def somfy_status(device):
    # RTS is one-way: an API entry never proves that the physical device is online.
    if device["deviceURL"].lower().startswith("rts:"):
        return "unobservable"
    available = device.get("available")
    if not isinstance(available, bool):
        return "unknown"
    states = device.get("states", [])
    if not isinstance(states, list):
        return "unknown"
    status = [s.get("value") for s in states if isinstance(s, dict)
              and s.get("name") == "core:StatusState"]
    if len(status) > 1:
        return "unknown"
    if status:
        if status[0] not in ("available", "unavailable"):
            return "unknown"
        if (status[0] == "available") != available:
            return "conflict"
    return "online" if available else "offline"



def hue_inventory(payload):
    """Join v2 connectivity services to physical device IDs, not light on/off."""
    if (not isinstance(payload, dict) or not isinstance(payload.get("errors"), list)
            or not isinstance(payload.get("data"), list)):
        raise CheckError("invalid Hue v2 response envelope")
    if payload["errors"]:
        raise CheckError("Hue API reported errors; response details withheld")
    resources = payload["data"]
    seen = set()
    devices = {}
    connectivity = {}
    for resource in resources:
        if (not isinstance(resource, dict) or not isinstance(resource.get("id"), str)
                or not resource["id"] or resource["id"] in seen
                or not isinstance(resource.get("type"), str)):
            raise CheckError("invalid or duplicate Hue resource")
        seen.add(resource["id"])
        if resource["type"] == "device":
            metadata = resource.get("metadata", {})
            if not isinstance(metadata, dict):
                raise CheckError("invalid Hue device metadata")
            devices[resource["id"]] = {
                "name": clean(metadata.get("name", resource["id"])), "state": "unknown"}
        elif resource["type"] == "zigbee_connectivity":
            owner = resource.get("owner")
            if (not isinstance(owner, dict) or owner.get("rtype") != "device"
                    or not isinstance(owner.get("rid"), str) or not owner["rid"]):
                raise CheckError("invalid Hue connectivity owner")
            connectivity.setdefault(owner["rid"], []).append(resource.get("status"))
    for identity, device in devices.items():
        states = connectivity.get(identity, [])
        if len(states) != 1 or not isinstance(states[0], str):
            continue
        device["state"] = {
            "connected": "online",
            "disconnected": "offline",
            "connectivity_issue": "offline",
            "unidirectional_incoming": "unobservable",
            "pending_discovery": "unknown",
        }.get(states[0], "unknown")
    return devices


def inventory(provider, data):
    if provider == "hue":
        return hue_inventory(data)
    if not isinstance(data, list):
        raise CheckError("API device inventory is not a list")
    result = {}
    key = "deviceURL" if provider == "somfy" else "id"
    for device in data:
        if (not isinstance(device, dict) or not isinstance(device.get(key), str)
                or not device[key] or device[key] in result):
            raise CheckError("API inventory has invalid or duplicate device IDs")
        if provider == "somfy":
            label = device.get("label", device[key])
            state = somfy_status(device)
        else:
            attrs = device.get("attributes", {})
            if not isinstance(attrs, dict):
                raise CheckError("invalid DIRIGERA device attributes")
            label = attrs.get("customName", device[key])
            reachable = device.get("isReachable")
            state = ("online" if reachable else "offline") if isinstance(reachable, bool) else "unknown"
        result[device[key]] = {"name": clean(label), "state": state}
    return result


def evaluate(devices, expected):
    if not expected:
        raise CheckError("no expected_devices baseline; run inventory and select device IDs")
    counts = {key: 0 for key in ("online", "offline", "missing", "unknown", "unobservable", "conflict")}
    details = []
    for identity in expected:
        device = devices.get(identity)
        state = device["state"] if device else "missing"
        counts[state] += 1
        if state != "online":
            details.append((device["name"] if device else clean(identity)) + ": " + state)
    code = 2 if counts["offline"] or counts["missing"] else 3 if any(
        counts[x] for x in ("unknown", "unobservable", "conflict")) else 0
    text = ", ".join("%s=%d" % (key, value) for key, value in counts.items())
    text += ", new=%d" % len(set(devices) - set(expected))
    if details:
        text += "; " + "; ".join(details[:8])
    perf = " ".join("%s=%d" % (key, value) for key, value in counts.items())
    return code, text + " | " + perf



def hue_status(config, mode):
    """Read selected v1 status fields using the existing pinned HTTPS connection."""
    if config["provider"] != "hue":
        raise CheckError("Hue status modes require a Hue configuration")
    data = request(config, "/api/" + config["token"] + "/config",
                   authenticated=False)
    return evaluate_hue_status(data, mode)


def evaluate_hue_status(data, mode):
    if not isinstance(data, dict):
        raise CheckError("invalid Hue configuration response")

    if mode == "hue-backup":
        backup = data.get("backup")
        if not isinstance(backup, dict):
            raise CheckError("Hue backup status missing or invalid")
        error = backup.get("errorcode")
        status = backup.get("status")
        if type(error) is not int or error < 0:
            raise CheckError("Hue backup error code missing or invalid")
        if error != 0:
            return 2, "bridge backup reports error code %d" % error
        if status != "idle":
            raise CheckError("backup reports no error; unverified status=%s" %
                             clean(status))
        return 0, "no backup error reported; status=idle"

    fields = {
        "hue-internet": ("internet", "internet connectivity"),
        "hue-remote-access": ("remoteaccess", "remote access"),
    }
    if mode not in fields:
        raise CheckError("invalid Hue status mode")
    field, label = fields[mode]
    services = data.get("internetservices")
    if not isinstance(services, dict):
        raise CheckError("Hue internet services status missing or invalid")
    status = services.get(field)
    if status == "connected":
        return 0, "%s connected" % label
    if status == "disconnected":
        return 2, "%s disconnected" % label
    raise CheckError("%s status missing or unrecognized: %s" %
                     (label, clean(status)))


def deadline(_signum, _frame):
    raise CheckError("local API check exceeded 15 seconds", 2)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--mode", choices=("hub", "devices", "inventory", "validate", "hue-backup", "hue-internet", "hue-remote-access"), default="devices")
    args = parser.parse_args(argv)
    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(15)
    try:
        try:
            config = load_config(args.config)
        except OSError:
            raise CheckError("private config missing, unreadable or unsafe")
        if args.mode == "validate":
            print("OK - local configuration valid (no network request)")
            return 0
        if args.mode.startswith("hue-"):
            code, output = hue_status(config, args.mode)
            print(("OK", "WARNING", "CRITICAL", "UNKNOWN")[code] + " - " + output)
            return code
        devices = inventory(config["provider"], request(config, PATHS[config["provider"]]))
        if args.mode == "inventory":
            print(json.dumps(devices, indent=2, ensure_ascii=True))
            return 0
        if args.mode == "hub":
            code, output = 0, "authenticated local API responds; %d inventory entries" % len(devices)
        else:
            code, output = evaluate(devices, config.get("expected_devices", []))
        print(("OK", "WARNING", "CRITICAL", "UNKNOWN")[code] + " - " + output)
        return code
    except CheckError as exc:
        print(("OK", "WARNING", "CRITICAL", "UNKNOWN")[exc.code] + " - " + str(exc))
        return exc.code
    except (OSError, http.client.HTTPException):
        print("CRITICAL - local API connection failed (network/TLS); no credentials logged")
        return 2
    except (ValueError, TypeError, KeyError, RecursionError):
        print("UNKNOWN - invalid local configuration or API payload")
        return 3
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    sys.exit(main())

