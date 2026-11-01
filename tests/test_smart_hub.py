# SPDX-License-Identifier: GPL-3.0-or-later
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import ssl
import tempfile
import unittest
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("smart_hub_test", ROOT / "check_smart_hub.py")
hub = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hub)


def config(provider="dirigera"):
    return dict(provider=provider, host="192.0.2.11", token="SECRET-token",
                certificate_sha256=hashlib.sha256(b"certificate").hexdigest(), expected_devices=["lamp"])


class DeviceChecks(unittest.TestCase):
    def test_dirigera_online_does_not_depend_on_light_being_on(self):
        data = [{"id": "lamp", "isReachable": True,
                 "attributes": {"customName": "Lamp", "isOn": False}}]
        code, text = hub.evaluate(hub.inventory("dirigera", data), ["lamp"])
        self.assertEqual(code, 0)
        self.assertIn("online=1", text)

    def test_offline_and_deleted_devices_are_critical(self):
        devices = hub.inventory("dirigera", [{"id": "lamp", "isReachable": False}])
        self.assertEqual(hub.evaluate(devices, ["lamp"])[0], 2)
        self.assertEqual(hub.evaluate({}, ["lamp"])[0], 2)

    def test_somfy_rts_never_proves_reachability(self):
        data = [{"deviceURL": "rts:///blind", "available": True}]
        devices = hub.inventory("somfy", data)
        self.assertEqual(hub.evaluate(devices, ["rts:///blind"])[0], 3)
        self.assertEqual(devices["rts:///blind"]["state"], "unobservable")

    def test_somfy_conflicting_flags_stay_unknown(self):
        for available, state in [(False, "available"), (True, "unavailable")]:
            device = {"deviceURL": "io://blind", "available": available,
                      "states": [{"name": "core:StatusState", "value": state}]}
            data = hub.inventory("somfy", [device])
            self.assertEqual(data["io://blind"]["state"], "conflict")
            self.assertEqual(hub.evaluate(data, ["io://blind"])[0], 3)

    def test_somfy_consistent_online_and_offline(self):
        for available, expected in [(True, 0), (False, 2)]:
            devices = hub.inventory("somfy", [{"deviceURL": "io://blind", "available": available}])
            self.assertEqual(hub.evaluate(devices, ["io://blind"])[0], expected)

    def test_empty_baseline_and_malformed_inventories_do_not_pass(self):
        with self.assertRaises(hub.CheckError):
            hub.evaluate({}, [])
        for data in [{}, [None], [{"id": "x"}, {"id": "x"}], [{"id": ""}]]:
            with self.assertRaises(hub.CheckError):
                hub.inventory("dirigera", data)

    def test_unknown_reachability_is_not_truthy_string(self):
        for value in [None, "false", 1]:
            devices = hub.inventory("dirigera", [{"id": "lamp", "isReachable": value}])
            self.assertEqual(hub.evaluate(devices, ["lamp"])[0], 3)

    def test_names_cannot_inject_perfdata_or_output_lines(self):
        self.assertEqual(hub.clean("lamp\n|CRITICAL\r"), "lamp  CRITICAL ")


class TransportChecks(unittest.TestCase):
    def test_private_json_error_reports_location_without_file_contents(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "config.json"
            path.write_text('{"token": "SECRET"}\n# trailing note')
            with patch.object(hub.os, "fstat", return_value=MagicMock(st_mode=0o100640, st_uid=0)):
                with self.assertRaises(hub.CheckError) as raised:
                    hub.load_config(path)
            self.assertIn("line 2, column 1", str(raised.exception))
            self.assertNotIn("SECRET", str(raised.exception))

    def connection(self, body=b"[]", status=200):
        conn = MagicMock()
        conn.sock.getpeercert.return_value = b"certificate"
        conn.getresponse.return_value.status = status
        conn.getresponse.return_value.read.return_value = body
        return conn

    def test_token_is_sent_only_after_pin_validation_and_get_only(self):
        conn = self.connection()
        with patch.object(hub.http.client, "HTTPSConnection", return_value=conn):
            self.assertEqual(hub.request(config(), "/v1/devices"), [])
        conn.connect.assert_called_once()
        self.assertEqual(conn.request.call_args.args[:2], ("GET", "/v1/devices"))
        self.assertEqual(conn.request.call_args.kwargs["headers"]["Authorization"], "Bearer SECRET-token")
        conn.close.assert_called_once()

    def test_changed_certificate_never_receives_token(self):
        conn = self.connection()
        conf = config()
        conf["certificate_sha256"] = "0" * 64
        with patch.object(hub.http.client, "HTTPSConnection", return_value=conn):
            with self.assertRaises(hub.CheckError) as raised:
                hub.request(conf, "/v1/devices")
        self.assertEqual(raised.exception.code, 2)
        conn.request.assert_not_called()

    def test_no_redirects_and_no_error_body_or_token_leak(self):
        for status in [302, 401, 403, 500]:
            conn = self.connection(body=b"SECRET-token", status=status)
            with patch.object(hub.http.client, "HTTPSConnection", return_value=conn):
                with self.assertRaises(hub.CheckError) as raised:
                    hub.request(config(), "/v1/devices")
            self.assertNotIn("SECRET", str(raised.exception))
            conn.getresponse.return_value.read.assert_not_called()

    def test_invalid_json_and_size_limit(self):
        for body in [b"not JSON", b"x" * (hub.LIMIT + 1)]:
            with patch.object(hub.http.client, "HTTPSConnection", return_value=self.connection(body)):
                with self.assertRaises(hub.CheckError):
                    hub.request(config(), "/v1/devices")

    def test_config_rejects_header_injection_urls_and_missing_pins(self):
        for key, value in [("token", "bad\r\nheader"), ("host", "https://evil"),
                           ("certificate_sha256", ""), ("expected_devices", ["x", "x"])]:
            conf = config()
            conf[key] = value
            with self.assertRaises(hub.CheckError):
                hub.validate(conf)

    def test_missing_config_is_unknown_and_does_not_disclose_exception(self):
        output = io.StringIO()
        with patch.object(hub, "load_config", side_effect=OSError("SECRET-token")), contextlib.redirect_stdout(output):
            self.assertEqual(hub.main(["--config", "missing"]), 3)
        self.assertNotIn("SECRET", output.getvalue())

    def test_total_timeout_is_critical(self):
        with self.assertRaises(hub.CheckError) as raised:
            hub.deadline(None, None)
        self.assertEqual(raised.exception.code, 2)


class EnrollmentChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("enroll_test", ROOT / "scripts/setup-smart-hub.py")
        cls.enroll = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.enroll)

    def test_private_write_refuses_existing_config(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "hub.json"
            target.write_text("existing-secret")
            with patch.object(self.enroll.grp, "getgrnam", return_value=MagicMock(gr_gid=123)), \
                    patch.object(self.enroll.Path, "lstat", return_value=MagicMock(st_uid=0, st_mode=0o40750)), \
                    patch.object(self.enroll.Path, "is_symlink", return_value=False):
                with self.assertRaises(FileExistsError):
                    self.enroll.save_config(target, config())
            self.assertEqual(target.read_text(), "existing-secret")

    def test_private_write_uses_0640_and_does_not_print_token(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "hub.json"
            output = io.StringIO()
            with patch.object(self.enroll.grp, "getgrnam", return_value=MagicMock(gr_gid=123)), \
                    patch.object(self.enroll.Path, "lstat", return_value=MagicMock(st_uid=0, st_mode=0o40750)), \
                    patch.object(self.enroll.Path, "is_symlink", return_value=False), \
                    patch.object(self.enroll.os, "fchown") as owner, contextlib.redirect_stdout(output):
                self.enroll.save_config(target, config())
            owner.assert_called_once()
            self.assertEqual(target.stat().st_mode & 0o777, 0o640)
            self.assertEqual(json.loads(target.read_text())["token"], "SECRET-token")
            self.assertNotIn("SECRET", output.getvalue())

    def test_pkce_pairing_never_prints_token(self):
        digest = hashlib.sha256(b"certificate").hexdigest()
        tls = MagicMock()
        tls.__enter__.return_value.getpeercert.return_value = b"certificate"
        tls_context = MagicMock()
        tls_context.wrap_socket.return_value = tls
        replies = [{"code": "pair-code"}, {"access_token": "SECRET-token"},
                   [{"id": "lamp", "isReachable": True, "attributes": {"customName": "Lamp"}}]]
        output = io.StringIO()
        with patch.object(self.enroll.socket, "create_connection", return_value=MagicMock()), \
                patch.object(self.enroll.hub, "context", return_value=tls_context), \
                patch.object(self.enroll.hub, "request", side_effect=replies) as request, \
                patch("builtins.input", side_effect=[digest[-12:], "", "y"]), \
                contextlib.redirect_stdout(output):
            saved = self.enroll.enroll("dirigera", "192.0.2.11")
        self.assertEqual(saved["token"], "SECRET-token")
        self.assertEqual(saved["expected_devices"], ["lamp"])
        self.assertIn("code_challenge_method=S256", request.call_args_list[0].args[1])
        self.assertFalse(request.call_args_list[1].kwargs["authenticated"])
        self.assertNotIn("SECRET", output.getvalue())



class HueChecks(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        EnrollmentChecks.setUpClass()

    def payload(self, status="connected", extra=None):
        resources = [
            {"id": "lamp", "type": "device", "metadata": {"name": "Living room"}},
            {"id": "zigbee-1", "type": "zigbee_connectivity",
             "owner": {"rid": "lamp", "rtype": "device"}, "status": status},
            {"id": "light-1", "type": "light", "on": {"on": False}},
        ]
        return {"errors": [], "data": resources + (extra or [])}

    def test_hue_light_off_but_connected_is_ok(self):
        devices = hub.inventory("hue", self.payload())
        self.assertEqual(list(devices), ["lamp"])
        self.assertEqual(devices["lamp"]["name"], "Living room")
        self.assertEqual(hub.evaluate(devices, ["lamp"])[0], 0)

    def test_hue_disconnected_and_connectivity_issue_are_critical(self):
        for state in ("disconnected", "connectivity_issue"):
            devices = hub.inventory("hue", self.payload(state))
            self.assertEqual(hub.evaluate(devices, ["lamp"])[0], 2)

    def test_hue_unknown_and_one_way_status_do_not_pass(self):
        for state in ("unidirectional_incoming", "pending_discovery", "new_status", None):
            devices = hub.inventory("hue", self.payload(state))
            self.assertEqual(hub.evaluate(devices, ["lamp"])[0], 3)

    def test_hue_missing_device_uses_stable_device_id(self):
        devices = hub.inventory("hue", {"errors": [], "data": []})
        self.assertEqual(hub.evaluate(devices, ["lamp"])[0], 2)

    def test_hue_missing_or_multiple_connectivity_services_stay_unknown(self):
        p = self.payload()
        p["data"] = p["data"][:1]
        self.assertEqual(hub.evaluate(hub.inventory("hue", p), ["lamp"])[0], 3)
        p = self.payload(extra=[{"id": "zigbee-2", "type": "zigbee_connectivity",
                                 "owner": {"rid": "lamp", "rtype": "device"}, "status": "connected"}])
        self.assertEqual(hub.evaluate(hub.inventory("hue", p), ["lamp"])[0], 3)

    def test_hue_malformed_envelope_errors_and_duplicate_ids(self):
        for p in ([], {"data": []}, {"errors": [], "data": None},
                  {"errors": [{"description": "SECRET"}], "data": []},
                  self.payload(extra=[{"id": "lamp", "type": "device"}])):
            with self.assertRaises(hub.CheckError) as raised:
                hub.inventory("hue", p)
            self.assertNotIn("SECRET", str(raised.exception))

    def test_hue_invalid_connectivity_owner_is_unknown(self):
        p = self.payload()
        p["data"][1]["owner"] = None
        with self.assertRaises(hub.CheckError):
            hub.inventory("hue", p)

    def test_hue_uses_https_443_and_application_key_header(self):
        conn = TransportChecks().connection(body=b'{"errors":[],"data":[]}')
        with patch.object(hub.http.client, "HTTPSConnection", return_value=conn) as factory:
            hub.request(config("hue"), "/clip/v2/resource")
        self.assertEqual(factory.call_args.args, ("192.0.2.11", 443))
        headers = conn.request.call_args.kwargs["headers"]
        self.assertEqual(headers["hue-application-key"], "SECRET-token")
        self.assertNotIn("Authorization", headers)

    def test_hue_changed_certificate_never_receives_application_key(self):
        conn = TransportChecks().connection()
        cfg = config("hue")
        cfg["certificate_sha256"] = "0" * 64
        with patch.object(hub.http.client, "HTTPSConnection", return_value=conn):
            with self.assertRaises(hub.CheckError):
                hub.request(cfg, "/clip/v2/resource")
        conn.request.assert_not_called()

class HiddenInputChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        EnrollmentChecks.setUpClass()
        cls.setup = EnrollmentChecks.enroll

    def test_hidden_input_refuses_echo_fallback(self):
        import warnings
        def fallback(prompt):
            warnings.warn('cannot hide input', self.setup.getpass.GetPassWarning)
            self.fail('must stop before echoed input')
        with patch.object(self.setup.getpass, 'getpass', side_effect=fallback):
            with self.assertRaises(self.setup.hub.CheckError):
                self.setup.hidden_token('Token: ')

    def test_hue_enrollment_uses_hidden_input(self):
        setup = self.setup
        digest = hashlib.sha256(b'certificate').hexdigest()
        tls = MagicMock()
        tls.__enter__.return_value.getpeercert.return_value = b'certificate'
        ctx = MagicMock()
        ctx.wrap_socket.return_value = tls
        output = io.StringIO()
        with patch.object(setup.socket, 'create_connection'), \
                patch.object(setup.hub, 'context', return_value=ctx), \
                patch.object(setup, 'hidden_token', return_value='SECRET-token') as hidden, \
                patch.object(setup.hub, 'request', return_value=HueChecks().payload()), \
                patch('builtins.input', side_effect=[digest[-12:], 'y']), \
                contextlib.redirect_stdout(output):
            saved = setup.enroll('hue', '192.0.2.10')
        self.assertEqual(saved['token'], 'SECRET-token')
        hidden.assert_called_once()
        self.assertNotIn('SECRET', output.getvalue())

if __name__ == "__main__":
    unittest.main()
