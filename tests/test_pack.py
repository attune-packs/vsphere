from __future__ import annotations

import importlib.util
import io
import os
import re
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lib import vsphere_client as client


class Context:
    def __init__(self, value):
        self.value = value

    def __enter__(self):
        return self.value

    def __exit__(self, exc_type, exc, traceback):
        return None


class MetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.actions = {
            path.stem: path.read_text(encoding="utf-8")
            for path in sorted((ROOT / "actions").glob("*.yaml"))
        }

    def test_curated_action_inventory(self):
        self.assertEqual(
            {
                "inventory_list",
                "vm_list",
                "vm_get",
                "vm_create_from_template",
                "vm_clone",
                "vm_cpu_memory_set",
                "vm_disk",
                "vm_nic",
                "vm_power",
                "snapshot",
                "tag_category",
                "tag",
                "tag_association",
                "vm_migrate",
                "vm_relocate",
                "guest_tools_get",
                "guest_process",
                "guest_file",
                "task_status",
            },
            set(self.actions),
        )

    def test_actions_have_flat_key_backed_json_contracts(self):
        for name, text in self.actions.items():
            with self.subTest(action=name):
                expected = {
                    "ref": f"vsphere.{name}",
                    "runner_type": "python",
                    "runtime_version": '">=3.10"',
                    "entry_point": "vsphere_action.py",
                    "parameter_delivery": "stdin",
                    "parameter_format": "json",
                    "output_format": "json",
                }
                for field, value in expected.items():
                    self.assertRegex(text, rf"(?m)^{field}: {re.escape(value)}$")
                self.assertIn("default_execution_permission_set_refs: [standard]", text)
                self.assertRegex(
                    text, r"profile_key: \{[^\n]*default: pack\.vsphere\.vcenter"
                )
                for output in ("operation", "data", "meta"):
                    self.assertRegex(text, rf"(?m)^  {output}: \{{type:")
                self.assertNotRegex(
                    text, r"(?m)^  (username|password|host|port|verify_tls|ca_cert):"
                )

    def test_guest_credentials_and_sensitive_process_fields_are_separate(self):
        for name in ("guest_process", "guest_file"):
            self.assertRegex(
                self.actions[name],
                r"guest_credential_key: \{[^\n]*default: pack\.vsphere\.guest",
            )
        self.assertRegex(
            self.actions["guest_process"], r"arguments: \{[^\n]*secret: true"
        )
        self.assertRegex(
            self.actions["guest_process"], r"environment: \{[^\n]*secret: true"
        )
        self.assertNotIn("guest_credential_key", self.actions["guest_tools_get"])

    def test_destructive_contracts_expose_confirmation(self):
        for name in (
            "vm_disk",
            "vm_nic",
            "vm_power",
            "snapshot",
            "tag_category",
            "tag",
            "tag_association",
            "guest_file",
        ):
            self.assertRegex(self.actions[name], r"(?m)^  confirmation: \{type: string")

    def test_source_version_license_and_sdk_pin(self):
        revision = "eed7a36730d4e3f3c9463b256e5009374acd6072"
        pack = (ROOT / "pack.yaml").read_text(encoding="utf-8")
        source = (ROOT / "SOURCE.md").read_text(encoding="utf-8")
        notice = (ROOT / "NOTICE").read_text(encoding="utf-8")
        self.assertIn(f'source_revision: "{revision}"', pack)
        self.assertIn('source_version: "1.3.5"', pack)
        self.assertIn('license: "Apache-2.0"', pack)
        self.assertIn(revision, source)
        self.assertIn(revision, notice)
        self.assertEqual(
            "pyvmomi==9.1.0.0\n",
            (ROOT / "requirements.txt").read_text(encoding="utf-8"),
        )
        self.assertIn("Apache License", (ROOT / "LICENSE").read_text(encoding="utf-8"))


class ValidationTests(unittest.TestCase):
    def profile(self, **changes):
        value = {"host": "vc.example.invalid", "username": "svc", "password": "secret"}
        value.update(changes)
        return value

    def test_profile_requires_verified_tls_and_bounded_timeouts(self):
        parsed = client._profile(self.profile())
        self.assertTrue(parsed["verify_tls"])
        self.assertEqual(30, parsed["connect_timeout_seconds"])
        for changes in (
            {"verify_tls": False},
            {"connect_timeout_seconds": 0},
            {"connect_timeout_seconds": 121},
            {"host": "https://vc.invalid/sdk"},
            {"extra_secret": "value"},
            {"minimum_api_version": "latest"},
        ):
            with (
                self.subTest(changes=changes),
                self.assertRaises(client.VspherePackError),
            ):
                client._profile(self.profile(**changes))

    def test_moid_validation_rejects_names_paths_and_injection(self):
        for value in ("vm-42", "group-v123", "snapshot-9", "task-a_b"):
            self.assertEqual(value, client._moid(value, "moid"))
        for value in ("production", "../vm-1", "vm-1/child", "vm-1\nsecret", ""):
            with self.subTest(value=value), self.assertRaises(client.VspherePackError):
                client._moid(value, "moid")

    def test_guest_key_accepts_only_guest_username_and_password(self):
        self.assertEqual(
            {"username": "guest", "password": "secret"},
            client._guest_credentials({"username": "guest", "password": "secret"}),
        )
        with self.assertRaisesRegex(client.VspherePackError, "may contain only"):
            client._guest_credentials(
                {"username": "guest", "password": "secret", "host": "leak"}
            )

    def test_fetch_key_accepts_json_without_leaking_lookup_exception(self):
        parsed = types.SimpleNamespace(
            data=types.SimpleNamespace(value='{"host":"vc.invalid"}')
        )
        fake_attune = types.ModuleType("attune")
        fake_attune.context = types.SimpleNamespace(client=object())
        fake_secrets = types.ModuleType("attune.api_client.api.secrets")
        fake_secrets.get_key = types.SimpleNamespace(
            sync_detailed=mock.Mock(
                return_value=types.SimpleNamespace(status_code=200, parsed=parsed)
            )
        )
        modules = {
            "attune": fake_attune,
            "attune.api_client": types.ModuleType("attune.api_client"),
            "attune.api_client.api": types.ModuleType("attune.api_client.api"),
            "attune.api_client.api.secrets": fake_secrets,
        }
        with mock.patch.dict(sys.modules, modules):
            self.assertEqual(
                "vc.invalid",
                client._fetch_key("pack.vsphere.vcenter", "vCenter profile")["host"],
            )
        fake_secrets.get_key.sync_detailed.assert_called_once_with(
            "pack.vsphere.vcenter", client=fake_attune.context.client
        )
        fake_secrets.get_key.sync_detailed.side_effect = RuntimeError("DO-NOT-LEAK")
        with (
            mock.patch.dict(sys.modules, modules),
            self.assertRaises(client.VspherePackError) as caught,
        ):
            client._fetch_key("pack.vsphere.vcenter", "vCenter profile")
        self.assertNotIn("DO-NOT-LEAK", str(caught.exception))


class InventoryAndTaskTests(unittest.TestCase):
    def test_object_selection_uses_exact_moid_not_duplicate_name_and_closes_view(self):
        class VirtualMachine:
            pass

        first = types.SimpleNamespace(_moId="vm-1", name="duplicate")
        second = types.SimpleNamespace(_moId="vm-2", name="duplicate")
        view = types.SimpleNamespace(view=[first, second], DestroyView=mock.Mock())
        value = object.__new__(client.VsphereClient)
        value.content = types.SimpleNamespace(
            rootFolder=object(),
            viewManager=types.SimpleNamespace(
                CreateContainerView=mock.Mock(return_value=view)
            ),
        )
        self.assertIs(second, value.object("vm-2", VirtualMachine, "vm_moid"))
        view.DestroyView.assert_called_once_with()
        with self.assertRaises(client.VspherePackError):
            value.object("vm-3", VirtualMachine, "vm_moid")
        self.assertEqual(2, view.DestroyView.call_count)

    def test_inventory_path_returns_components_and_detects_parent_cycle(self):
        root = object()
        dc = types.SimpleNamespace(_moId="datacenter-1", name="DC", parent=root)
        folder = types.SimpleNamespace(_moId="group-v1", name="apps", parent=dc)
        vm = types.SimpleNamespace(_moId="vm-1", name="web", parent=folder)
        value = object.__new__(client.VsphereClient)
        value.content = types.SimpleNamespace(rootFolder=root)
        self.assertEqual(["DC", "apps", "web"], value.path_parts(vm))
        folder.parent = vm
        with self.assertRaisesRegex(client.VspherePackError, "cycle"):
            value.path_parts(vm)

    def test_task_poll_timeout_is_bounded_and_does_not_retry_mutation(self):
        task = types.SimpleNamespace(
            _moId="task-1", info=types.SimpleNamespace(state="running")
        )
        value = object.__new__(client.VsphereClient)
        with (
            mock.patch("time.monotonic", side_effect=[10.0, 12.0]),
            mock.patch("time.sleep") as sleep,
        ):
            result = value.wait_task(task, 1, 1)
        self.assertTrue(result["timed_out"])
        self.assertFalse(result["complete"])
        sleep.assert_not_called()

    def test_task_fault_redacts_remote_message(self):
        class SecretFault(Exception):
            pass

        fault = SecretFault("password=DO-NOT-LEAK")
        task = types.SimpleNamespace(
            _moId="task-1",
            info=types.SimpleNamespace(
                state="error", error=types.SimpleNamespace(fault=fault)
            ),
        )
        value = object.__new__(client.VsphereClient)
        with self.assertRaises(client.VspherePackError) as caught:
            value.wait_task(task, 1, 1)
        self.assertIn("SecretFault", str(caught.exception))
        self.assertNotIn("DO-NOT-LEAK", str(caught.exception))


class PlacementAndDestructiveTests(unittest.TestCase):
    def test_datastore_checks_access_maintenance_and_reserve(self):
        healthy = types.SimpleNamespace(
            _moId="datastore-1",
            summary=types.SimpleNamespace(
                accessible=True, maintenanceMode="normal", freeSpace=10 * 1024**3
            ),
        )
        client._datastore_ready(healthy, 5 * 1024**3, 5 * 1024**3)
        for changes in (
            {"accessible": False},
            {"maintenanceMode": "inMaintenance"},
            {"freeSpace": 10 * 1024**3 - 1},
        ):
            summary = types.SimpleNamespace(
                accessible=True, maintenanceMode="normal", freeSpace=10 * 1024**3
            )
            for key, value in changes.items():
                setattr(summary, key, value)
            datastore = types.SimpleNamespace(_moId="datastore-1", summary=summary)
            with (
                self.subTest(changes=changes),
                self.assertRaises(client.VspherePackError),
            ):
                client._datastore_ready(datastore, 5 * 1024**3, 5 * 1024**3)

    def test_placement_rejects_host_outside_pool_and_unmounted_datastore(self):
        datastore = types.SimpleNamespace(_moId="datastore-1")
        good = types.SimpleNamespace(
            _moId="host-1",
            datastore=[datastore],
            runtime=types.SimpleNamespace(
                connectionState="connected", inMaintenanceMode=False
            ),
        )
        pool = types.SimpleNamespace(owner=types.SimpleNamespace(host=[good]))
        client._validate_placement(pool, datastore, good)
        outsider = types.SimpleNamespace(_moId="host-2", datastore=[datastore])
        with self.assertRaisesRegex(client.VspherePackError, "not in"):
            client._validate_placement(pool, datastore, outsider)
        missing = types.SimpleNamespace(_moId="datastore-2")
        with self.assertRaisesRegex(client.VspherePackError, "not mounted"):
            client._validate_placement(pool, missing, good)

    def test_hard_power_actions_require_exact_confirmation_before_mutation(self):
        class VirtualMachine:
            pass

        vim = types.SimpleNamespace(VirtualMachine=VirtualMachine)
        vm = types.SimpleNamespace(
            _moId="vm-42",
            runtime=types.SimpleNamespace(powerState="poweredOn"),
            guest=types.SimpleNamespace(toolsRunningStatus="guestToolsRunning"),
            ResetVM_Task=mock.Mock(return_value=types.SimpleNamespace(_moId="task-1")),
        )
        fake = types.SimpleNamespace(
            object=mock.Mock(return_value=vm),
            wait_task=mock.Mock(return_value={"task_moid": "task-1"}),
            meta={},
        )
        params = {"vm_moid": "vm-42", "operation": "reset"}
        with (
            mock.patch.object(client, "_sdk", return_value=(None, vim)),
            mock.patch.object(client, "_with_client", return_value=Context(fake)),
        ):
            with self.assertRaisesRegex(client.VspherePackError, "confirmation"):
                client._vm_power(params)
            vm.ResetVM_Task.assert_not_called()
            result = client._vm_power({**params, "confirmation": "RESET vm-42"})
        vm.ResetVM_Task.assert_called_once_with()
        self.assertEqual("reset", result["data"]["power_operation"])

    def test_snapshot_lookup_cannot_cross_vm_boundary(self):
        owned = types.SimpleNamespace(_moId="snapshot-1")
        other = types.SimpleNamespace(_moId="snapshot-2")
        vm = types.SimpleNamespace(
            _moId="vm-1",
            snapshot=types.SimpleNamespace(
                rootSnapshotList=[
                    types.SimpleNamespace(snapshot=owned, childSnapshotList=[]),
                ]
            ),
        )
        self.assertIs(owned, client._snapshot_object(object(), vm, "snapshot-1"))
        with self.assertRaisesRegex(client.VspherePackError, "does not belong"):
            client._snapshot_object(object(), vm, other._moId)


class GuestAndHttpTests(unittest.TestCase):
    def test_artifact_paths_are_confined_and_symlinks_rejected(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            tempfile.TemporaryDirectory() as outside,
        ):
            root = Path(directory)
            (root / "input.bin").write_bytes(b"data")
            (root / "escape").symlink_to(Path(outside) / "file")
            with mock.patch.dict(
                os.environ, {"ATTUNE_ARTIFACTS_DIR": directory}, clear=True
            ):
                self.assertEqual(
                    root / "input.bin", client._artifact_path("input.bin", output=False)
                )
                with self.assertRaises(client.VspherePackError):
                    client._artifact_path("../outside", output=True)
                with self.assertRaises(client.VspherePackError):
                    client._artifact_path("escape", output=True)

    def test_guest_transfer_url_requires_https_and_profile_host(self):
        value = types.SimpleNamespace(
            settings={"host": "vc.example.invalid"},
        )
        self.assertEqual(
            "https://vc.example.invalid/guestFile?id=1",
            client._safe_transfer_url(value, "https://*/guestFile?id=1"),
        )
        for url in (
            "http://vc.example.invalid/file",
            "https://evil.invalid/file",
            "https://user:pass@vc.example.invalid/file",
        ):
            with self.subTest(url=url), self.assertRaises(client.VspherePackError):
                client._safe_transfer_url(value, url)

    def test_current_tag_routes_and_delete_confirmation(self):
        fake_client = types.SimpleNamespace(meta={})
        rest = types.SimpleNamespace(request=mock.Mock(return_value=None))
        params = {
            "operation": "detach",
            "tag_id": "tag-uuid",
            "object_type": "VirtualMachine",
            "object_moid": "vm-42",
        }
        with self.assertRaises(client.VspherePackError):
            client._tag_association_request(
                params,
                fake_client,
                rest,
                "detach",
                "VirtualMachine",
                "vm-42",
                {"object_id": {}},
            )
        rest.request.assert_not_called()
        result = client._tag_association_request(
            {**params, "confirmation": "DETACH_TAG tag-uuid FROM VirtualMachine vm-42"},
            fake_client,
            rest,
            "detach",
            "VirtualMachine",
            "vm-42",
            {"object_id": {}},
        )
        path = rest.request.call_args.args[1]
        self.assertEqual("/api/cis/tagging/tag-association/tag-uuid", path)
        self.assertFalse(result["data"]["attached"])


class EntryPointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location(
            "vsphere_action_test", ROOT / "actions" / "vsphere_action.py"
        )
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def test_invalid_input_and_unknown_errors_do_not_echo_secrets(self):
        cases = [
            ("[]", None),
            ('{"password":"DO-NOT-ECHO"}', RuntimeError("DO-NOT-ECHO")),
        ]
        for raw, error in cases:
            stdout, stderr = io.StringIO(), io.StringIO()
            patch_execute = (
                mock.patch.object(self.module, "execute_action", side_effect=error)
                if error
                else mock.patch.object(self.module, "execute_action")
            )
            with (
                patch_execute,
                mock.patch.dict(os.environ, {"ATTUNE_ACTION": "vsphere.vm_get"}),
                mock.patch("sys.stdin", io.StringIO(raw)),
                mock.patch("sys.stdout", stdout),
                mock.patch("sys.stderr", stderr),
            ):
                self.assertEqual(1, self.module.main())
            self.assertEqual("", stdout.getvalue())
            self.assertNotIn("DO-NOT-ECHO", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
