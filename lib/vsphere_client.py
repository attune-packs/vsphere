"""Safe pyVmomi and vSphere Automation API operations for the Attune pack."""

from __future__ import annotations

import base64
import importlib.metadata
import json
import os
import re
import socket
import ssl
import stat
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

DEFAULT_PROFILE_KEY = "vsphere.vcenter"
DEFAULT_GUEST_KEY = "vsphere.guest"
MAX_API_RESPONSE = 4 * 1024 * 1024
MAX_GUEST_FILE = 128 * 1024 * 1024
MOID_PATTERN = re.compile(
    r"^[A-Za-z][A-Za-z0-9_-]{0,63}-[A-Za-z0-9][A-Za-z0-9_-]{0,127}$"
)


class VspherePackError(Exception):
    """An action-safe error that contains no remote body or credentials."""


def _sdk():
    try:
        from pyVim import connect
        from pyVmomi import vim
    except ImportError:
        raise VspherePackError("pyVmomi 9.1.0.0 is required on the worker") from None
    return connect, vim


def _fetch_key(key_ref: str, purpose: str) -> dict[str, Any]:
    if not isinstance(key_ref, str) or not key_ref.strip():
        raise VspherePackError(f"{purpose}_key must be a non-empty string")
    try:
        import attune
        from attune.api_client.api.secrets import get_key

        response = get_key.sync_detailed(client=attune.context.client, key_ref=key_ref)
    except Exception as exc:
        raise VspherePackError(
            f"could not read {purpose} Key ({type(exc).__name__})"
        ) from None
    if response.status_code != 200 or response.parsed is None:
        if response.status_code == 404:
            raise VspherePackError(f"{purpose} Key was not found")
        raise VspherePackError(
            f"could not read {purpose} Key (HTTP {response.status_code})"
        )
    value = response.parsed.data.value
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            raise VspherePackError(
                f"{purpose} Key must contain a JSON object"
            ) from None
    if not isinstance(value, dict):
        raise VspherePackError(f"{purpose} Key must contain an object")
    return value


def _text(value: Any, name: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise VspherePackError(
            f"{name} must be a {'string' if allow_empty else 'non-empty string'}"
        )
    if any(ord(character) < 32 for character in value):
        raise VspherePackError(f"{name} contains a control character")
    return value


def _moid(value: Any, name: str) -> str:
    value = _text(value, name)
    if not MOID_PATTERN.fullmatch(value):
        raise VspherePackError(f"{name} must be a valid managed object ID")
    return value


def _integer(
    params: dict[str, Any], name: str, default: int | None, minimum: int, maximum: int
) -> int | None:
    value = params.get(name, default)
    if value is None:
        return None
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise VspherePackError(f"{name} must be an integer from {minimum} to {maximum}")
    return value


def _boolean(params: dict[str, Any], name: str, default: bool = False) -> bool:
    value = params.get(name, default)
    if not isinstance(value, bool):
        raise VspherePackError(f"{name} must be a boolean")
    return value


def _required_integer(
    params: dict[str, Any], name: str, minimum: int, maximum: int
) -> int:
    value = _integer(params, name, None, minimum, maximum)
    if value is None:
        raise VspherePackError(f"{name} is required")
    return value


def _confirmation(params: dict[str, Any], expected: str) -> None:
    if params.get("confirmation") != expected:
        raise VspherePackError(f"confirmation must equal '{expected}'")


def _profile(value: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        "host",
        "port",
        "username",
        "password",
        "verify_tls",
        "ca_cert",
        "connect_timeout_seconds",
        "minimum_api_version",
    }
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise VspherePackError(
            f"vCenter profile contains unsupported field '{unknown[0]}'"
        )
    host = _text(value.get("host"), "profile host")
    if "://" in host or "/" in host or "@" in host:
        raise VspherePackError(
            "profile host must be a hostname or IP address without a URL scheme or path"
        )
    username = _text(value.get("username"), "profile username")
    if ":" in username:
        raise VspherePackError("profile username must not contain ':'")
    password = _text(value.get("password"), "profile password", allow_empty=True)
    port = value.get("port", 443)
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise VspherePackError("profile port must be an integer from 1 to 65535")
    verify_tls = value.get("verify_tls", True)
    if verify_tls is not True:
        raise VspherePackError(
            "profile verify_tls must be true; insecure TLS is not supported"
        )
    ca_cert = value.get("ca_cert")
    if ca_cert is not None:
        ca_cert = _text(ca_cert, "profile ca_cert")
    connect_timeout = value.get("connect_timeout_seconds", 30)
    if (
        isinstance(connect_timeout, bool)
        or not isinstance(connect_timeout, int)
        or not 1 <= connect_timeout <= 120
    ):
        raise VspherePackError(
            "profile connect_timeout_seconds must be an integer from 1 to 120"
        )
    minimum = value.get("minimum_api_version", "7.0")
    if not isinstance(minimum, str) or not re.fullmatch(
        r"[0-9]+(?:\.[0-9]+){0,3}", minimum
    ):
        raise VspherePackError(
            "profile minimum_api_version must be a numeric vSphere API version"
        )
    return {
        "host": host,
        "port": port,
        "username": username,
        "password": password,
        "verify_tls": True,
        "ca_cert": ca_cert,
        "connect_timeout_seconds": connect_timeout,
        "minimum_api_version": minimum,
    }


def _guest_credentials(value: dict[str, Any]) -> dict[str, str]:
    if set(value) - {"username", "password"}:
        raise VspherePackError(
            "guest credential Key may contain only username and password"
        )
    return {
        "username": _text(value.get("username"), "guest username"),
        "password": _text(value.get("password"), "guest password", allow_empty=True),
    }


def _version_tuple(value: str) -> tuple[int, ...]:
    match = re.match(r"^(\d+(?:\.\d+)*)", value)
    parts = tuple(int(part) for part in match.group(1).split(".")) if match else (0,)
    return parts + (0,) * (4 - len(parts))


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise VspherePackError("vSphere HTTP redirect was refused")


class VsphereClient:
    def __init__(self, settings: dict[str, Any]):
        self.settings = _profile(settings)
        self.ssl_context = ssl.create_default_context(cadata=self.settings["ca_cert"])
        self.si = None
        self.content = None
        self.api_version = None
        self._previous_socket_timeout = None

    def __enter__(self) -> VsphereClient:
        connect, _ = _sdk()
        self._previous_socket_timeout = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(self.settings["connect_timeout_seconds"])
            self.si = connect.SmartConnect(
                host=self.settings["host"],
                port=self.settings["port"],
                user=self.settings["username"],
                pwd=self.settings["password"],
                sslContext=self.ssl_context,
                httpConnectionTimeout=self.settings["connect_timeout_seconds"],
                connectionPoolTimeout=self.settings["connect_timeout_seconds"],
            )
            self.content = self.si.RetrieveContent()
        except Exception as exc:
            socket.setdefaulttimeout(self._previous_socket_timeout)
            raise VspherePackError(
                f"vCenter connection failed ({type(exc).__name__})"
            ) from None
        self.api_version = str(self.content.about.apiVersion)
        if _version_tuple(self.api_version) < _version_tuple(
            self.settings["minimum_api_version"]
        ):
            self.__exit__(None, None, None)
            raise VspherePackError(
                f"vCenter API {self.api_version} is below required {self.settings['minimum_api_version']}"
            )
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        if self.si is not None:
            connect, _ = _sdk()
            try:
                connect.Disconnect(self.si)
            except Exception:
                pass
        if self._previous_socket_timeout is not None:
            socket.setdefaulttimeout(self._previous_socket_timeout)
            self._previous_socket_timeout = None

    @property
    def meta(self) -> dict[str, Any]:
        try:
            sdk_version = importlib.metadata.version("pyvmomi")
        except importlib.metadata.PackageNotFoundError:
            sdk_version = None
        return {
            "vcenter_api_version": self.api_version,
            "pyvmomi_version": sdk_version,
            "mutation_retried": False,
        }

    def list_objects(self, types: list[Any]) -> list[Any]:
        try:
            view = self.content.viewManager.CreateContainerView(
                self.content.rootFolder, types, True
            )
        except Exception as exc:
            raise VspherePackError(
                f"inventory query failed ({type(exc).__name__})"
            ) from None
        try:
            return list(view.view)
        finally:
            try:
                view.DestroyView()
            except Exception:
                pass

    def object(self, moid: str, vim_type: Any, name: str) -> Any:
        expected = _moid(moid, name)
        for item in self.list_objects([vim_type]):
            if item._moId == expected:
                return item
        raise VspherePackError(
            f"{name} '{expected}' was not found as {vim_type.__name__}"
        )

    def network(self, moid: str) -> Any:
        _, vim = _sdk()
        expected = _moid(moid, "network_moid")
        types = [vim.Network, vim.dvs.DistributedVirtualPortgroup]
        if hasattr(vim, "OpaqueNetwork"):
            types.append(vim.OpaqueNetwork)
        for item in self.list_objects(types):
            if item._moId == expected:
                return item
        raise VspherePackError(
            f"network_moid '{expected}' was not found as a supported network"
        )

    def task(self, moid: str) -> Any:
        _, vim = _sdk()
        expected = _moid(moid, "task_moid")
        try:
            return vim.Task(expected, self.si._stub)
        except Exception as exc:
            raise VspherePackError(
                f"task_moid could not be addressed ({type(exc).__name__})"
            ) from None

    def path_parts(self, obj: Any) -> list[str]:
        parts: list[str] = []
        current = obj
        seen: set[str] = set()
        while current is not None and current is not self.content.rootFolder:
            moid = getattr(current, "_moId", "")
            if moid in seen:
                raise VspherePackError("inventory parent cycle detected")
            seen.add(moid)
            name = getattr(current, "name", None)
            if name:
                parts.append(str(name))
            current = getattr(current, "parent", None)
        parts.reverse()
        return parts

    def record(self, obj: Any) -> dict[str, Any]:
        parts = self.path_parts(obj)
        return {
            "moid": obj._moId,
            "name": str(obj.name),
            "type": obj.__class__.__name__.split(".")[-1],
            "inventory_path": "/" + "/".join(parts),
            "inventory_path_components": parts,
        }

    def wait_task(
        self, task: Any, timeout_seconds: int, poll_interval_seconds: int
    ) -> dict[str, Any]:
        deadline = time.monotonic() + timeout_seconds
        while True:
            try:
                state = str(task.info.state)
            except Exception as exc:
                raise VspherePackError(
                    f"vSphere task status failed ({type(exc).__name__})"
                ) from None
            if state not in {"queued", "running"}:
                break
            if time.monotonic() >= deadline:
                return {
                    "task_moid": task._moId,
                    "state": state,
                    "complete": False,
                    "timed_out": True,
                    "result_moid": None,
                }
            time.sleep(
                min(poll_interval_seconds, max(0.0, deadline - time.monotonic()))
            )
        if state != "success":
            fault = getattr(task.info, "error", None)
            fault_type = type(getattr(fault, "fault", fault)).__name__
            raise VspherePackError(f"vSphere task '{task._moId}' failed ({fault_type})")
        result = getattr(task.info, "result", None)
        return {
            "task_moid": task._moId,
            "state": state,
            "complete": True,
            "timed_out": False,
            "result_moid": getattr(result, "_moId", None),
        }


def _inventory_types(kind: str) -> list[Any]:
    _, vim = _sdk()
    mapping = {
        "datacenter": [vim.Datacenter],
        "cluster": [vim.ClusterComputeResource],
        "host": [vim.HostSystem],
        "datastore": [vim.Datastore],
        "folder": [vim.Folder],
        "network": [vim.Network, vim.dvs.DistributedVirtualPortgroup],
    }
    if hasattr(vim, "OpaqueNetwork"):
        mapping["network"].append(vim.OpaqueNetwork)
    if kind not in mapping:
        raise VspherePackError(
            "kind must be datacenter, cluster, host, datastore, network, or folder"
        )
    return mapping[kind]


def _vm_record(client: VsphereClient, vm: Any, details: bool = False) -> dict[str, Any]:
    value = client.record(vm)
    summary = vm.summary
    value.update(
        {
            "power_state": str(summary.runtime.powerState),
            "template": bool(summary.config.template),
            "cpu_count": summary.config.numCpu,
            "memory_mib": summary.config.memorySizeMB,
            "host_moid": getattr(summary.runtime.host, "_moId", None),
        }
    )
    if details:
        _, vim = _sdk()
        disks = []
        nics = []
        for device in vm.config.hardware.device:
            if isinstance(device, vim.vm.device.VirtualDisk):
                disks.append(
                    {
                        "device_key": device.key,
                        "label": device.deviceInfo.label,
                        "capacity_bytes": int(device.capacityInBytes),
                        "controller_key": device.controllerKey,
                        "unit_number": device.unitNumber,
                        "datastore_moid": getattr(
                            getattr(device, "backing", None), "datastore", None
                        )._moId
                        if getattr(getattr(device, "backing", None), "datastore", None)
                        else None,
                    }
                )
            elif isinstance(device, vim.vm.device.VirtualEthernetCard):
                backing = getattr(device, "backing", None)
                network = getattr(backing, "network", None)
                nics.append(
                    {
                        "device_key": device.key,
                        "label": device.deviceInfo.label,
                        "mac_address": device.macAddress,
                        "network_moid": getattr(network, "_moId", None),
                        "connected": getattr(
                            getattr(device, "connectable", None), "connected", None
                        ),
                        "start_connected": getattr(
                            getattr(device, "connectable", None), "startConnected", None
                        ),
                        "model": device.__class__.__name__.split(".")[-1],
                    }
                )
        value["disks"] = disks
        value["nics"] = nics
        value["tools_running_status"] = str(vm.guest.toolsRunningStatus)
    return value


def _task_limits(params: dict[str, Any]) -> tuple[int, int]:
    return (
        int(_integer(params, "task_timeout_seconds", 600, 1, 7200)),
        int(_integer(params, "poll_interval_seconds", 2, 1, 10)),
    )


def _datastore_ready(
    datastore: Any, required_bytes: int = 0, reserve_bytes: int = 0
) -> None:
    summary = datastore.summary
    if not bool(summary.accessible):
        raise VspherePackError(f"datastore '{datastore._moId}' is not accessible")
    maintenance = str(getattr(summary, "maintenanceMode", "normal"))
    if maintenance != "normal":
        raise VspherePackError(
            f"datastore '{datastore._moId}' is in maintenance state '{maintenance}'"
        )
    if int(summary.freeSpace) < required_bytes + reserve_bytes:
        raise VspherePackError(
            f"datastore '{datastore._moId}' does not meet the explicit free-space requirement"
        )


def _compute_hosts(pool: Any) -> list[Any]:
    owner = pool.owner
    return list(getattr(owner, "host", []) or [])


def _validate_placement(pool: Any, datastore: Any, host: Any | None) -> None:
    hosts = _compute_hosts(pool)
    if host is not None and all(candidate._moId != host._moId for candidate in hosts):
        raise VspherePackError(
            "host_moid is not in the resource pool's compute resource"
        )
    candidates = [host] if host is not None else hosts
    compatible = [
        candidate
        for candidate in candidates
        if any(ds._moId == datastore._moId for ds in candidate.datastore)
    ]
    if not compatible:
        raise VspherePackError(
            "datastore_moid is not mounted on an eligible destination host"
        )
    if not any(
        str(candidate.runtime.connectionState) == "connected"
        and not bool(candidate.runtime.inMaintenanceMode)
        for candidate in compatible
    ):
        raise VspherePackError(
            "no connected non-maintenance destination host can access the datastore"
        )


def _device(vm: Any, device_key: int, device_type: Any, name: str) -> Any:
    for item in vm.config.hardware.device:
        if item.key == device_key and isinstance(item, device_type):
            return item
    raise VspherePackError(f"{name} '{device_key}' was not found on VM '{vm._moId}'")


def _network_backing(network: Any) -> Any:
    _, vim = _sdk()
    if isinstance(network, vim.dvs.DistributedVirtualPortgroup):
        port = vim.dvs.PortConnection(
            portgroupKey=network.key,
            switchUuid=network.config.distributedVirtualSwitch.uuid,
        )
        return vim.vm.device.VirtualEthernetCard.DistributedVirtualPortBackingInfo(
            port=port
        )
    if isinstance(network, vim.Network):
        return vim.vm.device.VirtualEthernetCard.NetworkBackingInfo(
            network=network, deviceName=network.name
        )
    if hasattr(vim, "OpaqueNetwork") and isinstance(network, vim.OpaqueNetwork):
        return vim.vm.device.VirtualEthernetCard.OpaqueNetworkBackingInfo(
            opaqueNetworkId=network.summary.opaqueNetworkId,
            opaqueNetworkType=network.summary.opaqueNetworkType,
        )
    raise VspherePackError("network_moid has an unsupported network backing type")


def _artifact_path(relative: Any, *, output: bool) -> Path:
    root_value = os.environ.get("ATTUNE_ARTIFACTS_DIR")
    if not root_value:
        raise VspherePackError(
            "ATTUNE_ARTIFACTS_DIR is required for guest file transfer"
        )
    root = Path(root_value).resolve(strict=True)
    value = _text(relative, "artifact_path")
    if Path(value).is_absolute():
        raise VspherePackError("artifact_path must be relative to ATTUNE_ARTIFACTS_DIR")
    candidate = root.joinpath(value)
    parent = candidate.parent.resolve(strict=True)
    if not parent.is_relative_to(root):
        raise VspherePackError("artifact_path must stay within ATTUNE_ARTIFACTS_DIR")
    resolved = parent / candidate.name
    if resolved.is_symlink():
        raise VspherePackError("artifact_path must not be a symlink")
    if resolved.exists():
        actual = resolved.resolve(strict=True)
        if not actual.is_relative_to(root):
            raise VspherePackError("artifact_path must not escape through a symlink")
        resolved = actual
    elif not output:
        raise VspherePackError("artifact_path was not found")
    return resolved


def _read_artifact(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise VspherePackError(
            f"artifact_path could not be opened safely ({type(exc).__name__})"
        ) from None
    try:
        details = os.fstat(fd)
        if not stat.S_ISREG(details.st_mode):
            raise VspherePackError("artifact_path must reference a regular file")
        if details.st_size > MAX_GUEST_FILE:
            raise VspherePackError("guest upload is limited to 128 MiB")
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            value = stream.read(MAX_GUEST_FILE + 1)
            if len(value) > MAX_GUEST_FILE:
                raise VspherePackError("guest upload is limited to 128 MiB")
            return value
    finally:
        if fd >= 0:
            os.close(fd)


def _safe_transfer_url(client: VsphereClient, value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or parsed.username
        or parsed.password
        or not parsed.path
    ):
        raise VspherePackError("guest transfer returned an unsafe URL")
    host = parsed.hostname
    if host == "*":
        configured = client.settings["host"]
        configured = (
            f"[{configured}]"
            if ":" in configured and not configured.startswith("[")
            else configured
        )
        netloc = configured + (f":{parsed.port}" if parsed.port else "")
        parsed = parsed._replace(netloc=netloc)
    elif host is None or host.lower().rstrip(".") != client.settings[
        "host"
    ].lower().rstrip("."):
        raise VspherePackError("guest transfer host did not match the vCenter profile")
    return urlunsplit(parsed)


def _http_opener(context: ssl.SSLContext):
    return build_opener(_NoRedirect(), HTTPSHandler(context=context))


def _guest_context(
    client: VsphereClient, params: dict[str, Any]
) -> tuple[Any, Any, Any]:
    _, vim = _sdk()
    vm = client.object(
        _moid(params.get("vm_moid"), "vm_moid"), vim.VirtualMachine, "vm_moid"
    )
    if str(vm.runtime.powerState) != "poweredOn":
        raise VspherePackError("guest operation requires a powered-on VM")
    if str(vm.guest.toolsRunningStatus) != "guestToolsRunning":
        raise VspherePackError("guest operation requires running VMware Tools")
    credentials = _guest_credentials(
        _fetch_key(
            params.get("guest_credential_key", DEFAULT_GUEST_KEY), "guest credential"
        )
    )
    auth = vim.vm.guest.NamePasswordAuthentication(
        username=credentials["username"],
        password=credentials["password"],
        interactiveSession=False,
    )
    return vm, auth, client.content.guestOperationsManager


class RestClient:
    """Current /api vSphere Automation client used only for tagging."""

    def __init__(self, client: VsphereClient):
        self.client = client
        host = client.settings["host"]
        host = f"[{host}]" if ":" in host and not host.startswith("[") else host
        port = client.settings["port"]
        self.base_url = f"https://{host}{'' if port == 443 else ':' + str(port)}"
        self.opener = _http_opener(client.ssl_context)
        self.session_id: str | None = None

    def __enter__(self) -> RestClient:
        token = base64.b64encode(
            f"{self.client.settings['username']}:{self.client.settings['password']}".encode()
        ).decode("ascii")
        result = self._request(
            "POST", "/api/session", headers={"Authorization": f"Basic {token}"}
        )
        if not isinstance(result, str) or not result:
            raise VspherePackError(
                "vSphere Automation session returned an invalid identifier"
            )
        self.session_id = result
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        if self.session_id:
            try:
                self._request("DELETE", "/api/session")
            except VspherePackError:
                pass
            self.session_id = None

    def _request(
        self,
        method: str,
        path: str,
        body: Any = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        request_headers = {"Accept": "application/json"}
        if self.session_id:
            request_headers["vmware-api-session-id"] = self.session_id
        request_headers.update(headers or {})
        data = None
        if body is not None:
            data = json.dumps(body, separators=(",", ":")).encode("utf-8")
            request_headers["Content-Type"] = "application/json"
        request = Request(
            self.base_url + path, data=data, headers=request_headers, method=method
        )
        try:
            with self.opener.open(
                request, timeout=self.client.settings["connect_timeout_seconds"]
            ) as response:
                raw = response.read(MAX_API_RESPONSE + 1)
                status = response.status
        except HTTPError as exc:
            raise VspherePackError(
                f"vSphere Automation request failed (HTTP {exc.code})"
            ) from None
        except (URLError, TimeoutError, OSError) as exc:
            raise VspherePackError(
                f"vSphere Automation request failed ({type(exc).__name__})"
            ) from None
        if status < 200 or status >= 300:
            raise VspherePackError(f"vSphere Automation request failed (HTTP {status})")
        if len(raw) > MAX_API_RESPONSE:
            raise VspherePackError("vSphere Automation response exceeded 4 MiB")
        if not raw:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            raise VspherePackError(
                "vSphere Automation response was not valid JSON"
            ) from None

    def request(
        self,
        method: str,
        path: str,
        body: Any = None,
        query: dict[str, str] | None = None,
    ) -> Any:
        if query:
            path += "?" + urlencode(query)
        return self._request(method, path, body)


def _with_client(params: dict[str, Any]) -> VsphereClient:
    settings = _fetch_key(
        params.get("profile_key", DEFAULT_PROFILE_KEY), "vCenter profile"
    )
    return VsphereClient(settings)


def _result(operation: str, data: Any, client: VsphereClient) -> dict[str, Any]:
    return {"operation": operation, "data": data, "meta": client.meta}


def execute_action(operation: str, params: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(params, dict):
        raise VspherePackError("action parameters must be a JSON object")
    handlers = {
        "inventory_list": _inventory_list,
        "vm_list": _vm_list,
        "vm_get": _vm_get,
        "vm_create_from_template": _vm_create_from_template,
        "vm_clone": _vm_clone,
        "vm_cpu_memory_set": _vm_cpu_memory_set,
        "vm_disk": _vm_disk,
        "vm_nic": _vm_nic,
        "vm_power": _vm_power,
        "snapshot": _snapshot,
        "tag_category": _tag_category,
        "tag": _tag,
        "tag_association": _tag_association,
        "vm_migrate": _vm_migrate,
        "vm_relocate": _vm_relocate,
        "guest_tools_get": _guest_tools_get,
        "guest_process": _guest_process,
        "guest_file": _guest_file,
        "task_status": _task_status,
    }
    handler = handlers.get(operation)
    if handler is None:
        raise VspherePackError("unknown vSphere action")
    try:
        return handler(params)
    except VspherePackError:
        raise
    except Exception as exc:
        # pyVmomi faults can include guest credentials, customization data, or remote paths.
        raise VspherePackError(
            f"vSphere operation failed ({type(exc).__name__})"
        ) from None


def _inventory_list(params: dict[str, Any]) -> dict[str, Any]:
    kind = _text(params.get("kind"), "kind")
    path_prefix = params.get("path_prefix")
    if path_prefix is not None:
        path_prefix = _text(path_prefix, "path_prefix")
        if not path_prefix.startswith("/"):
            raise VspherePackError("path_prefix must be an absolute inventory path")
    with _with_client(params) as client:
        values = [
            client.record(item) for item in client.list_objects(_inventory_types(kind))
        ]
        values = list({item["moid"]: item for item in values}.values())
        if path_prefix:
            values = [
                item
                for item in values
                if item["inventory_path"] == path_prefix
                or item["inventory_path"].startswith(path_prefix.rstrip("/") + "/")
            ]
        values.sort(key=lambda item: (item["inventory_path"], item["moid"]))
        limit = int(_integer(params, "limit", 1000, 1, 5000))
        return _result("inventory_list", values[:limit], client)


def _vm_list(params: dict[str, Any]) -> dict[str, Any]:
    _, vim = _sdk()
    path_prefix = params.get("path_prefix")
    if path_prefix is not None:
        path_prefix = _text(path_prefix, "path_prefix")
        if not path_prefix.startswith("/"):
            raise VspherePackError("path_prefix must be an absolute inventory path")
    with _with_client(params) as client:
        values = [
            _vm_record(client, vm) for vm in client.list_objects([vim.VirtualMachine])
        ]
        if path_prefix:
            values = [
                item
                for item in values
                if item["inventory_path"] == path_prefix
                or item["inventory_path"].startswith(path_prefix.rstrip("/") + "/")
            ]
        template = params.get("template")
        if template is not None:
            template = _boolean(params, "template")
            values = [item for item in values if item["template"] is template]
        values.sort(key=lambda item: (item["inventory_path"], item["moid"]))
        limit = int(_integer(params, "limit", 1000, 1, 5000))
        return _result("vm_list", values[:limit], client)


def _vm_get(params: dict[str, Any]) -> dict[str, Any]:
    _, vim = _sdk()
    with _with_client(params) as client:
        vm = client.object(
            _moid(params.get("vm_moid"), "vm_moid"), vim.VirtualMachine, "vm_moid"
        )
        return _result("vm_get", _vm_record(client, vm, details=True), client)


def _clone(params: dict[str, Any], require_template: bool) -> dict[str, Any]:
    _, vim = _sdk()
    name = _text(params.get("name"), "name")
    if "/" in name:
        raise VspherePackError(
            "name must not contain '/' because it would make inventory paths ambiguous"
        )
    timeout, interval = _task_limits(params)
    with _with_client(params) as client:
        source = client.object(
            _moid(params.get("source_vm_moid"), "source_vm_moid"),
            vim.VirtualMachine,
            "source_vm_moid",
        )
        if bool(source.config.template) is not require_template:
            expected = "a template" if require_template else "a non-template VM"
            raise VspherePackError(f"source_vm_moid must reference {expected}")
        folder = client.object(
            _moid(params.get("folder_moid"), "folder_moid"), vim.Folder, "folder_moid"
        )
        if "VirtualMachine" not in set(getattr(folder, "childType", []) or []):
            raise VspherePackError("folder_moid must reference a VM inventory folder")
        if any(
            getattr(item, "name", None) == name
            for item in getattr(folder, "childEntity", []) or []
        ):
            raise VspherePackError(
                "destination folder already contains an object with the requested name"
            )
        pool = client.object(
            _moid(params.get("resource_pool_moid"), "resource_pool_moid"),
            vim.ResourcePool,
            "resource_pool_moid",
        )
        datastore = client.object(
            _moid(params.get("datastore_moid"), "datastore_moid"),
            vim.Datastore,
            "datastore_moid",
        )
        reserve_gib = int(_integer(params, "minimum_free_gib", 0, 0, 2**31 - 1))
        _datastore_ready(datastore, reserve_bytes=reserve_gib * 1024**3)
        host = None
        if params.get("host_moid") is not None:
            host = client.object(
                _moid(params.get("host_moid"), "host_moid"), vim.HostSystem, "host_moid"
            )
        _validate_placement(pool, datastore, host)
        location = vim.vm.RelocateSpec(datastore=datastore, pool=pool, host=host)
        spec = vim.vm.CloneSpec(location=location, powerOn=False, template=False)
        task = source.CloneVM_Task(folder=folder, name=name, spec=spec)
        data = client.wait_task(task, timeout, interval)
        data.update(
            {
                "source_vm_moid": source._moId,
                "folder_moid": folder._moId,
                "datastore_moid": datastore._moId,
            }
        )
        return _result(
            "vm_create_from_template" if require_template else "vm_clone", data, client
        )


def _vm_create_from_template(params: dict[str, Any]) -> dict[str, Any]:
    return _clone(params, True)


def _vm_clone(params: dict[str, Any]) -> dict[str, Any]:
    return _clone(params, False)


def _vm_cpu_memory_set(params: dict[str, Any]) -> dict[str, Any]:
    _, vim = _sdk()
    cpu = _integer(params, "cpu_count", None, 1, 768)
    memory = _integer(params, "memory_mib", None, 4, 24 * 1024 * 1024)
    if cpu is None and memory is None:
        raise VspherePackError("at least one of cpu_count or memory_mib is required")
    timeout, interval = _task_limits(params)
    with _with_client(params) as client:
        vm = client.object(
            _moid(params.get("vm_moid"), "vm_moid"), vim.VirtualMachine, "vm_moid"
        )
        spec = vim.vm.ConfigSpec()
        if cpu is not None:
            spec.numCPUs = cpu
        if memory is not None:
            spec.memoryMB = memory
        data = client.wait_task(vm.ReconfigVM_Task(spec=spec), timeout, interval)
        data["vm_moid"] = vm._moId
        return _result("vm_cpu_memory_set", data, client)


def _vm_disk(params: dict[str, Any]) -> dict[str, Any]:
    _, vim = _sdk()
    action = params.get("operation")
    if action not in {"add", "resize", "remove"}:
        raise VspherePackError("operation must be add, resize, or remove")
    timeout, interval = _task_limits(params)
    with _with_client(params) as client:
        vm_moid = _moid(params.get("vm_moid"), "vm_moid")
        vm = client.object(vm_moid, vim.VirtualMachine, "vm_moid")
        spec = vim.vm.ConfigSpec()
        change = vim.vm.device.VirtualDeviceSpec()
        if action == "add":
            size_gib = _required_integer(params, "size_gib", 1, 65536)
            controller_key = _required_integer(
                params, "controller_key", -(2**31), 2**31 - 1
            )
            unit = _required_integer(params, "unit_number", 0, 63)
            if unit == 7:
                raise VspherePackError("unit_number 7 is reserved on SCSI controllers")
            controller = _device(
                vm,
                controller_key,
                vim.vm.device.VirtualSCSIController,
                "controller_key",
            )
            if any(
                getattr(item, "controllerKey", None) == controller.key
                and getattr(item, "unitNumber", None) == unit
                for item in vm.config.hardware.device
            ):
                raise VspherePackError(
                    "controller_key and unit_number are already in use"
                )
            datastore = client.object(
                _moid(params.get("datastore_moid"), "datastore_moid"),
                vim.Datastore,
                "datastore_moid",
            )
            reserve_gib = int(_integer(params, "minimum_free_gib", 0, 0, 2**31 - 1))
            _datastore_ready(datastore, size_gib * 1024**3, reserve_gib * 1024**3)
            host = vm.runtime.host
            if host is None or all(
                item._moId != datastore._moId for item in host.datastore
            ):
                raise VspherePackError(
                    "datastore_moid is not mounted on the VM's current host"
                )
            backing = vim.vm.device.VirtualDisk.FlatVer2BackingInfo(
                datastore=datastore,
                fileName=f"[{datastore.name}]",
                diskMode="persistent",
                thinProvisioned=_boolean(params, "thin_provisioned", True),
            )
            change.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
            change.fileOperation = vim.vm.device.VirtualDeviceSpec.FileOperation.create
            change.device = vim.vm.device.VirtualDisk(
                backing=backing,
                capacityInBytes=size_gib * 1024**3,
                controllerKey=controller.key,
                unitNumber=unit,
            )
        else:
            device_key = _required_integer(params, "device_key", -(2**31), 2**31 - 1)
            disk = _device(vm, device_key, vim.vm.device.VirtualDisk, "device_key")
            if action == "resize":
                size_gib = _required_integer(params, "size_gib", 1, 65536)
                new_size = size_gib * 1024**3
                if new_size <= int(disk.capacityInBytes):
                    raise VspherePackError(
                        "disk resize only supports growth beyond current capacity"
                    )
                change.operation = vim.vm.device.VirtualDeviceSpec.Operation.edit
                disk.capacityInBytes = new_size
                change.device = disk
            else:
                delete_backing = _boolean(params, "delete_backing", False)
                verb = "REMOVE_DISK"
                suffix = " DELETE_BACKING" if delete_backing else " DETACH_ONLY"
                _confirmation(params, f"{verb} {device_key} FROM {vm_moid}{suffix}")
                change.operation = vim.vm.device.VirtualDeviceSpec.Operation.remove
                if delete_backing:
                    change.fileOperation = (
                        vim.vm.device.VirtualDeviceSpec.FileOperation.destroy
                    )
                change.device = disk
        spec.deviceChange = [change]
        data = client.wait_task(vm.ReconfigVM_Task(spec=spec), timeout, interval)
        data.update({"vm_moid": vm_moid, "disk_operation": action})
        return _result("vm_disk", data, client)


def _vm_nic(params: dict[str, Any]) -> dict[str, Any]:
    _, vim = _sdk()
    action = params.get("operation")
    if action not in {"add", "edit", "remove"}:
        raise VspherePackError("operation must be add, edit, or remove")
    timeout, interval = _task_limits(params)
    with _with_client(params) as client:
        vm_moid = _moid(params.get("vm_moid"), "vm_moid")
        vm = client.object(vm_moid, vim.VirtualMachine, "vm_moid")
        change = vim.vm.device.VirtualDeviceSpec()
        if action == "add":
            models = {
                "vmxnet3": vim.vm.device.VirtualVmxnet3,
                "e1000e": vim.vm.device.VirtualE1000e,
            }
            model = params.get("model", "vmxnet3")
            if model not in models:
                raise VspherePackError("model must be vmxnet3 or e1000e")
            network = client.network(_moid(params.get("network_moid"), "network_moid"))
            connectable = vim.vm.device.VirtualDevice.ConnectInfo(
                startConnected=_boolean(params, "start_connected", True),
                allowGuestControl=_boolean(params, "allow_guest_control", True),
            )
            change.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
            change.device = models[model](
                backing=_network_backing(network), connectable=connectable
            )
        else:
            device_key = _required_integer(params, "device_key", -(2**31), 2**31 - 1)
            nic = _device(
                vm, device_key, vim.vm.device.VirtualEthernetCard, "device_key"
            )
            if action == "remove":
                _confirmation(params, f"REMOVE_NIC {device_key} FROM {vm_moid}")
                change.operation = vim.vm.device.VirtualDeviceSpec.Operation.remove
            else:
                network = client.network(
                    _moid(params.get("network_moid"), "network_moid")
                )
                nic.backing = _network_backing(network)
                if params.get("start_connected") is not None:
                    nic.connectable.startConnected = _boolean(params, "start_connected")
                change.operation = vim.vm.device.VirtualDeviceSpec.Operation.edit
            change.device = nic
        spec = vim.vm.ConfigSpec(deviceChange=[change])
        data = client.wait_task(vm.ReconfigVM_Task(spec=spec), timeout, interval)
        data.update({"vm_moid": vm_moid, "nic_operation": action})
        return _result("vm_nic", data, client)


def _vm_power(params: dict[str, Any]) -> dict[str, Any]:
    _, vim = _sdk()
    action = params.get("operation")
    allowed = {
        "power_on",
        "power_off",
        "shutdown_guest",
        "reboot_guest",
        "suspend",
        "reset",
    }
    if action not in allowed:
        raise VspherePackError(
            "operation must be power_on, power_off, shutdown_guest, reboot_guest, suspend, or reset"
        )
    timeout, interval = _task_limits(params)
    with _with_client(params) as client:
        vm_moid = _moid(params.get("vm_moid"), "vm_moid")
        vm = client.object(vm_moid, vim.VirtualMachine, "vm_moid")
        state = str(vm.runtime.powerState)
        if action == "power_on":
            if state == "poweredOn":
                raise VspherePackError("VM is already powered on")
            task = vm.PowerOnVM_Task()
        elif action == "power_off":
            if state == "poweredOff":
                raise VspherePackError("VM is already powered off")
            _confirmation(params, f"POWER_OFF {vm_moid}")
            task = vm.PowerOffVM_Task()
        elif action == "suspend":
            if state != "poweredOn":
                raise VspherePackError("suspend requires a powered-on VM")
            task = vm.SuspendVM_Task()
        elif action == "reset":
            if state != "poweredOn":
                raise VspherePackError("reset requires a powered-on VM")
            _confirmation(params, f"RESET {vm_moid}")
            task = vm.ResetVM_Task()
        else:
            if state != "poweredOn":
                raise VspherePackError(f"{action} requires a powered-on VM")
            if str(vm.guest.toolsRunningStatus) != "guestToolsRunning":
                raise VspherePackError(f"{action} requires running VMware Tools")
            if action == "shutdown_guest":
                vm.ShutdownGuest()
            else:
                vm.RebootGuest()
            return _result(
                "vm_power",
                {
                    "vm_moid": vm_moid,
                    "power_operation": action,
                    "requested": True,
                    "task_moid": None,
                    "complete": False,
                },
                client,
            )
        data = client.wait_task(task, timeout, interval)
        data.update({"vm_moid": vm_moid, "power_operation": action})
        return _result("vm_power", data, client)


def _snapshot_entries(client: VsphereClient, vm: Any) -> list[dict[str, Any]]:
    roots = list(getattr(getattr(vm, "snapshot", None), "rootSnapshotList", []) or [])
    result: list[dict[str, Any]] = []

    def visit(node: Any, parent_moid: str | None) -> None:
        result.append(
            {
                "snapshot_moid": node.snapshot._moId,
                "vm_moid": vm._moId,
                "name": str(node.name),
                "description": str(node.description),
                "created_at": node.createTime.isoformat(),
                "state": str(node.state),
                "quiesced": bool(node.quiesced),
                "parent_snapshot_moid": parent_moid,
            }
        )
        for child in list(node.childSnapshotList or []):
            visit(child, node.snapshot._moId)

    for root in roots:
        visit(root, None)
    return result


def _snapshot_object(client: VsphereClient, vm: Any, moid: str) -> Any:
    expected = _moid(moid, "snapshot_moid")
    roots = list(getattr(getattr(vm, "snapshot", None), "rootSnapshotList", []) or [])
    stack = roots[:]
    while stack:
        item = stack.pop()
        if item.snapshot._moId == expected:
            return item.snapshot
        stack.extend(list(item.childSnapshotList or []))
    raise VspherePackError(
        f"snapshot_moid '{expected}' does not belong to VM '{vm._moId}'"
    )


def _snapshot(params: dict[str, Any]) -> dict[str, Any]:
    _, vim = _sdk()
    action = params.get("operation")
    if action not in {"list", "create", "revert", "delete"}:
        raise VspherePackError("operation must be list, create, revert, or delete")
    timeout, interval = _task_limits(params)
    with _with_client(params) as client:
        vm_moid = _moid(params.get("vm_moid"), "vm_moid")
        vm = client.object(vm_moid, vim.VirtualMachine, "vm_moid")
        if action == "list":
            return _result("snapshot", _snapshot_entries(client, vm), client)
        if action == "create":
            name = _text(params.get("name"), "name")
            if any(item["name"] == name for item in _snapshot_entries(client, vm)):
                raise VspherePackError("snapshot name already exists on this VM")
            task = vm.CreateSnapshot_Task(
                name=name,
                description=_text(
                    params.get("description", ""), "description", allow_empty=True
                ),
                memory=_boolean(params, "include_memory", False),
                quiesce=_boolean(params, "quiesce", False),
            )
        else:
            snapshot_moid = _moid(params.get("snapshot_moid"), "snapshot_moid")
            snapshot = _snapshot_object(client, vm, snapshot_moid)
            if action == "revert":
                _confirmation(params, f"REVERT_SNAPSHOT {snapshot_moid} ON {vm_moid}")
                task = snapshot.RevertToSnapshot_Task(
                    suppressPowerOn=_boolean(params, "suppress_power_on", True)
                )
            else:
                remove_children = _boolean(params, "remove_children", False)
                suffix = " WITH_CHILDREN" if remove_children else " ONLY"
                _confirmation(
                    params, f"DELETE_SNAPSHOT {snapshot_moid} ON {vm_moid}{suffix}"
                )
                task = snapshot.RemoveSnapshot_Task(
                    removeChildren=remove_children,
                    consolidate=_boolean(params, "consolidate", True),
                )
        data = client.wait_task(task, timeout, interval)
        data.update({"vm_moid": vm_moid, "snapshot_operation": action})
        return _result("snapshot", data, client)


def _tag_category(params: dict[str, Any]) -> dict[str, Any]:
    action = params.get("operation")
    if action not in {"list", "create", "delete"}:
        raise VspherePackError("operation must be list, create, or delete")
    with _with_client(params) as client, RestClient(client) as rest:
        base = "/api/cis/tagging/category"
        if action == "list":
            identifiers = rest.request("GET", base)
            if not isinstance(identifiers, list):
                raise VspherePackError("category list returned an invalid contract")
            data = [
                rest.request(
                    "GET", f"{base}/{quote(_text(item, 'category_id'), safe='')}"
                )
                for item in identifiers
            ]
        elif action == "create":
            cardinality = params.get("cardinality", "SINGLE")
            if cardinality not in {"SINGLE", "MULTIPLE"}:
                raise VspherePackError("cardinality must be SINGLE or MULTIPLE")
            types = params.get("associable_types", [])
            if not isinstance(types, list) or any(
                not isinstance(item, str) or not item for item in types
            ):
                raise VspherePackError(
                    "associable_types must be an array of non-empty strings"
                )
            data = {
                "category_id": rest.request(
                    "POST",
                    base,
                    {
                        "name": _text(params.get("name"), "name"),
                        "description": _text(
                            params.get("description", ""),
                            "description",
                            allow_empty=True,
                        ),
                        "cardinality": cardinality,
                        "associable_types": types,
                    },
                )
            }
        else:
            category_id = _text(params.get("category_id"), "category_id")
            _confirmation(params, f"DELETE_CATEGORY {category_id}")
            rest.request("DELETE", f"{base}/{quote(category_id, safe='')}")
            data = {"category_id": category_id, "deleted": True}
        return _result("tag_category", data, client)


def _tag(params: dict[str, Any]) -> dict[str, Any]:
    action = params.get("operation")
    if action not in {"list", "create", "delete"}:
        raise VspherePackError("operation must be list, create, or delete")
    with _with_client(params) as client, RestClient(client) as rest:
        base = "/api/cis/tagging/tag"
        if action == "list":
            identifiers = rest.request("GET", base)
            if not isinstance(identifiers, list):
                raise VspherePackError("tag list returned an invalid contract")
            data = [
                rest.request("GET", f"{base}/{quote(_text(item, 'tag_id'), safe='')}")
                for item in identifiers
            ]
            category_id = params.get("category_id")
            if category_id is not None:
                category_id = _text(category_id, "category_id")
                data = [item for item in data if item.get("category_id") == category_id]
        elif action == "create":
            data = {
                "tag_id": rest.request(
                    "POST",
                    base,
                    {
                        "name": _text(params.get("name"), "name"),
                        "description": _text(
                            params.get("description", ""),
                            "description",
                            allow_empty=True,
                        ),
                        "category_id": _text(params.get("category_id"), "category_id"),
                    },
                )
            }
        else:
            tag_id = _text(params.get("tag_id"), "tag_id")
            _confirmation(params, f"DELETE_TAG {tag_id}")
            rest.request("DELETE", f"{base}/{quote(tag_id, safe='')}")
            data = {"tag_id": tag_id, "deleted": True}
        return _result("tag", data, client)


def _tag_association(params: dict[str, Any]) -> dict[str, Any]:
    action = params.get("operation")
    if action not in {"list", "attach", "detach"}:
        raise VspherePackError("operation must be list, attach, or detach")
    object_type = _text(params.get("object_type"), "object_type")
    object_moid = _moid(params.get("object_moid"), "object_moid")
    body = {"object_id": {"id": object_moid, "type": object_type}}
    with _with_client(params) as client:
        _, vim = _sdk()
        types = {
            "VirtualMachine": vim.VirtualMachine,
            "Datacenter": vim.Datacenter,
            "ClusterComputeResource": vim.ClusterComputeResource,
            "HostSystem": vim.HostSystem,
            "Datastore": vim.Datastore,
            "Folder": vim.Folder,
            "ResourcePool": vim.ResourcePool,
        }
        if object_type in {"Network", "DistributedVirtualPortgroup", "OpaqueNetwork"}:
            found = client.network(object_moid)
            actual = (
                "DistributedVirtualPortgroup"
                if isinstance(found, vim.dvs.DistributedVirtualPortgroup)
                else found.__class__.__name__.split(".")[-1]
            )
            if actual != object_type:
                raise VspherePackError("object_type does not match object_moid")
        elif object_type in types:
            client.object(object_moid, types[object_type], "object_moid")
        else:
            raise VspherePackError(
                "object_type is not in the curated taggable type allowlist"
            )
        rest = RestClient(client)
        rest.__enter__()
        try:
            return _tag_association_request(
                params, client, rest, action, object_type, object_moid, body
            )
        finally:
            rest.__exit__(None, None, None)


def _tag_association_request(
    params: dict[str, Any],
    client: VsphereClient,
    rest: RestClient,
    action: str,
    object_type: str,
    object_moid: str,
    body: dict[str, Any],
) -> dict[str, Any]:
    base = "/api/cis/tagging/tag-association"
    if action == "list":
        data = rest.request("POST", base, body, {"action": "list-attached-tags"})
    else:
        tag_id = _text(params.get("tag_id"), "tag_id")
        if action == "detach":
            _confirmation(
                params, f"DETACH_TAG {tag_id} FROM {object_type} {object_moid}"
            )
        rest.request(
            "POST", f"{base}/{quote(tag_id, safe='')}", body, {"action": action}
        )
        data = {
            "tag_id": tag_id,
            "object_type": object_type,
            "object_moid": object_moid,
            "attached": action == "attach",
        }
    return _result("tag_association", data, client)


def _vm_migrate(params: dict[str, Any]) -> dict[str, Any]:
    _, vim = _sdk()
    timeout, interval = _task_limits(params)
    priority = params.get("priority", "defaultPriority")
    allowed = {"lowPriority", "defaultPriority", "highPriority"}
    if priority not in allowed:
        raise VspherePackError(
            "priority must be lowPriority, defaultPriority, or highPriority"
        )
    with _with_client(params) as client:
        vm = client.object(
            _moid(params.get("vm_moid"), "vm_moid"), vim.VirtualMachine, "vm_moid"
        )
        pool = client.object(
            _moid(params.get("resource_pool_moid"), "resource_pool_moid"),
            vim.ResourcePool,
            "resource_pool_moid",
        )
        host = client.object(
            _moid(params.get("host_moid"), "host_moid"), vim.HostSystem, "host_moid"
        )
        datastores = list(getattr(vm, "datastore", []) or [])
        if not datastores:
            raise VspherePackError("VM has no datastore to validate for migration")
        for datastore in datastores:
            _datastore_ready(datastore)
            _validate_placement(pool, datastore, host)
        task = vm.MigrateVM_Task(
            pool=pool,
            host=host,
            priority=getattr(vim.VirtualMachine.MovePriority, priority),
        )
        data = client.wait_task(task, timeout, interval)
        data.update(
            {
                "vm_moid": vm._moId,
                "host_moid": host._moId,
                "resource_pool_moid": pool._moId,
            }
        )
        return _result("vm_migrate", data, client)


def _vm_relocate(params: dict[str, Any]) -> dict[str, Any]:
    _, vim = _sdk()
    timeout, interval = _task_limits(params)
    priority = params.get("priority", "defaultPriority")
    if priority not in {"lowPriority", "defaultPriority", "highPriority"}:
        raise VspherePackError(
            "priority must be lowPriority, defaultPriority, or highPriority"
        )
    disk_move_type = params.get(
        "disk_move_type", "moveAllDiskBackingsAndDisallowSharing"
    )
    allowed_moves = {
        "moveAllDiskBackingsAndDisallowSharing",
        "moveAllDiskBackingsAndAllowSharing",
        "createNewChildDiskBacking",
    }
    if disk_move_type not in allowed_moves:
        raise VspherePackError("disk_move_type is not an allowed relocation mode")
    with _with_client(params) as client:
        vm = client.object(
            _moid(params.get("vm_moid"), "vm_moid"), vim.VirtualMachine, "vm_moid"
        )
        pool = client.object(
            _moid(params.get("resource_pool_moid"), "resource_pool_moid"),
            vim.ResourcePool,
            "resource_pool_moid",
        )
        datastore = client.object(
            _moid(params.get("datastore_moid"), "datastore_moid"),
            vim.Datastore,
            "datastore_moid",
        )
        reserve_gib = int(_integer(params, "minimum_free_gib", 0, 0, 2**31 - 1))
        _datastore_ready(datastore, reserve_bytes=reserve_gib * 1024**3)
        host = None
        if params.get("host_moid") is not None:
            host = client.object(
                _moid(params.get("host_moid"), "host_moid"), vim.HostSystem, "host_moid"
            )
        _validate_placement(pool, datastore, host)
        spec = vim.vm.RelocateSpec(
            datastore=datastore, pool=pool, host=host, diskMoveType=disk_move_type
        )
        task = vm.RelocateVM_Task(
            spec=spec, priority=getattr(vim.VirtualMachine.MovePriority, priority)
        )
        data = client.wait_task(task, timeout, interval)
        data.update(
            {
                "vm_moid": vm._moId,
                "datastore_moid": datastore._moId,
                "resource_pool_moid": pool._moId,
            }
        )
        return _result("vm_relocate", data, client)


def _guest_tools_get(params: dict[str, Any]) -> dict[str, Any]:
    _, vim = _sdk()
    with _with_client(params) as client:
        vm = client.object(
            _moid(params.get("vm_moid"), "vm_moid"), vim.VirtualMachine, "vm_moid"
        )
        data = {
            "vm_moid": vm._moId,
            "power_state": str(vm.runtime.powerState),
            "tools_running_status": str(vm.guest.toolsRunningStatus),
            "tools_version_status": str(vm.guest.toolsVersionStatus2),
            "guest_state": str(vm.guest.guestState),
        }
        return _result("guest_tools_get", data, client)


def _guest_process(params: dict[str, Any]) -> dict[str, Any]:
    _, vim = _sdk()
    action = params.get("operation")
    if action not in {"start", "status"}:
        raise VspherePackError("operation must be start or status")
    with _with_client(params) as client:
        vm, auth, manager = _guest_context(client, params)
        process_manager = manager.processManager
        if action == "start":
            environment = params.get("environment", [])
            if not isinstance(environment, list) or any(
                not isinstance(item, str) or "=" not in item for item in environment
            ):
                raise VspherePackError(
                    "environment must be an array of NAME=value strings"
                )
            spec = vim.vm.guest.ProcessManager.ProgramSpec(
                programPath=_text(params.get("program_path"), "program_path"),
                arguments=_text(
                    params.get("arguments", ""), "arguments", allow_empty=True
                ),
                workingDirectory=_text(
                    params.get("working_directory", ""),
                    "working_directory",
                    allow_empty=True,
                ),
                envVariables=environment,
            )
            pid = process_manager.StartProgramInGuest(vm=vm, auth=auth, spec=spec)
            data = {"vm_moid": vm._moId, "pid": int(pid), "started": True}
        else:
            pid = _required_integer(params, "pid", 1, 2**63 - 1)
            values = process_manager.ListProcessesInGuest(vm=vm, auth=auth, pids=[pid])
            if len(values) != 1 or int(values[0].pid) != pid:
                raise VspherePackError("guest process was not found")
            item = values[0]
            data = {
                "vm_moid": vm._moId,
                "pid": pid,
                "start_time": item.startTime.isoformat() if item.startTime else None,
                "end_time": item.endTime.isoformat() if item.endTime else None,
                "exit_code": item.exitCode,
                "complete": item.endTime is not None,
            }
        return _result("guest_process", data, client)


def _guest_file(params: dict[str, Any]) -> dict[str, Any]:
    _, vim = _sdk()
    action = params.get("operation")
    if action not in {"upload", "download", "delete"}:
        raise VspherePackError("operation must be upload, download, or delete")
    guest_path = _text(params.get("guest_path"), "guest_path")
    timeout = int(_integer(params, "transfer_timeout_seconds", 300, 1, 1800))
    with _with_client(params) as client:
        vm, auth, manager = _guest_context(client, params)
        file_manager = manager.fileManager
        if action == "delete":
            _confirmation(params, f"DELETE_GUEST_FILE {guest_path} ON {vm._moId}")
            file_manager.DeleteFileInGuest(vm=vm, auth=auth, filePath=guest_path)
            data = {"vm_moid": vm._moId, "guest_path": guest_path, "deleted": True}
        elif action == "upload":
            artifact = _artifact_path(params.get("artifact_path"), output=False)
            contents = _read_artifact(artifact)
            size = len(contents)
            overwrite = _boolean(params, "overwrite", False)
            if overwrite:
                _confirmation(
                    params, f"OVERWRITE_GUEST_FILE {guest_path} ON {vm._moId}"
                )
            attributes = vim.vm.guest.FileManager.FileAttributes()
            transfer = file_manager.InitiateFileTransferToGuest(
                vm=vm,
                auth=auth,
                guestFilePath=guest_path,
                fileAttributes=attributes,
                fileSize=size,
                overwrite=overwrite,
            )
            url = _safe_transfer_url(client, transfer)
            request = Request(
                url, data=contents, method="PUT", headers={"Content-Length": str(size)}
            )
            try:
                with _http_opener(client.ssl_context).open(
                    request, timeout=timeout
                ) as response:
                    status = response.status
            except HTTPError as exc:
                raise VspherePackError(
                    f"guest upload failed (HTTP {exc.code})"
                ) from None
            except (URLError, TimeoutError, OSError) as exc:
                raise VspherePackError(
                    f"guest upload failed ({type(exc).__name__})"
                ) from None
            if status < 200 or status >= 300:
                raise VspherePackError(f"guest upload failed (HTTP {status})")
            data = {
                "vm_moid": vm._moId,
                "guest_path": guest_path,
                "artifact_path": str(artifact),
                "bytes": size,
            }
        else:
            artifact = _artifact_path(params.get("artifact_path"), output=True)
            if artifact.exists() and not _boolean(params, "overwrite", False):
                raise VspherePackError(
                    "artifact_path already exists; set overwrite to replace it"
                )
            transfer = file_manager.InitiateFileTransferFromGuest(
                vm=vm, auth=auth, guestFilePath=guest_path
            )
            url = _safe_transfer_url(client, transfer.url)
            request = Request(url, method="GET")
            try:
                with _http_opener(client.ssl_context).open(
                    request, timeout=timeout
                ) as response:
                    raw = response.read(MAX_GUEST_FILE + 1)
                    status = response.status
            except HTTPError as exc:
                raise VspherePackError(
                    f"guest download failed (HTTP {exc.code})"
                ) from None
            except (URLError, TimeoutError, OSError) as exc:
                raise VspherePackError(
                    f"guest download failed ({type(exc).__name__})"
                ) from None
            if status < 200 or status >= 300:
                raise VspherePackError(f"guest download failed (HTTP {status})")
            if len(raw) > MAX_GUEST_FILE:
                raise VspherePackError("guest download exceeded 128 MiB")
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(artifact, flags, 0o600)
            try:
                os.fchmod(fd, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    fd = -1
                    stream.write(raw)
            except Exception:
                try:
                    artifact.unlink()
                except OSError:
                    pass
                raise
            finally:
                if fd >= 0:
                    os.close(fd)
            data = {
                "vm_moid": vm._moId,
                "guest_path": guest_path,
                "artifact_path": str(artifact),
                "bytes": len(raw),
            }
        return _result("guest_file", data, client)


def _task_status(params: dict[str, Any]) -> dict[str, Any]:
    wait = int(_integer(params, "wait_seconds", 0, 0, 300))
    interval = int(_integer(params, "poll_interval_seconds", 2, 1, 10))
    with _with_client(params) as client:
        task = client.task(_moid(params.get("task_moid"), "task_moid"))
        if wait:
            data = client.wait_task(task, wait, interval)
        else:
            try:
                state = str(task.info.state)
            except Exception as exc:
                raise VspherePackError(
                    f"vSphere task status failed ({type(exc).__name__})"
                ) from None
            if state not in {"queued", "running", "success"}:
                fault = getattr(task.info, "error", None)
                fault_type = type(getattr(fault, "fault", fault)).__name__
                raise VspherePackError(
                    f"vSphere task '{task._moId}' failed ({fault_type})"
                )
            result = getattr(task.info, "result", None)
            data = {
                "task_moid": task._moId,
                "state": state,
                "complete": state == "success",
                "timed_out": False,
                "result_moid": getattr(result, "_moId", None),
            }
        return _result("task_status", data, client)
