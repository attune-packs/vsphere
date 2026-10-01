# VMware vSphere Attune Pack

This curated pack adapts StackStorm Exchange `stackstorm-vsphere` 1.3.5 at
revision `eed7a36730d4e3f3c9463b256e5009374acd6072`. It uses pyVmomi 9.1.0.0,
the negotiated vSphere Web Services API, and the current vSphere Automation
tagging API. See [SOURCE.md](SOURCE.md) for the verified baseline and the limits
of the compatibility evidence.

## Requirements

- Python 3.10 or newer and `pyvmomi==9.1.0.0` on the Attune worker.
- Network access to a vCenter endpoint. Tags require vCenter, not standalone ESXi.
- Least-privilege vCenter permissions for only the selected actions.
- An encrypted, pack-owned vCenter profile Attune Key, normally `pack.vsphere.vcenter`.
- A separate encrypted guest credential Key for guest process/file actions.
- `ATTUNE_ARTIFACTS_DIR` for guest uploads and downloads.

## Keys And TLS

The vCenter profile Key contains one flat JSON object:

```json
{
  "host": "vcenter.example.com",
  "port": 443,
  "username": "svc-attune@example.com",
  "password": "REDACTED",
  "verify_tls": true,
  "ca_cert": "-----BEGIN CERTIFICATE-----\nREDACTED_PRIVATE_CA\n-----END CERTIFICATE-----",
  "connect_timeout_seconds": 30,
  "minimum_api_version": "7.0"
}
```

`verify_tls` defaults to and must remain `true`. `ca_cert` is optional and is
loaded directly into a private SSL context. No insecure mode or process-wide CA
file is provided. The socket timeout is applied for the action's SOAP lifetime
and restored during cleanup. REST and guest transfer requests also use bounded
timeouts, reject redirects, and use the same verified TLS context.

The guest credential Key, normally `pack.vsphere.guest`, is separate:

```json
{"username":"guest-automation","password":"REDACTED"}
```

Guest credentials are never accepted inline and are not returned. Guest process
arguments/environment are marked secret. Guest process status omits command
line, environment, and owner fields because they can contain credentials.

## Actions

| Action | Purpose |
|---|---|
| `vsphere.inventory_list` | Datacenter, cluster, host, datastore, network, and folder discovery |
| `vsphere.vm_list` / `vsphere.vm_get` | VM discovery and hardware/runtime details |
| `vsphere.vm_create_from_template` | Create from an explicit template/folder/pool/datastore/host |
| `vsphere.vm_clone` | Clone a non-template VM into explicit placement |
| `vsphere.vm_cpu_memory_set` | CPU and memory reconfiguration |
| `vsphere.vm_disk` | Explicit disk add/grow/detach/delete |
| `vsphere.vm_nic` | Explicit NIC add/edit/remove |
| `vsphere.vm_power` | Power on/off, guest shutdown/reboot, suspend, hard reset |
| `vsphere.snapshot` | Snapshot list/create/revert/delete |
| `vsphere.tag_category` / `vsphere.tag` | Current API category and tag operations |
| `vsphere.tag_association` | List/attach/detach tags on a validated object MOID |
| `vsphere.vm_migrate` | Compute migration with current datastore compatibility checks |
| `vsphere.vm_relocate` | Explicit compute/storage relocation |
| `vsphere.guest_tools_get` | VMware Tools and guest state discovery |
| `vsphere.guest_process` | Start/status using a separate guest Key |
| `vsphere.guest_file` | Confined upload/download/delete using a separate guest Key |
| `vsphere.task_status` | One-shot or bounded task polling by task MOID |

All action parameters are a flat JSON object. Successful output is consistently:

```json
{
  "operation": "vm_power",
  "data": {"vm_moid":"vm-42","power_operation":"power_on","task_moid":"task-7","state":"success","complete":true,"timed_out":false,"result_moid":null},
  "meta": {"vcenter_api_version":"9.1.0","pyvmomi_version":"9.1.0.0","mutation_retried":false}
}
```

## Identity And Placement

Discovery returns stable MOIDs, explicit inventory paths, and path components.
Every existing mutation target uses a MOID. Names are accepted only when naming
a newly cloned VM or snapshot; they are never used to select an existing VM.

Clone/create requires explicit folder, resource pool, and datastore MOIDs, plus
an optional host MOID. Relocation has the same explicit destination semantics.
The client rejects inaccessible or maintenance datastores, enforces the
requested free-space reserve, verifies the datastore is mounted on an eligible
connected non-maintenance host, and verifies an explicit host belongs to the
resource pool's compute resource. It never chooses the "most free" datastore or
silently follows a Storage DRS recommendation. Capacity/concurrency can change
after preflight; vCenter remains authoritative and task faults are surfaced by
safe fault type only.

## Safety Contracts

The following exact confirmations are required. Values are case-sensitive:

```text
POWER_OFF vm-42
RESET vm-42
REVERT_SNAPSHOT snapshot-9 ON vm-42
DELETE_SNAPSHOT snapshot-9 ON vm-42 ONLY
DELETE_SNAPSHOT snapshot-9 ON vm-42 WITH_CHILDREN
REMOVE_DISK 2000 FROM vm-42 DETACH_ONLY
REMOVE_DISK 2000 FROM vm-42 DELETE_BACKING
REMOVE_NIC 4000 FROM vm-42
DELETE_CATEGORY urn:vmomi:InventoryServiceCategory:...
DELETE_TAG urn:vmomi:InventoryServiceTag:...
DETACH_TAG tag-id FROM VirtualMachine vm-42
DELETE_GUEST_FILE /path/in/guest ON vm-42
OVERWRITE_GUEST_FILE /path/in/guest ON vm-42
```

`shutdown_guest` and `reboot_guest` require a powered-on VM and running VMware
Tools. They are guest requests without a vCenter Task, so output says
`requested: true` and `complete: false`. `power_off` and `reset` are hard power
operations and require confirmation. Suspend is separate from shutdown.

Disk removal distinguishes detach from backing destruction. Snapshot delete
distinguishes one node from its child tree and waits for the returned task.
Snapshot revert first proves the snapshot MOID belongs to the supplied VM.

No mutating API call is retried. A task timeout means the vCenter operation may
still be running; record the returned task MOID and call `vsphere.task_status`.
Task waits are bounded to 7,200 seconds and status waits to 300 seconds. SOAP
fault text and Automation API bodies are never propagated because they may
contain names, paths, customization values, or credentials.

## Guest Artifacts

Uploads and downloads are limited to 128 MiB. `artifact_path` must be relative
to `ATTUNE_ARTIFACTS_DIR`; existing symlinks and parent traversal are rejected.
Downloads are mode `0600` and partial output is removed after write failure.
Guest transfer URLs must be HTTPS, must not contain URL credentials, must target
the configured vCenter host (the documented `*` placeholder is replaced), and
cannot redirect. Guest paths are intentionally guest-native absolute or
relative strings; they are not local artifact paths.

## Upstream Differences

- Ambiguous name lookup and its early-return multiple-match bug are removed.
- Automatic host/datastore "best fit" and implicit disk placement are removed.
- TLS disabling, including `verify=False` guest transfers, is removed.
- Inline guest usernames/passwords and printed process specs are removed.
- Snapshot bulk-age deletion and broad all-VM destructive behavior are omitted.
- Legacy `/rest` tagging routes are replaced by current `/api` routes.
- Unbounded eventlet task loops are replaced by monotonic bounded polling.
- Raw SOAP/task errors are replaced by redacted operation and fault types.
- The StackStorm recent-task sensor is deferred because it has no durable,
  useful Attune execution mapping; task MOIDs are polled explicitly instead.

## Validation

```bash
python3 -m unittest discover -s tests -v
attune --output json pack check /home/david/Codebase/attune-packs/vsphere
attune pack test /home/david/Codebase/attune-packs/vsphere --detailed
```

Tests mock pyVmomi, vCenter, vAPI, Attune Keys, time, and transfers. No vCenter
or undeclared test dependency is required. Live behavior remains dependent on
vCenter version, licensing, privileges, VMware Tools, guest OS policy, network,
storage policy, and topology; those are deployment integration gaps, not unit
test claims.
