# Source Verification

- Upstream: https://github.com/StackStorm-Exchange/stackstorm-vsphere
- Upstream version/tag: `1.3.5` / `v1.3.5`
- Verified revision: `eed7a36730d4e3f3c9463b256e5009374acd6072`
- Revision date: `2025-02-14T21:17:38Z`
- Revision signature: GitHub API reports `verified: true`, reason `valid`, verified at `2025-02-14T21:22:40Z`
- Local signature check: signature present; signer public key was not available locally
- Upstream license: Apache License 2.0
- Upstream NOTICE: none at the verified revision
- Upstream pyVmomi pin: `8.0.3.0.1`
- API and SDK baseline reviewed: `2026-08-15`

Current compatibility evidence:

- PyPI published pyVmomi `9.1.0.0` on `2026-05-12`; it is the current release reviewed for this pack.
- The pyVmomi project states Python 3.10+ support and compatibility with the previous four vSphere and pyVmomi releases. Compatibility outside that policy may work but is not actively supported.
- Broadcom's current Web Services API reference is vSphere API 9.1 and exposes references for 9.1, 9.0, 8.0 updates, and 7.0 updates.
- This pack lets SmartConnect negotiate the server API version, reports `about.apiVersion`, and rejects servers below the profile's `minimum_api_version` (default `7.0`). It does not force a newer wire version onto an older server.
- Tags/categories use the current vSphere Automation `/api/cis/tagging` API. The retired `/rest/com/vmware/cis/tagging` routes in upstream are not used.
- vSphere Automation features require vCenter; a direct standalone ESXi endpoint does not provide the tagging API.

Authoritative references:

- https://pypi.org/project/pyvmomi/9.1.0.0/
- https://developer.broadcom.com/sdks/pyvmomi/latest
- https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/
- https://developer.broadcom.com/xapis/vsphere-automation-api/latest/
- https://developer.broadcom.com/xapis/vsphere-automation-api/latest/cis-tagging/

The implementation is a safety-oriented Attune adaptation, not a line-for-line port.
The upstream task sensor was intentionally deferred: periodic scans of recent vCenter
tasks do not map to a durable Attune execution identity. `vsphere.task_status` instead
provides caller-directed, bounded polling of a recorded task MOID.
