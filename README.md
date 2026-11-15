# Nautomation Prime Cisco Discovery Audit

Nautomation Prime Cisco Discovery Audit is a premium Windows network-audit
tool for Cisco IOS and IOS-XE environments. Starting from one or more seed
devices, it connects over SSH, discovers neighboring infrastructure with CDP,
LLDP, or both protocols, and produces a structured Excel workbook.

The release is a self-contained one-folder Windows download. It does
not require Python, an installer, online activation, a database, or a hosted
service.

## Supported scope

| Area | Support |
|---|---|
| Operating system | Windows 10/11 x64 |
| Network devices | Cisco IOS and IOS-XE |
| Connection | SSH through Netmiko, direct or through one jump host |
| Discovery | CDP, LLDP, or both |
| Reporting | Excel topology, inventory, DNS, and error sheets |
| Credentials | Windows Credential Manager or session-only entry |

Devices from other vendors can appear as LLDP neighbors in the report, but
the Cisco SSH driver will not connect to or crawl them.

## Discovery modes

Set the mode in the editable `config.yaml` beside the executable:

```yaml
discovery:
  protocol: "cdp"
```

Valid values are:

| Value | Behavior |
|---|---|
| `cdp` | Runs CDP only. This is the default and preserves established behavior. |
| `lldp` | Runs LLDP only. |
| `both` | Runs CDP and LLDP in the same SSH session and merges matching observations. |

In `both` mode, a physical adjacency reported by both protocols becomes one
directional report row with `PROTOCOLS` set to `CDP+LLDP`. Matching is
conservative: local port, remote identity, and remote port must agree after
normalizing common Cisco interface abbreviations. Ambiguous observations are
kept as separate rows rather than being merged incorrectly.

## Customer installation

1. Download the Windows ZIP release.
2. Verify its SHA-256 value against the supplied `.sha256` file or product
   manifest.
3. Extract the complete folder to a writable location.
4. Run
   `NautomationPrimeCiscoDiscoveryAudit.exe`.

Keep the executable, `_internal` directory, `config.yaml`, and `assets`
directory together. Moving only the executable will make the support files
unavailable.

## Running an audit

The setup screen collects:

- site name;
- one or more seed IP addresses or resolvable hostnames;
- primary device credentials;
- optional fallback credentials;
- optional jump/bastion host;
- optional CIDR, address range, or individual-IP discovery filter; and
- whether entered credentials should be stored in Windows Credential Manager.

The configured discovery mode is displayed in the setup and progress screens.
It is intentionally controlled by `config.yaml` rather than a per-run switch
so an organisation can standardize its audit method.

The application:

1. validates the selected protocol templates and workbook;
2. resolves and deduplicates seed devices;
3. connects to each Cisco device once;
4. runs `show version` and the selected neighbor command or commands;
5. normalizes and, in `both` mode, merges neighbor observations;
6. crawls eligible Cisco IOS/IOS-XE infrastructure management addresses;
7. performs best-effort DNS enrichment; and
8. writes the Excel report under `output/`.

## Report

The output filename is:

```text
<site>_Cisco_Discovery_Audit.xlsx
```

Unsafe Windows filename characters in the site name are replaced with
underscores. The original site name is retained inside the workbook.

### Audit sheet

One row represents one directional observation from a successfully queried
device:

| Column | Meaning |
|---|---|
| `LOCAL_HOST` | Local Cisco hostname |
| `LOCAL_IP` | Address used to query the local device |
| `LOCAL_PORT` | Local interface |
| `DESTINATION_HOST` | Neighbor name or LLDP chassis identity |
| `REMOTE_PORT` | Neighbor interface |
| `MANAGEMENT_IP` | Neighbor management address |
| `PLATFORM` | Reported platform/model when available |
| `SOFTWARE_VERSION` | CDP version or LLDP system description when available |
| `CAPABILITIES` | Protocol-reported capabilities |
| `PROTOCOLS` | `CDP`, `LLDP`, or `CDP+LLDP` |

### Inventory sheet

Inventory is derived from `show version` on devices that were actually
queried. `PROTOCOL_STATUS` distinguishes:

- `ok` with the parsed neighbor count;
- `empty` when the command succeeded with no neighbors;
- `disabled`;
- `unsupported`; and
- `parse failed`.

The status is also written to the application log so a disabled protocol is
not mistaken for a successful empty discovery.

### Other sheets

- `DNS Resolved`
- `Authentication Errors`
- `Connection Errors`

## Traversal safeguards

- CDP retains the established switch-capability traversal rule.
- LLDP peers are crawled only when their advertised description positively
  identifies supported Cisco IOS or IOS-XE infrastructure.
- Non-Cisco and unknown LLDP peers remain visible as leaf observations.
- Duplicate management addresses are queried once.
- The optional IP filter limits newly discovered management addresses. It
  accepts a comma-separated list of CIDR prefixes, inclusive ranges, and
  single addresses, for example
  `10.1.0.0/16, 192.168.1.5-192.168.1.9, 172.16.0.1`. Seed devices are always
  contacted regardless of the filter.
- Connection failures are retried according to
  `network.max_retry_attempts`.
- Press `Ctrl+S` on the discovery screen to stop early. Devices already being
  queried finish, and a report is written from what was collected.

## Credentials and security

Primary and optional fallback credentials can be stored in Windows Credential
Manager. Passwords are not written to `config.yaml`, logs, reports, or the
product manifest.

The jump host uses the primary credential. Fallback credentials apply only to
the destination device. All workers share a single SSH session to the jump
host and open one forwarded channel per device, so a crawl does not produce a
login per device.

By default an unknown jump-host SSH key is accepted with a logged warning. Set
`network.strict_host_keys: true` (or `CDP_STRICT_HOST_KEYS=1`) to reject any
key that is not already in the user's `known_hosts` file. Connect to the jump
host once with a normal SSH client first so its key is recorded. Enabling this
is recommended in production, as the bastion hop is usually the one that
crosses a trust boundary.

Audit workbooks and debug logs can expose hostnames, addresses, software
versions, serial numbers, interfaces, and topology. Treat the entire
extracted application folder and generated `output/` and `logs/` directories
as sensitive operational data. `logs/debug.log` rotates at 5 MB and keeps
three previous files; raw device command output is excluded from it unless
`CDP_DEBUG_RAW=1` is set for troubleshooting.

## Main configuration

```yaml
discovery:
  protocol: "cdp"  # cdp, lldp, or both

network:
  jump_host: ""
  device_type: "cisco_ios"
  ssh_port: 22
  strict_host_keys: false
  default_limit: 10
  default_timeout: 10
  max_retry_attempts: 3
```

The historical `CDP_*` environment-variable names remain supported for
compatibility:

| Variable | Purpose |
|---|---|
| `CDP_LIMIT` | Concurrent discovery workers |
| `CDP_TIMEOUT` | SSH operation timeout |
| `CDP_JUMP_SERVER` | Default jump host |
| `CDP_PRIMARY_CRED_TARGET` | Primary Credential Manager target |
| `CDP_ANSWER_CRED_TARGET` | Fallback Credential Manager target |
| `CDP_STRICT_HOST_KEYS` | Reject unknown jump-host SSH keys |
| `CDP_DEBUG_RAW` | Log raw device output (sensitive; off by default) |
| `LOGGING_CONFIG` | Alternate logging configuration |

These are ordinary environment variables set in the shell or in Windows; the
application does not read a `.env` file. Device credentials are never
configured this way — see `.env.example` for the full list.

`config.yaml` and these overrides are validated at start-up. A misspelt key,
an out-of-range value (for example `default_limit: 0`), an unknown Netmiko
`device_type`, or a jump host written as `user@host` or `host:port` stops the
tool before any device is contacted, with one line per problem naming the
setting (and the environment variable, if that is where the value came from).

## Troubleshooting

Run the installation check from PowerShell or Command Prompt:

```powershell
.\NautomationPrimeCiscoDiscoveryAudit.exe --check-install
```

Display the installed version:

```powershell
.\NautomationPrimeCiscoDiscoveryAudit.exe --version
```

Operational details are written to `logs/debug.log`. A protocol-specific
problem should also be visible in the Inventory `PROTOCOL_STATUS` column.

## Development

Source development supports Python 3.10 through 3.12:

```powershell
python -m pip install -e ".[dev,build]"
python -m pytest tests/ -q
python -m cdp_audit
```

Build the Windows one-folder executable and website handoff files:

```powershell
pyinstaller --noconfirm --clean cisco_discovery_audit.spec
python scripts/package_release.py
```

The release workflow runs the tests, builds on `windows-latest`, optionally
uses Authenticode secrets when configured, smoke-tests the packaged
application, and uploads a private workflow artifact. It does not create a
public GitHub Release.

The website handoff under `release/` contains:

- the Windows x64 ZIP;
- SHA-256 checksum;
- release notes; and
- `product-manifest.json` with version, platform, protocol support, filename,
  size, and checksum.


## Licensing and provenance

This product is licensed under the Apache License 2.0; see `LICENSE` and
`NOTICE`. It is free to use, modify and redistribute. Third-party components
retain their own licences; see `THIRD_PARTY_NOTICES.md` and the licence files
included in release builds. Tailoring, deployment and bespoke development are
available from Nautomation Prime: https://www.nautomationprime.io/work-with-me/

Secure Cartography was reviewed as a GPL-3.0 design reference only. No source
code, runtime package, or packaged template database from it is included.
Parser templates are attributed to the Apache-2.0 NTC Templates project.
Internal provenance details are recorded in `docs/PROVENANCE.md`.
