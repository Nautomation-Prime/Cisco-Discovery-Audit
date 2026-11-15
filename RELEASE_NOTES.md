# Nautomation Prime Cisco Discovery Audit 1.0.0

## Premium release highlights

- Configurable `cdp`, `lldp`, or `both` discovery with CDP as the default.
- Cisco IOS and IOS-XE discovery over the existing SSH/Netmiko connection.
- CDP and LLDP observations of the same adjacency are merged and labelled
  `CDP+LLDP`.
- Non-Cisco LLDP peers remain visible in the report but are not crawled.
- Inventory rows show explicit protocol status, including disabled,
  unsupported, empty, and parse-failed results.
- Rebranded Excel workbook with protocol provenance and discovery-mode metadata.
- Self-contained Windows x64 one-folder package; Python is not required.

## Supported environment

- Windows 10 or Windows 11, 64-bit.
- Cisco IOS and IOS-XE devices reachable by SSH.
- Optional SSH jump/bastion host.

## Upgrade note

The application retains the established `CDP_*` environment-variable names
for compatibility. The editable `config.yaml` now contains
`discovery.protocol`, which accepts `cdp`, `lldp`, or `both`.

Generated topology and inventory files may contain sensitive infrastructure
information. Store and distribute them according to your organisation's
security policy.
