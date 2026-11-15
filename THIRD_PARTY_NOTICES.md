# Third-party notices

Nautomation Prime Cisco Discovery Audit includes the following third-party
components. Their licences apply only to those components. Nautomation Prime's own code
is licensed under the Apache License 2.0 (see LICENSE).

| Component | Purpose | Licence | Source |
|---|---|---|---|
| CPython | Embedded Python runtime | PSF-2.0 | https://www.python.org/ |
| TextFSM | CLI output parsing | Apache-2.0 | https://github.com/google/textfsm |
| NTC Templates | Cisco CDP, LLDP, and version parser templates | Apache-2.0 | https://github.com/networktocode/ntc-templates |
| openpyxl | Excel workbook writing | MIT | https://foss.heptapod.net/openpyxl/openpyxl |
| PyYAML | Configuration parsing | MIT | https://github.com/yaml/pyyaml |
| Pydantic, pydantic-core, annotated-types, typing-inspection | Configuration and input validation | MIT | https://github.com/pydantic/pydantic |
| typing_extensions | Typing backports used by Pydantic | PSF-2.0 | https://github.com/python/typing_extensions |
| Paramiko | SSH transport | LGPL-2.1 | https://github.com/paramiko/paramiko |
| Netmiko | Network-device SSH sessions | MIT | https://github.com/ktbyers/netmiko |
| pySerial | Serial transport dependency used by Netmiko | BSD-3-Clause | https://github.com/pyserial/pyserial |
| Textual and Rich | Terminal user interface | MIT | https://github.com/Textualize/textual and https://github.com/Textualize/rich |
| pywin32 | Windows Credential Manager integration | PSF-2.0 | https://github.com/mhammond/pywin32 |
| tomli | TOML metadata parsing on Python 3.10 | MIT | https://github.com/hukkin/tomli |

The Windows release process copies the licence files shipped by the installed
distributions into `third_party_licenses/`. PyInstaller is used only to build
the Windows executable and is covered by GPL-2.0-or-later with its exception
for distributing bundled applications.

## NTC Templates attribution

The TextFSM templates under `assets/textfsm/` are derived from Network to
Code's NTC Templates project. The LLDP template is based on commit
`d0bc5a480fe935afb6d9f6806c795a0390aaec90`. The existing CDP and version
templates use the same upstream parsing rules and are retained with explicit
attribution.

Copyright 2015 Jason Edelman and Network to Code, LLC.

Licensed under the Apache License, Version 2.0. You may obtain a copy at:
https://www.apache.org/licenses/LICENSE-2.0
