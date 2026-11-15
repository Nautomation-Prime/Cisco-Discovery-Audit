# Product provenance

This repository is the codebase for **Nautomation Prime Cisco Discovery
Audit**, licensed under the Apache License 2.0 from 15 November 2026.

## Ownership review

Repository history through 10 August 2026 contains commits authored under
Christopher Davies/Chris Davies aliases and GitHub Copilot automation. No
independent human contributor was identified in the Git author history.
Before commercial distribution, Nautomation Prime should retain records
confirming ownership of the Excel workbook, branding, documentation, and any
customer-provided fixtures.

Earlier revisions carried inconsistent Apache-2.0, MIT, and GPL-3.0 notices,
and a proprietary licence with an EULA was applied between August and
November 2026. From 15 November 2026 the project is licensed under Apache-2.0
and the EULA is withdrawn. Permissions already granted to recipients of
historical revisions are unaffected.

## Secure Cartography review

Secure Cartography was reviewed only as a design reference at commit
`0cc48580e62fea5b8d639b09f2d2d2ed3dab1453` on 10 August 2026:

* https://github.com/scottpeterman/secure_cartography/blob/0cc48580e62fea5b8d639b09f2d2d2ed3dab1453/pyproject.toml
* https://github.com/scottpeterman/secure_cartography/blob/0cc48580e62fea5b8d639b09f2d2d2ed3dab1453/sc2/scng/discovery/models.py
* https://github.com/scottpeterman/secure_cartography/blob/0cc48580e62fea5b8d639b09f2d2d2ed3dab1453/sc2/scng/discovery/engine.py
* https://github.com/scottpeterman/secure_cartography/blob/0cc48580e62fea5b8d639b09f2d2d2ed3dab1453/sc2/scng/discovery/ssh/collector.py

That project declares GPL-3.0. No source code, packaged TextFSM database, or
runtime dependency from Secure Cartography may be copied, imported, vendored,
or distributed in this product, because GPL-3.0 code cannot be relicensed
under Apache-2.0. Protocol-neutral records,
conservative topology deduplication, and separated collection/reporting were
implemented independently from public protocol and Cisco CLI behaviour.

## Parser templates

TextFSM templates are sourced from the Apache-2.0 NTC Templates project rather
than Secure Cartography:

* Upstream repository: https://github.com/networktocode/ntc-templates
* Reviewed commit: `d0bc5a480fe935afb6d9f6806c795a0390aaec90`
* LLDP source path: `ntc_templates/templates/cisco_ios_show_lldp_neighbors_detail.textfsm`

Template source and licence attribution must remain in distributed
third-party notices.
