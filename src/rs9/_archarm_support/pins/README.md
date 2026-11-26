# Qualified ArchARM pins (byte-exact copies required)

`rs9._archarm_support.pins.load_qualified_pins()` reads exactly these three
files from this directory and refuses (`ARCHARM_PIN_FILE`) on absence or any
byte difference. They are not regenerated, refreshed or re-pinned.

| File | Bytes | SHA-256 | Origin (public P tree) |
| --- | --- | --- | --- |
| `PACKAGE-PINS.json` | 78585 | `53c812397e73cdb16c80cd5cd72b6ed66889817d8aa79b075034434895da2987` | `tools/verification/archarm_runtime_probe/PACKAGE-PINS.json` |
| `ROOTFS-PIN.json` | 3408 | `0d92f648e1f9bc2ef29846b7f37d7fae99ccbb4adc6fd918d797c2ac9054edff` | `tools/verification/archarm_base_probe/ROOTFS-PIN.json` |
| `archlinuxarm-builder-public.gpg` | 3857 | `4e4202772328674af68f90f675e077d192337fc8ced15cddcd35875a9de5b5f9` | `tools/verification/archarm_base_probe/archlinuxarm-builder-public.gpg` |

## Named successors

Each successor carries its own exact package file, byte length and SHA-256.
All profiles reuse the root filesystem and signing certificate listed above.

The Nebular 0.8.0 product route selects `PACKAGE-PINS-successor-20261126.json`.
Its 79,740 bytes match SHA-256
`1471e21504ac0edb5d1abf9602f0266e6efce42e8c9398aff7f5efadda6cb17a`.
Only the eight package rows identified in the graphics runtime probe changed
from the 20261120 profile. The
[key-free native probe](https://github.com/Knowledge-Forge-AI/theme-forge-packages/actions/runs/45865135627)
verified the dependency runtime. RS9 product build and client qualification
require their own evidence.
