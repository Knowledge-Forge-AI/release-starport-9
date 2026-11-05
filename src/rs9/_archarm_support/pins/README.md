# Qualified ArchARM pins (byte-exact copies required)

`rs9._archarm_support.pins.load_qualified_pins()` reads exactly these three
files from this directory and refuses (`ARCHARM_PIN_FILE`) on absence or any
byte difference. They are not regenerated, refreshed or re-pinned.

| File | Bytes | SHA-256 | Origin (public P tree) |
| --- | --- | --- | --- |
| `PACKAGE-PINS.json` | 78585 | `53c812397e73cdb16c80cd5cd72b6ed66889817d8aa79b075034434895da2987` | `tools/verification/archarm_runtime_probe/PACKAGE-PINS.json` |
| `ROOTFS-PIN.json` | 3408 | `0d92f648e1f9bc2ef29846b7f37d7fae99ccbb4adc6fd918d797c2ac9054edff` | `tools/verification/archarm_base_probe/ROOTFS-PIN.json` |
| `archlinuxarm-builder-public.gpg` | 3857 | `4e4202772328674af68f90f675e077d192337fc8ced15cddcd35875a9de5b5f9` | `tools/verification/archarm_base_probe/archlinuxarm-builder-public.gpg` |

The preparing worker had only text-editing tools and could not create a
byte-exact copy of the binary public key, so it placed none of the three. The
parent must byte-copy them from the qualified source (the files under
`reference/qualified-tools/`). It must then check the sizes and digests above
and include this directory in the package data.
