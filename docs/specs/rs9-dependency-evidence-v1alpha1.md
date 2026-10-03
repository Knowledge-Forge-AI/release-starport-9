# Linux dependency evidence v1alpha1

Status: implemented candidate, with unresolved runtime and mapping qualification
reported explicitly. Distro names are adapter-owned knowledge, never tenant facts.

`rs9.dependency-evidence.v1alpha1` binds the ingestion record hash and has sorted
per-platform records. Each includes:

- asset and payload-manifest identities;
- every ELF object's path/hash, machine/type, PT_INTERP, DT_NEEDED, SONAME,
  RPATH/RUNPATH and GNU version needs;
- executable scripts' shebang argv, interpreter and nearest packaged engine
  declaration with its source hash where available;
- system SONAMEs and requiring objects, reachable bundled providers, symbol
  version floors, candidate ecosystem packages and mapping qualification;
- unresolved findings and advisory dlopen string candidates.

The parser supports ELF64 little endian x86_64/aarch64, checks file/segment/string
and linked-table bounds, and rejects unsupported or malformed inputs. System
loader resolution is not inferred from filenames: a bundled SONAME must have an
unambiguous provider reachable through the requiring object's `$ORIGIN` search
path. Foreign architecture, unknown SONAME/interpreter and unqualified search
paths remain findings. A colocated library without loader-path evidence is not
automatically bundled.

Version floors are numerical maxima of required GLIBC/GLIBCXX/CXXABI symbols.
They describe symbol ABI requirements, not the installed package's version.
The adapters can translate the GLIBC floor and a simple observed Node `>=N`
engine constraint into package constraints; GLIBCXX/CXXABI retain symbol evidence
and RPM automatic requirements. Nix package attributes need separate provider
and version qualification.

All released executable capabilities are conservatively scanned, including
auxiliary Loom scripts. Their use by the GUI is not inferred from a shebang.
`DT_NEEDED` does not capture dlopen or transitive library closure. Advisory strings
are neither mandatory dependencies nor proof of absence. Node module/resource
resolution and GUI sidecar readiness require observable runtime qualification.

Core evidence labels mappings unqualified. Container provider receipts can
qualify individual mappings for a named environment without changing tenant
facts or making an edited JSON verdict authoritative. `hicolor-icon-theme` is an
adapter desktop integration dependency; it does not originate in ELF evidence.

The [Nebular report](../architecture/nebular-shadow-projection.md) compares the
observed closures with the existing public recipes. Full package acceptance stays
deferred until all relevant evidence and installation gates are satisfied.
