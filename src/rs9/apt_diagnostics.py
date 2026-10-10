"""WP-APT command diagnostics and read-only guest trust probe.

Provides bounded, sanitized diagnostic collection, in-guest read-only trust
probing for root and _apt readability/ancestors/modes/hashes/verifiers,
explicit positive control binding, and causally meaningful tamper qualification
where wrong reasons cannot pass tamper.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

from rs9.build_native import CommandReceipt
from rs9.errors import ContractError

from rs9.machine_stream import machine_text


REASON_CATEGORIES = (
    "COMMAND_SUCCESS",
    "SIGNATURE_REJECTED",
    "SIGNED_ENVELOPE_INVALID",
    "KEY_MISMATCH",
    "INDEX_HASH_MISMATCH",
    "PACKAGE_HASH_MISMATCH",
    "PACKAGE_CORRUPT",
    "INDEX_CORRUPT",
    "PERMISSION_DENIED",
    "COMMAND_NOT_FOUND",
    "PACKAGE_NOT_FOUND",
    "NETWORK_UNAVAILABLE",
    "INVENTORY_FAILED",
    "UNCLASSIFIED_FAILURE",
    "SIGNATURE_POLICY_REJECTED",
    "SANDBOX_UNREADABLE",
    "RELEASE_NOT_VALID_YET",
    "NO_RELEASE_FILE",
    "SOURCE_CONFIG_ERROR",
)

QUALIFYING_TAMPER_CATEGORIES: dict[str, set[str]] = {
    "package": {
        "PACKAGE_HASH_MISMATCH",
        "PACKAGE_CORRUPT",
    },
    "index": {
        "INDEX_HASH_MISMATCH",
        "INDEX_CORRUPT",
        "SIGNATURE_REJECTED",
    },
    "signature": {
        "SIGNATURE_REJECTED",
        "SIGNED_ENVELOPE_INVALID",
    },
    "wrongkey": {"KEY_MISMATCH"},
}

GUEST_PROBE_PYTHON_SNIPPET = r"""
import hashlib,json,os,pwd,stat,subprocess,sys
try: apt_present=bool(pwd.getpwnam('_apt'))
except KeyError: apt_present=False
rows=[]
for target in sys.argv[1:]:
    ancestors=[]
    current=target
    while True:
        row={"path":current}
        try:
            st=os.lstat(current)
            kind='directory' if stat.S_ISDIR(st.st_mode) else 'file' if stat.S_ISREG(st.st_mode) else 'symlink' if stat.S_ISLNK(st.st_mode) else 'special'
            row.update(type=kind,mode=stat.S_IMODE(st.st_mode),owner='root' if st.st_uid==0 else 'self' if st.st_uid==os.getuid() else 'other',readable=os.access(current,os.R_OK),traversable=os.access(current,os.X_OK) if kind=='directory' else None)
            if current==target and kind=='file' and st.st_size<=1024*1024:
                fd=os.open(current,os.O_RDONLY|os.O_NOFOLLOW)
                with os.fdopen(fd,'rb') as f: row['sha256']=hashlib.sha256(f.read(1024*1024+1)).hexdigest()
        except OSError as e: row.update(error='missing' if isinstance(e,FileNotFoundError) else 'permission-denied' if isinstance(e,PermissionError) else 'io-error')
        ancestors.append(row)
        parent=os.path.dirname(current)
        if parent==current: break
        current=parent
    rows.append({"target":target,"ancestors":ancestors})
versions={}
for name in ('apt-get','sqv','gpgv'):
    try:
        r=subprocess.run([name,'--version'],capture_output=True,timeout=5)
        versions[name]={"exit_code":r.returncode,"stdout_sha256":hashlib.sha256(r.stdout).hexdigest(),"stderr_sha256":hashlib.sha256(r.stderr).hexdigest(),"version":r.stdout.decode('ascii',errors='replace').splitlines()[0] if r.stdout else None}
    except (OSError,subprocess.TimeoutExpired): versions[name]={"status":"unavailable"}
print(json.dumps({"apt_user_present":apt_present,"targets":rows,"verifiers":versions}))
"""


def safe_sample(text: str | bytes, max_chars: int = 512) -> str:
    """Sanitize and cap diagnostic stream: printable ASCII only, redacted absolute paths."""
    if isinstance(text, (bytes, bytearray)):
        text = text.decode("ascii", errors="replace")
    if not isinstance(text, str):
        text = str(text)
    if any(c not in "\n\r\t" and not 32 <= ord(c) < 127 for c in text):
        return "non-printable-stream-withheld"
    # Withhold the whole sample on a credential match, before truncation.
    from rs9.security import scan_for_credentials
    from rs9.errors import ContractError
    try:
        scan_for_credentials(text)
    except ContractError:
        return "credential-stream-withheld"
    text = re.sub(r"(?i)(?:bearer\s+|(?:password|token|secret|credential)\s*[:=]\s*)\S+", "[CREDENTIAL]", text)
    text = re.sub(r"https?://[^\s]+", "[URL]", text)
    text = re.sub(r"(?<![A-Za-z0-9])/(?:[^\s:;,\"']+)", "[PATH]", text)
    return text[:max_chars]


def classify_rejection(
    receipt: CommandReceipt | None,
    *,
    stage: str | None = None,
    family: str = "apt",
    source_uri: str | None = None,
    distribution: str | None = None,
) -> str:
    """Classify command outcome into a bounded reason category."""
    if receipt is None:
        return "UNCLASSIFIED_FAILURE"
    if receipt.exit_code == 0:
        return "COMMAND_SUCCESS"

    if family == "dnf":
        from rs9.dnf_diagnostics import classify_dnf
        return classify_dnf(receipt, stage=stage)

    combined = (receipt.stderr_text + "\n" + receipt.stdout_text)[:1024 * 1024].lower()
    categories = (("SIGNATURE_POLICY_REJECTED", ("policy rejects", "not bound", "weak digest", "unsupported public key algorithm")),
                  ("SANDBOX_UNREADABLE", ("unsandboxed as root", "couldn't be accessed by user '_apt'")),
                  ("RELEASE_NOT_VALID_YET", ("not valid yet",)),
                  ("NO_RELEASE_FILE", ("does not have a release file",)),
                  ("SOURCE_CONFIG_ERROR", ("malformed entry", "conflicting values set for option signed-by")))
    for category, tokens in categories:
        if any(token in combined for token in tokens):
            return category

    if receipt.exit_code == 127 or "command not found" in combined:
        return "COMMAND_NOT_FOUND"

    if "permission denied" in combined or "could not open lock file" in combined or "are you root?" in combined:
        return "PERMISSION_DENIED"

    # A transport or missing-package failure cannot qualify a trust negative,
    # even when the stream also contains a generic signature message.
    if any(s in combined for s in ("network is unreachable", "could not connect",
                                   "cannot assign requested address", "could not resolve host",
                                   "temporary failure resolving", "name or service not known",
                                   "connection refused", "connection timed out", "network down",
                                   "<html", "<!doctype", "captive portal", "302 found", "403 forbidden",
                                   "401 unauthorized", "500 internal server error", "http/1.")):
        return "NETWORK_UNAVAILABLE"
    if any(s in combined for s in ("unable to locate package", "no installation candidate",
                                   "target not found:", "no match for argument:")):
        return "PACKAGE_NOT_FOUND"

    # Narrow causal invalid-envelope acceptance: resolute InRelease invalid envelope at apt refresh exit 100
    if _is_signed_envelope_invalid(receipt, stage=stage, family=family,
                                   source_uri=source_uri, distribution=distribution):
        return "SIGNED_ENVELOPE_INVALID"

    # Family-specific wording must precede generic corruption fallbacks. These
    # are diagnostic categories; the positive control and failing stage still
    # determine whether a tamper rejection earns qualification credit.
    if family == "apt" and re.search(r"\bmissing key [0-9a-f]+\b", combined):
        return "KEY_MISMATCH"
    if family == "pacman":
        # Pacman prints this fixed repository-key diagnostic before its generic
        # PGP corruption summary. Accept only a complete hexadecimal identity;
        # malformed keys and remote lookup errors alone prove no key mismatch.
        if re.search(r'^error: rs9: key "[0-9a-f]{40}" is unknown\s*$', combined, re.MULTILINE):
            return "KEY_MISMATCH"
        if re.search(r'signature from .+ is invalid\b', combined) or any(
                token in combined for token in ("invalid or corrupted database (pgp signature)",
                                               "invalid or corrupted package (pgp signature)")):
            return "SIGNATURE_REJECTED"
    if family == "dnf":
        if any(token in combined for token in ("signing key not found", "public key is not installed")):
            return "KEY_MISMATCH"
        if "bad gpg signature" in combined:
            return "SIGNATURE_REJECTED"

    if family != "pacman" and any(token in combined for token in ("no_pubkey", "public key is not available", "unknown key", "unknown trust", "public key not found")):
        return "KEY_MISMATCH"

    if any(s in combined for s in ("badsig", "is not signed", "invalid signature", "corrupted signature", "expkeysig")):
        return "SIGNATURE_REJECTED"

    if "hash sum mismatch" in combined or "checksum mismatch" in combined:
        if stage == "install" or ".deb" in combined:
            return "PACKAGE_HASH_MISMATCH"
        return "INDEX_HASH_MISMATCH"

    if "unable to locate package" in combined or "no installation candidate" in combined:
        return "PACKAGE_NOT_FOUND"

    if any(s in combined for s in ("network is unreachable", "could not connect", "cannot assign requested address")):
        return "NETWORK_UNAVAILABLE"


    if "invalid or corrupted package" in combined or "invalid or corrupted database" in combined:
        if stage == "install" or ".deb" in combined:
            return "PACKAGE_CORRUPT"
        return "INDEX_CORRUPT"

    return "UNCLASSIFIED_FAILURE"


def _is_signed_envelope_invalid(
    receipt: CommandReceipt,
    *,
    stage: str | None = None,
    family: str = "apt",
    source_uri: str | None = None,
    distribution: str | None = None,
) -> bool:
    """Repair only exact local file: resolute InRelease invalid envelope at apt refresh exit 100."""
    if (family != "apt" or stage != "refresh" or receipt.exit_code != 100
            or source_uri != "file:/srv/rs9/apt" or distribution != "resolute"):
        return False

    if len(receipt.stdout_bytes) + len(receipt.stderr_bytes) > 1024 * 1024:
        return False

    if receipt.stdout_bytes and not receipt.stdout_bytes.endswith(b"\n"):
        return False
    if receipt.stderr_bytes and not receipt.stderr_bytes.endswith(b"\n"):
        return False

    try:
        stdout_text = machine_text(
            receipt,
            stream="stdout",
            limit=1024 * 1024,
            code="STREAM_LIMIT_EXCEEDED",
            substage="refresh-stream",
            encoding="utf-8",
        )
        stderr_text = machine_text(
            receipt,
            stream="stderr",
            limit=1024 * 1024,
            code="STREAM_LIMIT_EXCEEDED",
            substage="refresh-stream",
            encoding="utf-8",
        )
    except (ContractError, UnicodeDecodeError):
        return False

    stream_text = stderr_text + stdout_text
    combined = stream_text.lower()

    # Reject HTTP / HTTPS / captive portal HTML content
    if any(h in combined for h in ("http://", "https://", "<html", "<!doctype", "captive portal", "login required", "302 found", "403 forbidden", "401 unauthorized", "http/1.")):
        return False

    # Explicit local file source and resolute InRelease distribution context required
    if "resolute" not in combined or "inrelease" not in combined:
        return False
    if not re.search(r"file:(?:/|\[path\])", combined):
        return False

    lines = [line.strip() for line in stream_text.splitlines() if line.strip()]
    if not lines:
        return False

    expected = (f"e: openpgp signature verification failed: {source_uri} {distribution} "
                "inrelease: signed file isn't valid, got 'nodata'")
    suffix = " (does the network require authentication?)"
    location = re.escape(source_uri + " " + distribution + " InRelease")
    progress = re.compile(r"(?:Get|Hit|Ign|Err):[0-9]+ " + location + r"(?: \[[0-9,]+ B\])?", re.I)
    continuation = re.compile(r"signed file isn't valid, got 'nodata'(?: \(does the network require authentication\?\))?(?: \[[0-9,]+ B\])?", re.I)
    has_qualifying = False
    for line in lines:
        if line.lower() in {expected, expected + suffix}:
            has_qualifying = True
        elif (progress.fullmatch(line)
              or line.lower() in {"reading package lists...", "reading package lists... done"}
              or continuation.fullmatch(line)):
            continue
        else:
            return False

    return has_qualifying


def record_command_diagnostics(
    *,
    stage: str,
    family: str,
    product: str,
    arch: str,
    receipt: CommandReceipt | None = None,
    repo_identity: str | None = None,
    public_fingerprint: str | None = None,
    verification: Mapping[str, Any] | None = None,
    source_uri: str | None = None,
    distribution: str | None = None,
) -> dict[str, Any]:
    """Bounded, sanitized diagnostics recording command execution evidence."""
    category = classify_rejection(receipt, stage=stage, family=family,
                                  source_uri=source_uri, distribution=distribution)
    out: dict[str, Any] = {
        "stage": stage,
        "family": family,
        "product": product,
        "arch": arch,
        "reason_category": category,
    }
    if receipt is not None:
        out["exit_code"] = receipt.exit_code
        out["stdout_sha256"] = receipt.stdout_sha256
        out["stderr_sha256"] = receipt.stderr_sha256
        out["stdout_bytes"] = len(receipt.stdout_bytes)
        out["stderr_bytes"] = len(receipt.stderr_bytes)
        out["safe_sample"] = safe_sample(receipt.stderr_text or receipt.stdout_text)
        stream_shapes = {}
        for name, raw_bytes in (("stdout", receipt.stdout_bytes), ("stderr", receipt.stderr_bytes)):
            raw_len = len(raw_bytes)
            is_strict_utf8 = True
            try:
                decoded = raw_bytes.decode("utf-8")
            except UnicodeDecodeError:
                is_strict_utf8 = False
                decoded = getattr(receipt, f"{name}_text", "")

            raw_lines = decoded.splitlines()
            line_count = len(raw_lines)
            preview_lines = [safe_sample(line, 512) for line in raw_lines[:64]]

            complete = (
                raw_len <= 65536
                and is_strict_utf8
                and line_count <= 64
                and all(len(line) <= 512 for line in raw_lines)
                and all(all(c in "\n\r\t" or 32 <= ord(c) < 127 for c in line) for line in raw_lines)
                and not any(p in {"non-printable-stream-withheld", "credential-stream-withheld"} for p in preview_lines)
            )
            stream_shapes[name] = {
                "lines": preview_lines,
                "line_count": line_count,
                "complete": complete,
            }
        out["stream_shapes"] = stream_shapes
    else:
        out["exit_code"] = None
        out["stdout_sha256"] = None
        out["stderr_sha256"] = None
        out["stdout_bytes"] = 0
        out["stderr_bytes"] = 0
        out["safe_sample"] = ""

    if category == "SIGNED_ENVELOPE_INVALID":
        out["distribution"] = "resolute"
        out["source_context"] = "file"
        out["target_envelope"] = "InRelease"

    if repo_identity:
        out["repo_identity"] = str(repo_identity)[:256]
    if public_fingerprint:
        out["public_fingerprint"] = str(public_fingerprint)[:64]
    if verification:
        out["verification"] = {k:v for k,v in verification.items() if k in {"untampered_refresh","signature_status","signatures_ok"} and v in {True,False,"pass","fail","not-run"}}
    return out


def probe_guest_trust(client, *, keyring_path="/etc/apt/keyrings/rs9-nonproduction.gpg",
                      repo_root="/srv/rs9/apt", arch="amd64", expected_key_sha256=None,
                      public_fingerprint=None):
    """Actually read public inputs as root and _apt; never synthesize observations."""
    if arch not in {"amd64", "arm64"}:
        raise ValueError("invalid-probe-architecture")
    targets = [keyring_path, repo_root, *[f"{repo_root}/dists/resolute/{p}" for p in
               ("InRelease", "Release", "Release.gpg", *[f"main/binary-{arch}/Packages{s}" for s in ("", ".xz", ".gz")])]]
    result = {"status": "probed", "users": {}}
    for user in (None, "_apt"):
        label = "root" if user is None else "_apt"
        try:
            receipt = client.exec(["python3", "-c", GUEST_PROBE_PYTHON_SNIPPET, *targets], user=user)
        except Exception:
            result['users'][label]={'status':'probe-unavailable'}
            result['status']='incomplete'
            continue
        row = record_command_diagnostics(stage="trust-probe",family="apt",product="repository",arch=arch,receipt=receipt)
        try:
            if receipt.exit_code or len(receipt.stdout_bytes) > 48 * 1024:
                raise ValueError()
            doc = json.loads(receipt.stdout_bytes)
            if not isinstance(doc,dict) or not isinstance(doc.get("targets"),list) or len(doc["targets"])!=len(targets):
                raise ValueError()
            # Only allow requested guest paths and their ancestors; raw errors
            # and unexpected output fields do not enter diagnostic custody.
            observations=[]
            for target in doc["targets"]:
                if not isinstance(target, dict) or target.get("target") not in targets or not isinstance(target.get("ancestors"),list):
                    raise ValueError()
                ancestors=[]
                allowed={str(p) for p in (Path(target["target"]),*Path(target["target"]).parents)}
                for a in target["ancestors"][:32]:
                    if not isinstance(a, dict) or a.get("path") not in allowed: raise ValueError()
                    filtered={"path":a["path"]}
                    for k in ("type","mode","owner","readable","traversable","error","sha256"):
                        v=a.get(k)
                        valid=(k=='type' and v in {'file','directory','symlink','special'} or
                               k=='owner' and v in {'root','self','other'} or
                               k=='error' and v in {'missing','permission-denied','io-error'} or
                               k=='mode' and type(v)is int and 0<=v<=0o7777 or
                               k in {'readable','traversable'} and type(v)is bool or
                               k=='sha256' and isinstance(v,str) and re.fullmatch(r'[0-9a-f]{64}',v))
                        if valid: filtered[k]=v
                    ancestors.append(filtered)
                observations.append({"target":target["target"],"ancestors":ancestors})
            row["targets"]=observations
            row["apt_user_present"]=doc.get("apt_user_present") is True
            versions = doc.get('verifiers', {})
            if not isinstance(versions, dict):
                raise ValueError()
            row['verifiers'] = {}
            for name, info in versions.items():
                if name not in {'apt-get', 'sqv', 'gpgv'} or not isinstance(info, dict):
                    continue
                bounded = {}
                for key, value in info.items():
                    if key == 'version' and isinstance(value, str):
                        bounded[key] = safe_sample(value, 128)
                    elif key in {'stdout_sha256', 'stderr_sha256'} and isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value):
                        bounded[key] = value
                    elif key == 'exit_code' and type(value) is int and -128 <= value <= 255:
                        bounded[key] = value
                    elif key == 'status' and value == 'unavailable':
                        bounded[key] = value
                row['verifiers'][name] = bounded
        except (ValueError,TypeError,KeyError):
            row['status']='probe-unavailable'
            result['status']='incomplete'
        result['users'][label]=row
    result['expected_key_sha256']=expected_key_sha256
    result['public_fingerprint']=public_fingerprint
    actual=next((a.get('sha256') for t in result['users']['root'].get('targets',[]) if t['target']==keyring_path
                 for a in t['ancestors'] if a['path']==keyring_path),None)
    result['key_readback_matches']=bool(expected_key_sha256 and actual==expected_key_sha256)
    try:
        receipt=client.exec(['gpgv','--status-fd','1','--keyring',keyring_path,
                             repo_root+'/dists/resolute/Release.gpg',repo_root+'/dists/resolute/Release'])
        valid=re.findall(r'\[GNUPG:\] VALIDSIG ([0-9A-F]{40})\b',receipt.stdout_text)
        result['signature_verification']={'status':'pass' if receipt.exit_code==0 and valid and public_fingerprint in valid else 'not-run' if receipt.exit_code==127 else 'fail',
            'issuer_fingerprints':valid[:4],'stdout_sha256':receipt.stdout_sha256,'stderr_sha256':receipt.stderr_sha256,'exit_code':receipt.exit_code}
    except Exception:
        result['signature_verification']={'status':'not-run','reason':'probe-unavailable'}
    return result


def trust_identity(spec):
    """Public index/key byte identities and config binding; no host paths retained."""
    from rs9.release_core import digest
    from rs9.scratch import canonical
    identities=[]
    for source,target,writable in spec.get('mounts',[]):
        if writable: continue
        p=Path(source)
        if target.startswith('/rs9') or '/smoke' in target: continue
        files=([p] if p.is_file() else
               [f for f in p.rglob('*') if f.is_file() and not f.is_symlink() and
                (f.name in {'InRelease','Release','Release.gpg','repomd.xml','repomd.xml.asc','rs9.db','rs9.db.sig','rs9.db.tar.gz','rs9.db.tar.gz.sig'}
                 or f.suffix in {'.asc','.gpg'})])
        identities.append({'destination':target,'files':[
            {'path':f.name if p.is_file() else f.relative_to(p).as_posix(),'sha256':digest(f.read_bytes())}
            for f in sorted(files)]})
    return digest(canonical({'family':spec['family'],'configure':spec['configure'],'refresh':spec['refresh'],
                             'inputs':identities}))


def apt_readability(probe, *, executed, repo_root='/srv/rs9/apt',
                    keyring_path='/etc/apt/keyrings/rs9-nonproduction.gpg', arch='amd64'):
    """Credit only complete executed _apt target and ancestor observations."""
    if not executed or not isinstance(probe, dict) or probe.get('status') != 'probed':
        return 'not-run'
    user = probe.get('users', {}).get('_apt', {})
    if user.get('apt_user_present') is not True:
        return 'not-run'
    expected = {repo_root, keyring_path, *[f'{repo_root}/dists/resolute/{name}' for name in
                ('InRelease', 'Release', 'Release.gpg', *[f'main/binary-{arch}/Packages{s}'
                                                        for s in ('', '.xz', '.gz')])]}
    targets = user.get('targets', [])
    if len(targets) != len(expected) or {t.get('target') for t in targets} != expected:
        return 'not-run'
    for target in targets:
        path = Path(target['target'])
        ancestors = target.get('ancestors', [])
        rows = {row.get('path'): row for row in ancestors}
        required = {str(p) for p in (path, *path.parents)}
        if len(rows) != len(ancestors) or not required <= set(rows):
            return 'not-run'
        leaf = rows[str(path)]
        if leaf.get('readable') is not True or leaf.get('type') not in {'file', 'directory'}:
            return 'fail'
        for name in required - {str(path)}:
            row = rows[name]
            if row.get('type') != 'directory' or row.get('traversable') is not True:
                return 'fail'
        if leaf.get('type') == 'directory' and leaf.get('traversable') is not True:
            return 'fail'
    return 'pass'


def build_positive_control(*, family,image,platform,product,repository=None,keyring=None,
                           receipts=None,success=False,setup_sha256=None,dnf_probe=None):
    from rs9.release_core import digest
    control={'success':bool(success),'family':family,'image_sha256':digest(image.encode()),
             'platform':platform,'product':product,'setup_sha256':setup_sha256,'stages':{}}
    for stage,items in (receipts or {}).items():
        if not isinstance(items,list):items=[items]
        control['stages'][stage]=[{'exit_code':r.exit_code,'executed':r.executed,
            'stdout_sha256':r.stdout_sha256,'stderr_sha256':r.stderr_sha256} for r in items]
    if family == 'dnf':
        from rs9.dnf_diagnostics import valid_identity
        control['dnf_client'] = dnf_probe
        control['success'] = bool(success and valid_identity(dnf_probe))
    return control


def validate_positive_control(control, *, family,image,platform,product,dirs=None,keyring=None,setup_sha256=None,dnf_probe=None):
    from rs9.release_core import digest
    if not isinstance(control,Mapping) or control.get('success') is not True:
        return False,'positive-control-failed-or-missing'
    expected={'family':family,'image_sha256':digest(image.encode()),'platform':platform,'product':product,
              'setup_sha256':setup_sha256}
    if not setup_sha256 or any(control.get(k)!=v for k,v in expected.items()):
        return False,'positive-control-binding-mismatch'
    if family == 'dnf':
        from rs9.dnf_diagnostics import valid_identity
        actual = control.get('dnf_client')
        if (not valid_identity(actual) or actual['identity'].get('image_reference_sha256') != expected['image_sha256']
                or actual['identity'].get('platform') != platform
                or (dnf_probe is not None and (not valid_identity(dnf_probe)
                    or dnf_probe['identity_sha256'] != actual['identity_sha256']))):
            return False,'positive-control-binding-mismatch'
    stages=control.get('stages',{})
    if any(not isinstance(stages.get(s),list) or not stages[s] or
           any(not isinstance(r,dict) or r.get('exit_code')!=0 or r.get('executed') is not True
               for r in stages[s])
           for s in ('configure','refresh','install','query')):
        return False,'positive-control-stage-incomplete'
    return True,None


def qualify_tamper_rejection(
    kind: str,
    refresh_rcpt: CommandReceipt | None,
    install_rcpt: CommandReceipt | None,
    query_rcpt: CommandReceipt | None,
    family: str = "apt",
    *,
    configure_rcpt: CommandReceipt | None = None,
    signature_context: Mapping[str, Any] | None = None,
    dnf_context: Mapping[str, Any] | None = None,
) -> tuple[bool, str, str | None, dict[str, Any]]:
    """Causally qualify rejection for the tamper kind; wrong reasons cannot pass."""
    # 1. Did installation succeed? If installed, rejection failed.
    installed = False
    if query_rcpt is not None and query_rcpt.exit_code == 0:
        installed = True
    elif install_rcpt is not None and install_rcpt.exit_code == 0:
        installed = True

    if installed:
        return False, "COMMAND_SUCCESS", "tampered-content-accepted", {}

    if family == "dnf":
        from rs9.dnf_diagnostics import qualify_dnf
        return qualify_dnf(kind, refresh_rcpt, install_rcpt, query_rcpt,
                           configure=configure_rcpt, context=dnf_context)

    if configure_rcpt is not None and configure_rcpt.exit_code != 0:
        category = classify_rejection(configure_rcpt, stage="configure", family=family)
        sample = safe_sample((configure_rcpt.stderr_text if configure_rcpt else "") or (configure_rcpt.stdout_text if configure_rcpt else ""))
        return False, category, f"wrong-stage-failure:configure-failed-during-tamper:{category}", {
            "failed_stage": "configure", "sample": sample, "exit_code": configure_rcpt.exit_code,
        }

    allowed = set(QUALIFYING_TAMPER_CATEGORIES.get(kind, set()))
    if kind == "package" and family in {"pacman", "dnf"}:
        allowed.add("SIGNATURE_REJECTED")

    # For kind == "package", refresh must succeed because metadata is untampered.
    if kind == "package":
        if refresh_rcpt is None or refresh_rcpt.exit_code != 0:
            category = classify_rejection(refresh_rcpt, stage="refresh", family=family)
            sample = safe_sample(refresh_rcpt.stderr_text or refresh_rcpt.stdout_text) if refresh_rcpt else ""
            return False, category, f"wrong-stage-failure:refresh-failed-during-package-tamper:{category}", {
                "failed_stage": "refresh", "sample": sample, "exit_code": refresh_rcpt.exit_code if refresh_rcpt else None
            }
        category = classify_rejection(install_rcpt, stage="install", family=family)
        sample = safe_sample((install_rcpt.stderr_text if install_rcpt else "") or (install_rcpt.stdout_text if install_rcpt else ""))
        if category in allowed:
            return True, category, None, {"qualifying_stage": "install", "sample": sample}
        return False, category, f"wrong-tamper-rejection-reason:{category}", {"qualifying_stage": "install", "sample": sample}

    # For kind == "signature" or "wrongkey", refresh MUST fail.
    if kind in ("signature", "wrongkey"):
        if refresh_rcpt is not None and refresh_rcpt.exit_code == 0:
            return False, "COMMAND_SUCCESS", f"bypassed-{kind}-verification-on-refresh", {}
        context = signature_context or {}
        category = classify_rejection(refresh_rcpt, stage="refresh", family=family,
                                      source_uri=context.get("source_uri"),
                                      distribution=context.get("distribution"))
        sample = safe_sample((refresh_rcpt.stderr_text if refresh_rcpt else "") or (refresh_rcpt.stdout_text if refresh_rcpt else ""))
        if category in allowed:
            qual_diag: dict[str, Any] = {"qualifying_stage": "refresh", "sample": sample}
            if category == "SIGNED_ENVELOPE_INVALID":
                if (kind != "signature" or context.get("mutation_verified") is not True
                        or context.get("network_disconnected") is not True
                        or context.get("positive_control_valid") is not True
                        or any(r is None or r.executed is not True
                               for r in (configure_rcpt, refresh_rcpt, install_rcpt, query_rcpt))
                        or configure_rcpt.exit_code != 0
                        or install_rcpt.exit_code != 100 or query_rcpt.exit_code != 1):
                    return False, category, "invalid-envelope-proof-incomplete", qual_diag
                environment_categories = {"PERMISSION_DENIED", "COMMAND_NOT_FOUND", "NETWORK_UNAVAILABLE",
                                          "SOURCE_CONFIG_ERROR", "SANDBOX_UNREADABLE"}
                if any(classify_rejection(r, stage=stage, family=family) in environment_categories
                       for r, stage in ((install_rcpt, "install"), (query_rcpt, "query"))):
                    return False, category, "invalid-envelope-downstream-environment-failure", qual_diag
                qual_diag.update({
                    "distribution": "resolute",
                    "source_context": "file",
                    "target_envelope": "InRelease",
                })
            return True, category, None, qual_diag
        return False, category, f"wrong-tamper-rejection-reason:{category}", {"qualifying_stage": "refresh", "sample": sample}

    # For kind == "index", either refresh or install can reject with index corruption/hash mismatch.
    if kind == "index":
        target_rcpt = refresh_rcpt if (refresh_rcpt is not None and refresh_rcpt.exit_code != 0) else install_rcpt
        stage = "refresh" if target_rcpt is refresh_rcpt else "install"
        category = classify_rejection(target_rcpt, stage=stage, family=family)
        sample = safe_sample((target_rcpt.stderr_text if target_rcpt else "") or (target_rcpt.stdout_text if target_rcpt else ""))
        if stage == "refresh" and category in allowed:
            return True, category, None, {"qualifying_stage": stage, "sample": sample}
        return False, category, f"wrong-tamper-rejection-reason:{category}", {"qualifying_stage": stage, "sample": sample}

    return False, "UNCLASSIFIED_FAILURE", f"unsupported-tamper-kind:{kind}", {}
