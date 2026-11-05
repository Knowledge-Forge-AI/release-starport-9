"""Guest scripts: ported installer (+ guest-account stage) and the drop-only preamble.

The installer body is the qualified ``INSTALL_SCRIPT`` with the namespace
transforms recorded in ``origin.py``. The only behavioral addition is the
``account`` stage, placed after every package/hook/file-capability validation
and before ``done`` (hence before the sole SDK commit).

The preamble performs no privilege transition. It only verifies, using bash
builtins reading its own ``/proc/self/status``, that real/effective/saved/fs
UID and GID equal the verified runner values, supplementary groups are empty
or only the primary GID, inheritable/permitted/effective/ambient capabilities
are zero, the bounding set is the closed role value and NoNewPrivs is 1, and
only then ``exec``s the requested argv.
"""
from __future__ import annotations

import re

from rs9._archarm_support.pins import ROOT_NAMES
from rs9._archarm_support.refusal import SdkRefusal, require
from rs9._archarm_support.rootfs import FINGERPRINT

INPUTS_TARGET = "/run/rs9-inputs"
GUEST_KEYRING = "/var/lib/rs9-archarm-sdk-gnupg"
GUEST_ACCOUNT = "rs9builder"
GUEST_HOME = "/tmp/home"
MAX_ID = 2147483647
_PLACEHOLDER_RE = re.compile(r"@[A-Z]+@")

# Public pacman configuration: no repositories, signatures required.
PACMAN_CONF = f"""[options]
RootDir = /
DBPath = /var/lib/pacman/
CacheDir = /var/cache/pacman/pkg/
LogFile = /var/log/pacman.log
GPGDir = {GUEST_KEYRING}/
HookDir = /etc/pacman.d/hooks/
Architecture = aarch64
SigLevel = Required DatabaseRequired
LocalFileSigLevel = Required
RemoteFileSigLevel = Required
"""

INSTALL_STAGES = ("inputs", "keyring", "pacman", "delta", "hooks", "ptpcaps", "account", "done")
INSTALL_FAILURES = ("identity", "inputs", "keyring", "pacman_query", "chroot", "pacman_exit",
                    "pacman_error", "base_changed", "delta", "hooks_schemas",
                    "hooks_pixbuf", "hooks_immodules", "hooks_mime", "hooks_icons",
                    "hooks_fonts", "ptpcaps", "account_uid_collision", "account_gid_collision",
                    "account_name_collision", "account_create", "account_verify")
INSTALL_PREFIX = "RSI"

_INSTALL_TEMPLATE = r'''set -euo pipefail
exec 3>&1 >/dev/null 2>&1
umask 022
export LANG=C LC_ALL=C PATH=/usr/bin:/bin HOME=/root
I=@INPUTS@
C=@INPUTS@/pacman.conf
K=@INPUTS@/key/archlinuxarm-builder-public.gpg
G=@KEYRING@
T=/var/tmp/rs9-archarm-sdk-install
FPR=@FPR@
U=@UID@
V=@GID@
N=@ACCOUNT@
H=@HOME@
mark() { printf 'RSI %s\n' "$1" >&3; }
fail() { printf 'RSI fail %s\n' "$1" >&3; exit 1; }
test "$(id -u):$(id -g)" = 0:0 || fail identity
test "$(uname -m)" = aarch64 || fail identity
test ! -e "$G" || fail inputs
test ! -e "$T" || fail inputs
test -f "$C" || fail inputs
test -f "$K" || fail inputs
set -- "$I"/pkg/[0-9][0-9][0-9].pkg.tar.xz
test "$#" -eq @COUNT@ || fail inputs
for p in "$@"; do
  test -f "$p" || fail inputs
  test -f "$p.sig" || fail inputs
done
test "$(ls -A "$I/pkg" | wc -l)" -eq @ENTRIES@ || fail inputs
mark inputs
mkdir -m 0700 "$G" "$T"
: > "$G/common.conf"
gpg --no-options --no-autostart --batch --homedir "$G" --import "$K" || fail keyring
printf '%s:6:\n' "$FPR" | gpg --no-options --no-autostart --batch --homedir "$G" --import-ownertrust || fail keyring
gpg --no-options --no-autostart --batch --homedir "$G" --check-trustdb || fail keyring
gpg --no-options --no-autostart --batch --homedir "$G" --with-colons --list-keys > "$T/keys" || fail keyring
test "$(grep -c '^pub:' "$T/keys")" -eq 1 || fail keyring
test "$(awk -F: '$1 == "pub" { print $2 }' "$T/keys")" = u || fail keyring
test "$(awk -F: '$1 == "fpr" { print $10; exit }' "$T/keys")" = "$FPR" || fail keyring
mark keyring
pacman --config "$C" -Q | LC_ALL=C sort > "$T/before" || fail pacman_query
rc=0
pacman --config "$C" -U --noconfirm --noprogressbar "$@" > "$T/pacman.out" 2>&1 || rc=$?
if grep -q 'could not change the root directory' "$T/pacman.out"; then fail chroot; fi
test "$rc" -eq 0 || fail pacman_exit
if grep -Eq '^error:|command failed to execute correctly' "$T/pacman.out"; then fail pacman_error; fi
mark pacman
pacman --config "$C" -Q | LC_ALL=C sort > "$T/after" || fail pacman_query
test -z "$(LC_ALL=C comm -23 "$T/before" "$T/after")" || fail base_changed
test "$(LC_ALL=C comm -13 "$T/before" "$T/after" | wc -l)" -eq @COUNT@ || fail delta
pacman --config "$C" -Q @ROOTS@ || fail delta
mark delta
test -s /usr/share/glib-2.0/schemas/gschemas.compiled || fail hooks_schemas
if compgen -G '/usr/lib/gdk-pixbuf-2.0/2.10.0/loaders/*.so' >/dev/null; then
  test -s /usr/lib/gdk-pixbuf-2.0/2.10.0/loaders.cache || fail hooks_pixbuf
else
  test ! -e /usr/lib/gdk-pixbuf-2.0/2.10.0/loaders.cache || fail hooks_pixbuf
fi
test -s /usr/lib/gtk-3.0/3.0.0/immodules.cache || fail hooks_immodules
test -s /usr/share/mime/mime.cache || fail hooks_mime
test -s /usr/share/icons/hicolor/icon-theme.cache || fail hooks_icons
test -n "$(ls -A /var/cache/fontconfig)" || fail hooks_fonts
mark hooks
case "$(getcap /usr/lib/gstreamer-1.0/gst-ptp-helper)" in
  *' cap_net_bind_service,cap_net_admin=ep') ;;
  *) fail ptpcaps ;;
esac
mark ptpcaps
has_id() { awk -F: -v want="$2" '$3 == want { found = 1 } END { exit found ? 0 : 1 }' "$1"; }
has_name() { awk -F: -v want="$2" '$1 == want { found = 1 } END { exit found ? 0 : 1 }' "$1"; }
test -f /etc/passwd || fail account_verify
test -f /etc/group || fail account_verify
test -f /etc/shadow || fail account_verify
if has_id /etc/passwd "$U"; then fail account_uid_collision; fi
if has_id /etc/group "$V"; then fail account_gid_collision; fi
for f in /etc/passwd /etc/group /etc/shadow /etc/gshadow; do
  if test -e "$f" && has_name "$f" "$N"; then fail account_name_collision; fi
done
test ! -e "$H" || fail account_create
groupadd --gid "$V" "$N" || fail account_create
useradd --no-log-init --no-create-home --no-user-group --uid "$U" --gid "$V" --home-dir "$H" "$N" || fail account_create
test "$(awk -F: -v n="$N" '$1 == n { print $3 ":" $4 ":" $6 }' /etc/passwd)" = "$U:$V:$H" || fail account_verify
test "$(awk -F: -v n="$N" '$1 == n { print $3 }' /etc/group)" = "$V" || fail account_verify
test -z "$(awk -F: -v n="$N" '$1 == n { print $4 }' /etc/group)" || fail account_verify
test "$(awk -F: -v want="$U" '$3 == want' /etc/passwd | wc -l)" -eq 1 || fail account_verify
test "$(awk -F: -v want="$V" '$3 == want' /etc/group | wc -l)" -eq 1 || fail account_verify
case "$(awk -F: -v n="$N" '$1 == n { print $2 }' /etc/shadow)" in
  '!'*) ;;
  *) fail account_verify ;;
esac
test ! -e "$H" || fail account_verify
mark account
rm -f -- "$T/keys" "$T/before" "$T/after" "$T/pacman.out"
rmdir -- "$T"
mark done
'''


def valid_id(value):
    return type(value) is int and 1 <= value <= MAX_ID


def render_install_script(*, count, uid, gid):
    require(type(count) is int and 0 < count <= 256, "INSTALL_SCRIPT")
    require(valid_id(uid) and valid_id(gid), "RUNNER_IDENTITY")
    text = _INSTALL_TEMPLATE
    for key, value in (("@INPUTS@", INPUTS_TARGET), ("@KEYRING@", GUEST_KEYRING),
                       ("@FPR@", FINGERPRINT), ("@UID@", str(uid)), ("@GID@", str(gid)),
                       ("@ACCOUNT@", GUEST_ACCOUNT), ("@HOME@", GUEST_HOME),
                       ("@COUNT@", str(count)), ("@ENTRIES@", str(2 * count)),
                       ("@ROOTS@", " ".join(ROOT_NAMES))):
        text = text.replace(key, value)
    require(_PLACEHOLDER_RE.search(text) is None, "INSTALL_SCRIPT")
    return text


def installer_cmd(*, count, uid, gid):
    return ("/usr/bin/bash", "-c", render_install_script(count=count, uid=uid, gid=gid))


# ----------------------------------------------------------------------- preamble

PREAMBLE_OK = b"RS9-ARCHARM-PREAMBLE-OK\n"
PREAMBLE_EXIT = 213
PREAMBLE_ARG0 = "rs9-preamble"
ZERO_CAPS = "0000000000000000"
# CHOWN(0) DAC_OVERRIDE(1) FOWNER(3) FSETID(4) SETGID(6) SETUID(7) SETFCAP(31)
SEVEN_CAPS_MASK = "%016x" % sum(1 << bit for bit in (0, 1, 3, 4, 6, 7, 31))

_PREAMBLE_TEMPLATE = r'''set -u
fail() { exit @EXIT@; }
test "$#" -gt 0 || fail
uid= gid= grp=unset ci= cp= ce= cb= ca= nnp=
while IFS=$'\t' read -r key value; do
  case "$key" in
    Uid:) uid=$value ;;
    Gid:) gid=$value ;;
    Groups:) grp=$value ;;
    CapInh:) ci=$value ;;
    CapPrm:) cp=$value ;;
    CapEff:) ce=$value ;;
    CapBnd:) cb=$value ;;
    CapAmb:) ca=$value ;;
    NoNewPrivs:) nnp=$value ;;
  esac
done < /proc/self/status
test "$uid" = "$(printf '@UID@\t@UID@\t@UID@\t@UID@')" || fail
test "$gid" = "$(printf '@GID@\t@GID@\t@GID@\t@GID@')" || fail
grp=${grp% }
case "$grp" in
  ''|@GID@) ;;
  *) fail ;;
esac
for v in "$ci" "$cp" "$ce" "$ca"; do
  test "$v" = @ZERO@ || fail
done
test "$cb" = @BOUNDING@ || fail
test "$nnp" = 1 || fail
umask @UMASK@
export HOME=@HOME@ TMPDIR=/tmp
if test -e "$HOME" || test -L "$HOME"; then
  test -d "$HOME" && ! test -L "$HOME" && test -O "$HOME" || fail
else
  mkdir -m 0700 -- "$HOME" || fail
fi
@OK@
exec "$@"
'''


def render_preamble(*, uid, gid, bounding, umask, attest):
    require(valid_id(uid) and valid_id(gid), "RUNNER_IDENTITY")
    require(bounding in (ZERO_CAPS, SEVEN_CAPS_MASK) and umask in ("022", "077"), "PREAMBLE")
    text = _PREAMBLE_TEMPLATE
    ok = "printf 'RS9-ARCHARM-PREAMBLE-OK\\n' >&2" if attest else ":"
    for key, value in (("@EXIT@", str(PREAMBLE_EXIT)), ("@UID@", str(uid)), ("@GID@", str(gid)),
                       ("@ZERO@", ZERO_CAPS), ("@BOUNDING@", bounding), ("@UMASK@", umask),
                       ("@HOME@", GUEST_HOME), ("@OK@", ok)):
        text = text.replace(key, value)
    require(_PLACEHOLDER_RE.search(text) is None, "PREAMBLE")
    return text


def preamble_argv(argv, **kwargs):
    return ["/usr/bin/bash", "-c", render_preamble(**kwargs), PREAMBLE_ARG0, *argv]


def strip_attestation(exit_code, stderr):
    """Return stderr without the positive token; a missing token means the preamble refused."""
    if isinstance(stderr, bytes) and stderr.startswith(PREAMBLE_OK):
        return stderr[len(PREAMBLE_OK):]
    raise SdkRefusal("PREAMBLE_IDENTITY")


# ----------------------------------------------------------------------- tokens

def parse_tokens(output, prefix, stages, failures, label):
    """Accept only fixed in-order stage tokens and at most one closed failure token."""
    try:
        text = output.decode("ascii", "strict")
    except UnicodeDecodeError:
        raise SdkRefusal(label) from None
    require(text == "" or text.endswith("\n"), label)
    lines = text.splitlines()
    require(len(lines) <= len(stages) + 1, label)
    done, failure = [], None
    for line in lines:
        parts = line.split(" ")
        require(failure is None and len(parts) in (2, 3) and parts[0] == prefix, label)
        if len(parts) == 3:
            require(parts[1] == "fail" and parts[2] in failures, label)
            failure = parts[2]
        else:
            require(len(done) < len(stages) and parts[1] == stages[len(done)], label)
            done.append(parts[1])
    return done, failure
