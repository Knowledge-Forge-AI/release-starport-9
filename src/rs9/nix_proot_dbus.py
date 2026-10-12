"""One fixed D-Bus audit source shared by guest execution and source fixtures."""

from rs9.nix_proot_dbus_pin import DBUS_SESSION_CONFIG_SHA256

DBUS_AUDIT_SOURCE = 'DBUS_SESSION_CONFIG_SHA256 = ' + repr(DBUS_SESSION_CONFIG_SHA256) + '\n' + r'''
import hashlib, json, os, re, shutil, stat, xml.etree.ElementTree as ET

D_MAX_BYTES = 65536
D_MAX_FILES = 32
D_MAX_DEPTH = 4
D_MAX_ENTRIES = 128

def d_top(path):
    return '/'.join(path.split('/')[:4]) if path and path.startswith('/nix/store/') else None

def d_path(path, known):
    if not path: return None
    if not isinstance(path, str) or os.path.normpath(path) != path: return '<withheld-path>'
    if re.fullmatch(r'/nix/store/[0-9a-df-np-sv-z]{32}-[A-Za-z0-9+._?=-]+(?:/[A-Za-z0-9+._?=@~-]+)*', path): return path
    if path in ('/etc', '/etc/dbus-1', '/etc/dbus-1/session.conf'): return path
    if re.fullmatch(r'/etc/dbus-1/[A-Za-z0-9._-]{1,64}', path): return path
    return '<withheld-path>'

def d_is_standard_legacy(path):
    if not path: return False
    if path in ('/etc/dbus-1', '/etc/dbus-1/session.conf', '/etc/dbus-1/session-local.conf', '/etc/dbus-1/session.d'):
        return True
    if re.fullmatch(r'/etc/dbus-1(?:/[A-Za-z0-9._-]{1,64})+', path):
        return True
    return False

def d_check_no_symlinks(path):
    parts = path.split('/')
    curr = ''
    for part in parts[1:]:
        curr += '/' + part
        if os.path.islink(curr):
            return False
    return True

def d_entries(path):
    entries = []
    with os.scandir(path) as scan:
        for entry in scan:
            if len(entries) >= D_MAX_ENTRIES: raise ValueError('config-audit-limit')
            entries.append(entry.name)
    return sorted(entries)

def d_read(path, known, is_root=False):
    if is_root:
        if not path or not path.startswith('/nix/store/'):
            raise ValueError('config-outside-closure')
        if os.path.normpath(path) != path or '//' in path or path.endswith('/'):
            raise ValueError('config-not-normalized')
        if d_top(path) not in known:
            raise ValueError('config-outside-closure')
        if not d_check_no_symlinks(path):
            raise ValueError('config-symlinked-component')
    real = os.path.realpath(path)
    if is_root and real != path:
        raise ValueError('config-symlinked-component')
    if d_top(real) not in known:
        raise ValueError('symlink-outside-closure')
    fd = os.open(real, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError('config-not-regular')
        if info.st_size > D_MAX_BYTES:
            raise ValueError('config-oversize')
    except Exception:
        os.close(fd)
        raise
    with os.fdopen(fd, 'rb') as stream:
        raw = stream.read(D_MAX_BYTES + 1)
    if len(raw) > D_MAX_BYTES:
        raise ValueError('config-oversize')
    actual_sha = hashlib.sha256(raw).hexdigest()
    if is_root and actual_sha != DBUS_SESSION_CONFIG_SHA256:
        raise ValueError('dbus-session-config-mismatch')
    try:
        text = raw.decode('utf-8')
    except UnicodeError:
        raise ValueError('config-malformed')
    if '\x00' in text:
        raise ValueError('config-malformed')
    if re.search(r'<!\s*ENTITY\b', text, re.IGNORECASE):
        raise ValueError('config-entities-rejected')
    root = ET.fromstring(raw)
    if root.tag != 'busconfig':
        raise ValueError('config-malformed')
    return root, {
        'path': d_path(path, known),
        'real_path': d_path(real, known),
        'bytes': len(raw),
        'sha256': actual_sha,
    }

def d_include(elem, current_path, depth, known):
    value = (elem.text or '').strip()
    if not value: raise ValueError('config-malformed')
    if '\x00' in value or any(ord(c) < 32 for c in value): raise ValueError('config-malformed')
    target = os.path.normpath(value if value.startswith('/') else os.path.join(os.path.dirname(current_path), value))
    directory = elem.tag == 'includedir'
    present = os.path.lexists(target)
    real = os.path.realpath(target) if present else None
    skip_selinux = elem.get('if_selinux_enabled') == 'yes' and not os.path.isdir('/sys/fs/selinux')
    ignore = elem.get('ignore_missing') == 'yes'
    required = not directory and not ignore and not skip_selinux
    in_closure = bool(real and d_top(real) in known)
    rec = {
        'tag': elem.tag,
        'raw': d_path(value, known) if value.startswith('/') else (
            value if re.fullmatch(r'[A-Za-z0-9._/-]{1,128}', value) else '<withheld-path>'
        ),
        'resolved': d_path(target, known),
        'resolved_sha256': hashlib.sha256(target.encode()).hexdigest(),
        'ignore_missing': ignore,
        'required': required,
        'conditional_skipped': skip_selinux,
        'present': present,
        'real_path': d_path(real, known) if real else None,
        'in_closure': in_closure,
        'depth': depth,
    }
    error = None
    if d_top(target) not in known and not d_is_standard_legacy(target):
        error = 'symlink-outside-closure'
    elif not present and required:
        error = 'missing-required-include'
    elif present and d_top(real) not in known:
        error = 'symlink-outside-closure'
    elif present and directory and not os.path.isdir(target):
        error = 'includedir-not-directory'
    elif present and not directory and not os.path.exists(target):
        error = 'config-file-missing'
    next_paths = []
    if present and not skip_selinux and not error:
        if directory:
            next_paths = [os.path.join(target, n) for n in d_entries(target) if n.endswith('.conf')]
        else:
            next_paths = [target]
    return rec, next_paths, error

def d_element_facts(elem, known, listens, auth, services, policies):
    if elem.tag == 'listen':
        value = (elem.text or '').strip()
        listens.append('unix:tmpdir' if value.startswith('unix:tmpdir=') else
            'unix:path' if value.startswith('unix:path=') else
            'unix:dir' if value.startswith('unix:dir=') else 'other')
    if elem.tag == 'auth':
        value = (elem.text or '').strip()
        auth.append(value if value in ('EXTERNAL', 'DBUS_COOKIE_SHA1', 'ANONYMOUS') else 'other')
    if elem.tag == 'standard_session_servicedirs':
        services.append({'kind': 'standard-session'})
    if elem.tag == 'servicedir':
        value = (elem.text or '').strip()
        if len(services) >= D_MAX_ENTRIES: raise ValueError('config-audit-limit')
        services.append({'kind': 'explicit', 'path': d_path(value, known),
            'path_sha256': hashlib.sha256(value.encode()).hexdigest()})
    if elem.tag == 'policy':
        if len(policies) >= D_MAX_ENTRIES: raise ValueError('config-audit-limit')
        p_rec = {
            'context': elem.get('context') if elem.get('context') in ('default', 'mandatory') else 'other',
            'allow_count': len(elem.findall('allow')),
            'deny_count': len(elem.findall('deny')),
        }
        policies.append(p_rec)

def d_traverse(root_path, known):
    root_norm = os.path.normpath(root_path)
    root_real = os.path.realpath(root_path)
    queue = [(root_path, 0, {root_norm}, {root_real})]
    files = []
    includes = []
    listens = []
    auth = []
    services = []
    policies = []
    reason, failing = None, None
    current = root_path
    try:
        while queue:
            current, depth, ancestor_norms, ancestor_reals = queue.pop(0)
            if depth > D_MAX_DEPTH or len(files) >= D_MAX_FILES:
                raise ValueError('config-audit-limit')
            root_elem, record = d_read(current, known, is_root=(depth == 0))
            record['depth'] = depth
            files.append(record)
            for elem in root_elem.iter():
                d_element_facts(elem, known, listens, auth, services, policies)
                if elem.tag in ('include', 'includedir'):
                    if len(includes) >= D_MAX_ENTRIES: raise ValueError('config-audit-limit')
                    rec, targets, error = d_include(elem, current, depth, known)
                    includes.append(rec)
                    if error:
                        failing = rec['resolved']
                        raise ValueError(error)
                    for target in targets:
                        target_norm = os.path.normpath(target)
                        target_real = os.path.realpath(target)
                        if target_norm in ancestor_norms or target_real in ancestor_reals:
                            failing = d_path(target, known)
                            raise ValueError('config-cycle-detected')
                        queue.append((target, depth + 1, ancestor_norms | {target_norm}, ancestor_reals | {target_real}))
    except ET.ParseError:
        reason = 'config-malformed'
    except FileNotFoundError:
        reason = 'config-file-missing'
    except OSError:
        reason = 'config-unreadable'
    except ValueError as error:
        reason = str(error)
    if reason and failing is None:
        failing = d_path(current, known)
    rule_count = sum(p['allow_count'] + p['deny_count'] for p in policies)
    return {
        'status': 'fail' if reason else 'pass',
        'reason': reason,
        'failing_path': failing,
        'files': files,
        'includes': includes,
        'listen_classes': sorted(set(listens)),
        'auth_mechanisms': sorted(set(auth)),
        'audit_complete': not reason,
        'service_directories': services,
        'policies': policies,
        'policy_count': len(policies),
        'policy_rule_count': rule_count,
        'policy_element_count': len(policies) + rule_count,
        'limits': {'file_bytes': D_MAX_BYTES, 'depth': D_MAX_DEPTH, 'max_files': D_MAX_FILES, 'entries': D_MAX_ENTRIES},
    }

def d_legacy_state():
    result = {}
    reason, failing_path = None, None
    # Legacy /etc/dbus-1 directory AND session.conf lexists absent check
    legacy_dir = '/etc/dbus-1'
    legacy_conf = '/etc/dbus-1/session.conf'
    etc_ancestor = '/etc'

    etc_symlink = os.path.islink(etc_ancestor)
    dir_lexists = os.path.lexists(legacy_dir)
    dir_symlink = os.path.islink(legacy_dir)
    conf_lexists = os.path.lexists(legacy_conf)
    conf_symlink = os.path.islink(legacy_conf)
    legacy_absent = not (etc_symlink or dir_lexists or dir_symlink or conf_lexists or conf_symlink)

    result['legacy_absence'] = {
        'legacy_directory': legacy_dir,
        'legacy_session_conf': legacy_conf,
        'absent': legacy_absent,
        'etc_symlink': etc_symlink,
        'directory_lexists': dir_lexists,
        'directory_symlink': dir_symlink,
        'session_conf_lexists': conf_lexists,
        'session_conf_symlink': conf_symlink,
    }
    result['singleton_directory'] = {
        'path': legacy_dir,
        'present': dir_lexists,
        'absent': not (dir_lexists or conf_lexists),
        'is_singleton': False,
        'entries': [],
        'entry_count': 0,
    }

    if not reason and not legacy_absent:
        if etc_symlink:
            reason = 'legacy-ancestor-symlink'
            failing_path = etc_ancestor
        elif dir_symlink:
            reason = 'legacy-dbus-symlink'
            failing_path = legacy_dir
        elif conf_symlink:
            reason = 'legacy-session-config-symlink'
            failing_path = legacy_conf
        elif conf_lexists:
            reason = 'legacy-session-config-present'
            failing_path = legacy_conf
        elif dir_lexists:
            reason = 'legacy-dbus-directory-present' if os.path.isdir(legacy_dir) else 'legacy-dbus-present'
            failing_path = legacy_dir

    return result, reason, failing_path

def audit_dbus_config(spec):
    if (type(spec) is not dict or type(spec.get('closure')) is not list
        or len(spec['closure']) > 4096
        or any(type(p) is not str or not re.fullmatch(r'/nix/store/[0-9a-df-np-sv-z]{32}-[A-Za-z0-9+._?=-]+', p)
               for p in spec['closure'])
        or any(type(spec.get(k)) is not str for k in ('dbus_daemon', 'dbus_session_config'))):
        return {'status':'fail','reason':'config-input-invalid','failing_path':None,'audit_complete':False,'files':[],'includes':[]}
    known = set(spec.get('closure', []))
    expected = spec.get('dbus_daemon')
    config = spec.get('dbus_session_config')
    expected_sha = DBUS_SESSION_CONFIG_SHA256

    resolved = shutil.which('dbus-daemon')
    real = os.path.realpath(resolved) if resolved else None
    present = bool(resolved and os.path.isfile(resolved))
    same = bool(present and expected and real == os.path.realpath(expected))
    result = {
        'daemon_identity': {
            'expected': d_path(expected, known),
            'resolved': d_path(resolved, known),
            'real_path': d_path(real, known),
            'present': present,
            'in_closure': bool(real and d_top(real) in known),
            'same_real_file': same,
        }
    }
    reason = (
        'dbus-daemon-missing' if not present else
        'dbus-daemon-mismatch' if not same else
        'daemon-outside-closure' if d_top(real) not in known else None
    )
    failing_path = resolved if reason else None

    legacy_state, legacy_reason, legacy_path = d_legacy_state()
    result.update(legacy_state)
    if not reason:
        reason, failing_path = legacy_reason, legacy_path

    conf_present = bool(config and os.path.exists(config))
    conf_real = os.path.realpath(config) if conf_present else None
    result['session_config_identity'] = {
        'guest_path': d_path(config, known),
        'store_path': d_path(config, known),
        'expected_store_path': d_path(config, known),
        'real_path': d_path(conf_real, known) if conf_real else None,
        'present': conf_present,
        'in_closure': bool(conf_real and d_top(conf_real) in known),
        'config_mode': 'explicit-store-main',
        'pinned_sha256': expected_sha,
    }

    if not reason:
        if not config:
            reason = 'dbus-session-config-missing'
            failing_path = config
        elif not config.startswith('/nix/store/'):
            reason = 'config-outside-closure'
            failing_path = config
        elif os.path.normpath(config) != config or '//' in config or config.endswith('/'):
            reason = 'config-not-normalized'
            failing_path = config
        elif d_top(config) not in known:
            reason = 'config-outside-closure'
            failing_path = config
        elif config != d_top(expected) + '/share/dbus-1/session.conf':
            reason = 'dbus-session-config-mismatch'
            failing_path = config
        elif not d_check_no_symlinks(config):
            reason = 'config-symlinked-component'
            failing_path = config
        elif not conf_present:
            reason = 'dbus-session-config-missing'
            failing_path = config

    if reason:
        return {
            **result,
            'status': 'fail',
            'reason': reason,
            'failing_path': d_path(failing_path, known) if failing_path else None,
            'audit_complete': False,
            'files': [],
            'includes': [],
        }

    return {**result, **d_traverse(config, known)}
'''


def audit_dbus_config(spec):
    """Execute the exact fixed guest audit against an explicit fixture filesystem."""
    namespace = {}
    exec(compile(DBUS_AUDIT_SOURCE, "rs9-dbus-audit", "exec"), namespace)
    return namespace["audit_dbus_config"](spec)
