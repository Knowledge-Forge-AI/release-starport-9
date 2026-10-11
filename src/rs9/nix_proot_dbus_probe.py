"""Bounded D-Bus controls; observations never qualify the application."""
import base64
import hashlib
import json

from rs9.nix_proot_wait import _unique


# Fixed project source, not released payload code. Only its own nofork child
# receives signals. Address bytes stay local and are never emitted.
MINIMAL_CONFIG = '''<busconfig>
  <type>session</type>
  <listen>unix:tmpdir=/tmp</listen>
  <auth>EXTERNAL</auth>
  <policy context="default"><deny send_destination="*"/></policy>
</busconfig>
'''
# This deny-only control has no application clients or include files. It does
# not replace the pinned guest config, test its full semantics, or grant access.
DAEMON_PROBE_SOURCE = 'MINIMAL_CONFIG='+repr(MINIMAL_CONFIG)+'\n'+r'''
import base64,hashlib,json,os,signal,subprocess,sys,tempfile,time
command=json.loads(sys.argv[1])
def identity(pid):
    try:
        with open('/proc/%s/stat'%pid) as stream:return int(stream.read().rsplit(')',1)[1].split()[19])
    except (OSError,ValueError,IndexError):return None
def reap(child,seconds):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        try:pid,status=os.waitpid(child.pid,os.WNOHANG)
        except InterruptedError:continue
        if pid:
            child.returncode=os.waitstatus_to_exitcode(status)
            return status
        time.sleep(.05)
    return None
record={'schema':'rs9.dbus-daemon-control.v1','spawn_errno':None,
        'child_pid':None,'child_starttime':None,'address_class':'none',
        'timed_out':False,'output_limit':False,'wait_status':None,
        'raw_returncode':None,'reaped':False,'cleanup_errno':None,
        'stdout_bytes':0,'stderr_bytes':0,'stderr_truncated':False,
        'stderr_sha256':None,'stderr_base64':''}
with tempfile.TemporaryDirectory() as config_dir,tempfile.TemporaryFile() as out,tempfile.TemporaryFile() as err:
    if len(sys.argv)>2:
        if len(sys.argv)!=3 or sys.argv[2]!='minimal-no-includes':raise ValueError('control-mode-invalid')
        config_path=os.path.join(config_dir,'session.conf')
        with open(config_path,'xb') as stream:stream.write(MINIMAL_CONFIG.encode())
        command=[*command,'--config-file='+config_path]
    child=None
    try:
        child=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=out,stderr=err)
        record.update(child_pid=child.pid,child_starttime=identity(child.pid))
        deadline=time.monotonic()+5
        while True:
            sizes=[os.fstat(s.fileno()).st_size for s in (out,err)]
            if max(sizes)>4096:record['output_limit']=True;break
            address=os.pread(out.fileno(),4097,0)
            if b'\n' in address:
                record['address_class']='unix' if address.startswith(b'unix:') and address.count(b'\n')==1 else 'unexpected'
                break
            status=reap(child,.05)
            if status is not None:record['wait_status']=status;break
            if time.monotonic()>=deadline:record['timed_out']=True;break
    except OSError as error:
        record['spawn_errno' if child is None else 'cleanup_errno']=error.errno
    finally:
        if child is not None and child.returncode is None:
            # Popen.send_signal polls/reaps and would erase raw waitpid status.
            # This unreaped owned child cannot have its PID reused here.
            try:os.kill(child.pid,signal.SIGTERM)
            except ProcessLookupError:pass
            except OSError as error:record['cleanup_errno']=error.errno
            record['wait_status']=reap(child,1)
            if record['wait_status'] is None:
                try:os.kill(child.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                except OSError as error:record['cleanup_errno']=error.errno
                record['wait_status']=reap(child,1)
        record['reaped']=bool(child is not None and child.returncode is not None)
        record['raw_returncode']=child.returncode if child is not None else None
    record['stdout_bytes']=os.fstat(out.fileno()).st_size
    size=os.fstat(err.fileno()).st_size
    raw=os.pread(err.fileno(),4096,0)
    record.update(stderr_bytes=size,stderr_truncated=size>len(raw),
                  stderr_sha256=hashlib.sha256(raw).hexdigest(),
                  stderr_base64=base64.b64encode(raw).decode())
print(json.dumps(record,sort_keys=True))
'''

SOCKET_PROBE_SOURCE = r'''
import json,os,secrets,socket,stat
info=os.stat('/tmp')
result={'schema':'rs9.dbus-socket-control.v1','tmp_mode':stat.S_IMODE(info.st_mode),
        'tmp_owner_matches':info.st_uid==os.getuid(),'tmp_writable':os.access('/tmp',os.W_OK)}
for kind in ('path','abstract'):
    address='/tmp/rs9-dbus-'+secrets.token_hex(8)
    if kind=='abstract':address='\0'+address
    error=None;bound=False
    with socket.socket(socket.AF_UNIX) as sock:
        try:sock.bind(address);bound=True
        except OSError as exc:error=exc.errno
    if bound and kind=='path':os.unlink(address)
    result[kind]={'bound':bound,'errno':error}
print(json.dumps(result,sort_keys=True))
'''

SESSION_PROBE_SOURCE = r'''
import json,os
def identity(pid):
    try:
        with open('/proc/%s/stat'%pid) as stream:
            fields=stream.read(4096).rsplit(')',1)[1].split()
        return int(fields[1]),int(fields[19])
    except (OSError,ValueError,IndexError):return None
parent=os.getppid();children=[];complete=True;count=0
with os.scandir('/proc') as entries:
    for entry in entries:
        if not entry.name.isdigit():continue
        count+=1
        if count>4096:complete=False;break
        state=identity(entry.name)
        if state is None:complete=False;continue
        if state[0]!=parent:continue
        try:
            with open(entry.path+'/comm') as stream:name=stream.read(64).strip()
        except OSError:complete=False;continue
        if name=='dbus-daemon':children.append({'pid':int(entry.name),'starttime':state[1]})
        if len(children)>16:complete=False;children=children[:16];break
print(json.dumps({'schema':'rs9.dbus-session-control.v1','complete':complete,'daemons':children}))
'''


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def config_include_structure(audit):
    """Report observed root self-includes without guessing daemon acceptance."""
    files = audit.get('files', [])
    includes = audit.get('includes', [])
    if not audit.get('audit_complete') or not files:
        return {'status': 'unobserved', 'qualification_authority': False}
    root = files[0].get('real_path')
    edges = [row for row in includes if row.get('present') and not row.get('conditional_skipped')
             and row.get('depth') == 0 and row.get('real_path') == root]
    return {'status': 'observed', 'root_self_include_observed': bool(edges), 'self_include_count': len(edges),
            'native_daemon_acceptance': 'unproven', 'qualification_authority': False}


def _json_control(run):
    if run.error or run.returncode != 0 or len(run.stdout) > 8192:
        return None
    try:
        doc = json.loads(run.stdout, object_pairs_hook=_unique)
        return doc if type(doc) is dict else None
    except (ValueError, UnicodeError, RecursionError):
        return None


def daemon_control(run, *, stage, argv_sha256, host_binds=(), closure=()):
    """Validate the entire frame before retaining any child-provided fields."""
    from rs9.nix_proot_stderr import stream_diagnostic
    doc = _json_control(run)
    keys = {'schema', 'spawn_errno', 'child_pid', 'child_starttime', 'address_class',
            'timed_out', 'output_limit', 'wait_status', 'raw_returncode', 'reaped',
            'cleanup_errno', 'stdout_bytes', 'stderr_bytes', 'stderr_truncated',
            'stderr_sha256', 'stderr_base64'}
    try:
        if doc is None or set(doc) != keys or doc['schema'] != 'rs9.dbus-daemon-control.v1':
            raise ValueError
        for key in ('timed_out', 'output_limit', 'reaped', 'stderr_truncated'):
            if type(doc[key]) is not bool:
                raise ValueError
        for key in ('spawn_errno', 'cleanup_errno', 'child_pid', 'child_starttime', 'wait_status'):
            if doc[key] is not None and (type(doc[key]) is not int or not 0 <= doc[key] < 2**63):
                raise ValueError
        for key in ('stdout_bytes', 'stderr_bytes'):
            if type(doc[key]) is not int or not 0 <= doc[key] < 2**63:
                raise ValueError
        rc = doc['raw_returncode']
        if rc is not None and (type(rc) is not int or not -64 <= rc <= 255):
            raise ValueError
        if doc['address_class'] not in ('none', 'unix', 'unexpected'):
            raise ValueError
        if doc['spawn_errno'] is not None and (doc['child_pid'] is not None or doc['reaped']
                                               or doc['address_class'] != 'none'):
            raise ValueError
        if doc['child_pid'] is None and (doc['child_starttime'] is not None or doc['reaped']):
            raise ValueError
        if doc['reaped'] != (rc is not None):
            raise ValueError
        raw = base64.b64decode(doc['stderr_base64'], validate=True)
        if len(raw) > 4096 or _digest(raw) != doc['stderr_sha256']:
            raise ValueError
        if doc['stderr_bytes'] != len(raw) and not (doc['stderr_truncated'] and doc['stderr_bytes'] > len(raw)):
            raise ValueError
        if doc['stderr_truncated'] and doc['stderr_bytes'] <= len(raw):
            raise ValueError
        # Reaping and raw status must agree, including genuine signal death.
        import os
        status = doc['wait_status']
        if doc['reaped'] != (status is not None):
            raise ValueError
        if status is not None and (not (os.WIFEXITED(status) or os.WIFSIGNALED(status))
                                   or os.waitstatus_to_exitcode(status) != rc):
            raise ValueError
    except (ValueError, TypeError, KeyError, OverflowError):
        return {'status': 'unobserved', 'reason': 'daemon-control-frame-invalid'}
    result = {k: v for k, v in doc.items() if k != 'stderr_base64'}
    error = 'timeout' if doc['timed_out'] else 'output-limit' if (
        doc['output_limit'] or doc['stderr_truncated'] or doc['stdout_bytes'] > 4096) else None
    result['stderr_diagnostic'] = stream_diagnostic(raw, stage=stage, argv_sha256=argv_sha256,
        returncode=rc, run_error=error, truncated=doc['stderr_truncated'], host_binds=host_binds, closure=closure)
    result['status'] = ('observed' if doc['address_class'] == 'unix' and doc['reaped']
                        and not error and doc['cleanup_errno'] is None else 'fail')
    return result


def socket_control(run):
    doc = _json_control(run)
    if (doc is None or set(doc) != {'schema', 'tmp_mode', 'tmp_owner_matches', 'tmp_writable', 'path', 'abstract'}
            or doc['schema'] != 'rs9.dbus-socket-control.v1'):
        return {'status': 'unobserved', 'reason': 'socket-control-frame-invalid'}
    if (type(doc['tmp_mode']) is not int or not 0 <= doc['tmp_mode'] <= 0o7777
            or any(type(doc[k]) is not bool for k in ('tmp_owner_matches', 'tmp_writable'))):
        return {'status': 'unobserved', 'reason': 'socket-control-frame-invalid'}
    for kind in ('path', 'abstract'):
        row = doc[kind]
        if (type(row) is not dict or set(row) != {'bound', 'errno'} or type(row['bound']) is not bool
                or (row['errno'] is not None and (type(row['errno']) is not int or not 1 <= row['errno'] <= 4096))
                or row['bound'] != (row['errno'] is None)):
            return {'status': 'unobserved', 'reason': 'socket-control-frame-invalid'}
    return {**doc, 'status': 'observed'}


def observed_survivors(rt, identities):
    """Read only, PID plus kernel start time; frame grants no kill authority."""
    if not identities or any(type(row.get('pid')) is not int or type(row.get('starttime')) is not int
                             for row in identities):
        return {'status': 'unobserved', 'reason': 'daemon-identity-unobserved', 'kill_authority': False}
    survivors = []
    for _ in range(10):
        survivors = []
        for row in identities:
            try:
                fields = (rt.proc_root / str(row['pid']) / 'stat').read_text().rsplit(')', 1)[1].split()
                if int(fields[19]) == row['starttime']:
                    survivors.append(row)
            except FileNotFoundError:
                pass
            except (OSError, ValueError, IndexError):
                return {'status': 'unobserved', 'reason': 'daemon-lifecycle-unreadable', 'kill_authority': False}
        if not survivors:
            break
        rt.sleep(.1)
    return {'status': 'observed', 'survivors': len(survivors), 'kill_authority': False}


def session_control(rt, run):
    doc = _json_control(run)
    if (doc is None or set(doc) != {'schema', 'complete', 'daemons'}
            or doc['schema'] != 'rs9.dbus-session-control.v1' or type(doc['complete']) is not bool
            or type(doc['daemons']) is not list or len(doc['daemons']) > 16):
        return {'status': 'unobserved', 'reason': 'session-control-frame-invalid'}
    for row in doc['daemons']:
        if (type(row) is not dict or set(row) != {'pid', 'starttime'}
                or any(type(row[k]) is not int or not 1 <= row[k] < 2**63 for k in row)):
            return {'status': 'unobserved', 'reason': 'session-control-frame-invalid'}
    observed = doc['complete'] and bool(doc['daemons'])
    return {**doc, 'status': 'observed' if observed else 'unobserved',
            **({'reason': 'daemon-identity-unobserved' if not doc['daemons'] else 'session-scan-incomplete'}
               if not observed else {}),
            'identity_basis': 'observed-proc-comm-only', 'absence_proven': False,
            'lifecycle': observed_survivors(rt, doc['daemons'])}


def decomposition_cause(rows, original_failed):
    """Name only the failing control, not an inferred native root cause."""
    by = {row['stage']: row for row in rows}
    if any(row.get('status') == 'unobserved' for row in rows):
        return 'control-evidence-incomplete'
    if by['daemon-version']['status'] != 'pass':
        return 'daemon-version-control-failed'
    if by['run-session-version']['status'] != 'pass':
        return 'run-session-version-control-failed'
    sockets = by['socket-controls']['control']
    if sockets['status'] != 'observed':
        return 'socket-control-unobserved'
    if not sockets['path']['bound']:
        return 'path-socket-bind-failed'
    default, explicit = (by[k]['control']['status'] == 'observed' for k in ('daemon-default', 'daemon-explicit'))
    if not default and not explicit:
        return 'default-and-explicit-daemon-controls-failed'
    if not explicit:
        return 'explicit-config-daemon-control-failed'
    if not default:
        return 'compiled-config-path-control-divergent'
    tmp, root = (by[k]['status'] == 'pass' for k in ('session-tmp', 'session-root'))
    if not tmp and root:
        return 'guest-cwd-dependent'
    if not tmp:
        return 'run-session-control-failed'
    if not root or by['session-explicit']['status'] != 'pass':
        return 'session-control-divergent'
    return 'target-or-probe-failed' if original_failed else 'not-reproduced-in-controls'


def run_dbus_decomposition(rt, original_failed, dbus_state):
    """Run after the original five stages; never change their argv or first failure."""
    from rs9.nix_proot_launch import classify_failure, redact_text
    from rs9.nix_proot_stderr import stream_diagnostic
    facts = rt.facts
    python = [facts['python'], '-I', '-S', '-B', '-c']
    daemon = [facts['dbus_daemon'], '--nofork', '--nopidfile', '--print-address=1']
    commands = [
        ('daemon-version', [facts['dbus_daemon'], '--version'], '/tmp'),
        ('run-session-version', [facts['dbus_run_session'], '--version'], '/tmp'),
        ('socket-controls', [*python, SOCKET_PROBE_SOURCE], '/tmp'),
        ('daemon-default', [*python, DAEMON_PROBE_SOURCE, json.dumps([*daemon, '--session'])], '/tmp'),
        ('daemon-explicit', [*python, DAEMON_PROBE_SOURCE, json.dumps([*daemon, '--config-file=/etc/dbus-1/session.conf'])], '/tmp'),
        ('daemon-minimal', [*python, DAEMON_PROBE_SOURCE, json.dumps(daemon), 'minimal-no-includes'], '/tmp'),
        ('session-tmp', [facts['dbus_run_session'], '--', *python, SESSION_PROBE_SOURCE], '/tmp'),
        ('session-root', [facts['dbus_run_session'], '--', *python, SESSION_PROBE_SOURCE], '/'),
        ('session-explicit', [facts['dbus_run_session'], '--dbus-daemon=' + facts['dbus_daemon'],
                              '--config-file=/etc/dbus-1/session.conf', '--', *python, dbus_state], '/tmp'),
    ]
    host_binds = tuple(str(p) for p in (rt.layout.tmp_dir, rt.layout.cache_dir, rt.layout.loader_tmp,
                                       rt.layout.etc_dir, *rt.layout.workspaces))
    rows = []
    for label, command, cwd in commands:
        run = rt.run('dbus-control-' + label, command, timeout=15, cwd=cwd)
        digest = _digest(json.dumps(command).encode())
        row = {'stage': label, 'guest_cwd_policy': cwd, 'argv_sha256': digest,
               'stage_argv': [redact_text(arg, host_binds) for arg in command],
               'status': 'pass' if not run.error and run.returncode == 0 else 'fail',
               **classify_failure(run)}
        row['stderr_diagnostic'] = stream_diagnostic(run.stderr, stage=label, argv_sha256=digest,
            returncode=run.returncode, run_error=run.error, host_binds=host_binds, closure=rt.closure)
        if label.startswith('daemon-') and label != 'daemon-version':
            if label == 'daemon-minimal':
                row.update(config_variant='temporary-minimal-no-includes',
                           config_sha256=_digest(MINIMAL_CONFIG.encode()),
                           qualification_authority=False, self_include_causality_proven=False)
            row['control'] = daemon_control(run, stage=label, argv_sha256=digest, host_binds=host_binds, closure=rt.closure)
            row['status'] = 'pass' if row['control']['status'] == 'observed' else row['control']['status']
            control = row['control']
            row['lifecycle'] = observed_survivors(rt, [{'pid': control.get('child_pid'),
                                                       'starttime': control.get('child_starttime')}])
        elif label == 'socket-controls':
            row['control'] = socket_control(run)
            row['status'] = 'pass' if row['control']['status'] == 'observed' else 'unobserved'
        elif label in ('session-tmp', 'session-root'):
            row['control'] = session_control(rt, run)
            if row['status'] == 'pass' and row['control']['status'] != 'observed':
                row['status'] = 'unobserved'
        rows.append(row)
    return {'schema': 'rs9.dbus-decomposition.v1', 'stages': rows,
            'dbus_cause': decomposition_cause(rows, original_failed),
            'cause_scope': 'control-boundary-only', 'qualification_authority': False,
            'application_qualified': False, 'status': 'diagnostic-only'}
