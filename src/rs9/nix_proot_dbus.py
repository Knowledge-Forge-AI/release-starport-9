"""One fixed D-Bus audit source shared by guest execution and source fixtures."""

DBUS_AUDIT_SOURCE = r'''
import hashlib,json,os,re,shutil,stat,xml.etree.ElementTree as ET
D_MAX_BYTES=65536
D_MAX_FILES=32
D_MAX_DEPTH=4
D_MAX_ENTRIES=128

def d_top(path):
    return '/'.join(path.split('/')[:4]) if path and path.startswith('/nix/store/') else None

def d_path(path,known):
    if not path:return None
    if d_top(path) in known:return path
    if re.fullmatch(r'/nix/store/[0-9a-df-np-sv-z]{32}-[A-Za-z0-9+._?=-]+(?:/[A-Za-z0-9+._?=@~-]+)*',path):return path
    if path in ('/etc/dbus-1','/etc/dbus-1/session.conf'):return path
    if re.fullmatch(r'/etc/dbus-1/[A-Za-z0-9._-]{1,64}',path):return path
    return '<withheld-path>'

def d_entries(path):
    entries=[]
    with os.scandir(path) as scan:
        for entry in scan:
            if len(entries)>=D_MAX_ENTRIES:raise ValueError('config-audit-limit')
            entries.append(entry.name)
    return sorted(entries)

def d_read(path,known):
    real=os.path.realpath(path)
    if d_top(real) not in known:raise ValueError('symlink-outside-closure')
    fd=os.open(real,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):raise ValueError('config-not-regular')
        if info.st_size>D_MAX_BYTES:raise ValueError('config-oversize')
        raw=stream.read(D_MAX_BYTES+1)
    if len(raw)>D_MAX_BYTES:raise ValueError('config-oversize')
    root=ET.fromstring(raw)
    if root.tag!='busconfig':raise ValueError('config-malformed')
    return root,{'path':d_path(path,known),'real_path':d_path(real,known),
        'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}

def d_include(elem,path,depth,known):
    value=(elem.text or '').strip()
    if not value:raise ValueError('config-malformed')
    target=os.path.normpath(value if value.startswith('/') else os.path.join(os.path.dirname(path),value))
    directory=elem.tag=='includedir'
    present=os.path.isdir(target) if directory else os.path.exists(target)
    real=os.path.realpath(target) if present else None
    skip_selinux=elem.get('if_selinux_enabled')=='yes' and not os.path.isdir('/sys/fs/selinux')
    ignore=elem.get('ignore_missing')=='yes'
    # D-Bus includedir permits absent directories; a present unreadable
    # directory is not silently treated as empty by this audit.
    required=not directory and not ignore and not skip_selinux
    rec={'tag':elem.tag,'raw':d_path(value,known) if value.startswith('/') else
         value if re.fullmatch(r'[A-Za-z0-9._/-]{1,128}',value) else '<withheld-path>',
         'resolved':d_path(target,known),'resolved_sha256':hashlib.sha256(target.encode()).hexdigest(),
         'ignore_missing':ignore,'required':required,'conditional_skipped':skip_selinux,
         'present':present,'real_path':d_path(real,known),'in_closure':bool(real and d_top(real) in known),'depth':depth}
    error=None
    if not present and required:error='missing-required-include'
    if present and d_top(real) not in known:error='symlink-outside-closure'
    next_paths=[]
    if present and not skip_selinux and not error:
        if directory:
            next_paths=[os.path.join(target,n) for n in d_entries(target) if n.endswith('.conf')]
        else:next_paths=[target]
    return rec,next_paths,error

def d_traverse(path,known):
    queue=[(path,0)];seen=set();files=[];includes=[];listens=[];auth=[];services=[]
    reason,failing=None,None
    try:
        while queue:
            current,depth=queue.pop(0)
            if current in seen:continue
            if depth>D_MAX_DEPTH or len(seen)>=D_MAX_FILES:raise ValueError('config-audit-limit')
            seen.add(current)
            root,record=d_read(current,known);record['depth']=depth;files.append(record)
            for elem in root.iter():
                if elem.tag=='listen':
                    value=(elem.text or '').strip()
                    listens.append('unix:tmpdir' if value.startswith('unix:tmpdir=') else
                        'unix:path' if value.startswith('unix:path=') else
                        'unix:dir' if value.startswith('unix:dir=') else 'other')
                if elem.tag=='auth':
                    value=(elem.text or '').strip()
                    auth.append(value if value in ('EXTERNAL','DBUS_COOKIE_SHA1','ANONYMOUS') else 'other')
                if elem.tag=='standard_session_servicedirs':services.append({'kind':'standard-session'})
                if elem.tag=='servicedir':
                    value=(elem.text or '').strip()
                    if len(services)>=D_MAX_ENTRIES:raise ValueError('config-audit-limit')
                    services.append({'kind':'explicit','path':d_path(value,known),
                        'path_sha256':hashlib.sha256(value.encode()).hexdigest()})
                if elem.tag not in ('include','includedir'):continue
                if len(includes)>=D_MAX_ENTRIES:raise ValueError('config-audit-limit')
                rec,targets,error=d_include(elem,current,depth,known);includes.append(rec)
                if error:
                    failing=rec['resolved'];raise ValueError(error)
                queue.extend((target,depth+1) for target in targets)
    except ET.ParseError:reason='config-malformed'
    except FileNotFoundError:reason='config-file-missing'
    except OSError:reason='config-unreadable'
    except ValueError as error:reason=str(error)
    if reason and failing is None:failing=d_path(current,known)
    return {'status':'fail' if reason else 'pass','reason':reason,'failing_path':failing,
        'files':files,'includes':includes,'listen_classes':sorted(set(listens)),
        'auth_mechanisms':sorted(set(auth)),'audit_complete':not reason,
        'service_directories':services,
        'limits':{'file_bytes':D_MAX_BYTES,'depth':D_MAX_DEPTH,'max_files':D_MAX_FILES,'entries':D_MAX_ENTRIES}}

def audit_dbus_config(spec):
    known=set(spec['closure']);expected=spec.get('dbus_daemon');config=spec.get('dbus_session_config')
    resolved=shutil.which('dbus-daemon');real=os.path.realpath(resolved) if resolved else None
    present=bool(resolved and os.path.isfile(resolved))
    same=bool(present and expected and real==os.path.realpath(expected))
    result={'daemon_identity':{'expected':d_path(expected,known),'resolved':d_path(resolved,known),
        'real_path':d_path(real,known),'present':present,'in_closure':d_top(real) in known,'same_real_file':same}}
    reason='dbus-daemon-missing' if not present else 'dbus-daemon-mismatch' if not same else \
        'daemon-outside-closure' if d_top(real) not in known else None
    directory='/etc/dbus-1';path=directory+'/session.conf'
    try:
        dir_present=os.path.isdir(directory);entries=d_entries(directory) if dir_present else []
        singleton=entries==['session.conf']
        conf_present=os.path.exists(path);conf_real=os.path.realpath(path) if conf_present else None
        matches=bool(config and conf_real==config)
        result['singleton_directory']={'path':directory,'present':dir_present,'is_singleton':singleton,
            'entries':['session.conf'] if singleton else [],'entry_count':len(entries)}
        result['session_config_identity']={'guest_path':path,'expected_store_path':d_path(config,known),
            'real_path':d_path(conf_real,known),'present':conf_present,'matches_fact':matches,
            'in_closure':d_top(conf_real) in known}
        reason=reason or ('dbus-directory-missing' if not dir_present else
            'dbus-directory-not-singleton' if not singleton else 'dbus-session-config-missing' if not conf_present else
            'dbus-session-config-mismatch' if not matches else 'symlink-outside-closure' if d_top(conf_real) not in known else None)
    except OSError:reason=reason or 'config-unreadable'
    except ValueError:reason=reason or 'config-audit-limit'
    if reason:
        return {**result,'status':'fail','reason':reason,'failing_path':path,
                'audit_complete':False,'files':[],'includes':[]}
    return {**result,**d_traverse(path,known)}
'''


def audit_dbus_config(spec):
    """Execute the exact fixed guest audit against an explicit fixture filesystem."""
    namespace = {}
    exec(compile(DBUS_AUDIT_SOURCE, "rs9-dbus-audit", "exec"), namespace)
    return namespace["audit_dbus_config"](spec)
