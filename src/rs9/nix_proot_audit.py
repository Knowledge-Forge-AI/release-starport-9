"""Bounded guest-side command closure audit; references are diagnostic candidates."""
import hashlib
import json
from rs9.nix_proot_dbus import DBUS_AUDIT_SOURCE, audit_dbus_config


# Executed only by an explicit probe using the pinned guest Python. No host
# filesystem substitution can establish guest visibility.
GUEST_AUDIT_SOURCE = r'''
import hashlib,json,os,re,shlex,shutil,stat,struct,sys,xml.etree.ElementTree as ET
spec=json.loads(sys.argv[1])
store=re.compile(r"/nix/store/[0-9a-df-np-sv-z]{32}-[A-Za-z0-9+._?=-]+(?:/[A-Za-z0-9+._?=@~-]+)*")
known=set(spec['closure'])
binds=spec['host_binds']
public=('/etc/','/run/','/var/run/','/var/tmp/','/usr/','/bin/','/lib/','/lib64/','/dev/','/proc/')
helpers=('Xvfb','xauth','xkbcomp','getopt','mcookie','mktemp','which','awk','sed','rm','dbus-daemon','node','python3','sh','bash','env')
runtime_paths=('/etc/dbus-1/session.conf','/etc/dbus-1','/run','/var/run','/var/lib/dbus/machine-id',
               '/etc/machine-id','/usr/share/X11','/etc/X11','/tmp/.X11-unix')
absolute_command=re.compile(r'/(?:usr/)?(?:bin|sbin)/[A-Za-z0-9+._-]+')
def sha(raw): return hashlib.sha256(raw).hexdigest()
def top(p):
    return '/'.join(p.split('/')[:4]) if p and p.startswith('/nix/store/') else None
def path_fact(p):
    if any(p==b or p.startswith(b+'/') for b in binds):
        return {'path_class':'host-bind-state','path_sha256':sha(p.encode())}
    if store.fullmatch(p):
        return {'path_class':'closure-store' if top(p) in known else 'store-outside-closure','path':p}
    if p in ('/tmp','/tmp/.X11-unix','/run','/var/run','/etc','/usr') or p.startswith(public):
        return {'path_class':'guest-system','path':p}
    return {'path_class':'guest-other','path_sha256':sha(p.encode())}
def reference(p,role):
    return dict(path_fact(p),role=role,present=os.path.exists(p))
def interp(raw):
    if len(raw)<64 or raw[:4]!=b'\x7fELF' or raw[4] not in (1,2) or raw[5] not in (1,2): return None
    endian='<' if raw[5]==1 else '>'
    is64=raw[4]==2
    off=struct.unpack_from(endian+('Q' if is64 else 'I'),raw,32 if is64 else 28)[0]
    size,count=struct.unpack_from(endian+'HH',raw,54 if is64 else 42)
    need=56 if is64 else 32
    if size<need or count>128: return None
    for i in range(count):
        p=off+i*size
        if p+need>len(raw): return None
        if struct.unpack_from(endian+'I',raw,p)[0]==3:
            target=struct.unpack_from(endian+('Q' if is64 else 'I'),raw,p+(8 if is64 else 4))[0]
            n=struct.unpack_from(endian+('Q' if is64 else 'I'),raw,p+(32 if is64 else 16))[0]
            if not 0<n<=1024 or target+n>len(raw): return None
            return raw[target:target+n].split(b'\0',1)[0].decode('utf-8','strict')
    return None
roots=[]
queue=[]
for role,expected in spec['roots'].items():
    resolved=shutil.which(spec['names'][role])
    roots.append({'role':role,'fact':reference(expected,'pinned-command'),
                  'path_resolution':reference(resolved,'PATH-command') if resolved else {'present':False},
                  'same_real_file':bool(resolved and os.path.realpath(resolved)==os.path.realpath(expected))})
    queue.append((expected,role,0,os.environ.get('PATH','')))
seen=set();files=[];limited=False
while queue and len(files)<64:
    p,role,depth,inherited_path=queue.pop(0)
    if p in seen: continue
    seen.add(p)
    rec=dict(reference(p,role),depth=depth,references=[])
    real=os.path.realpath(p)
    rec['resolved']=reference(real,'symlink-target')
    # Read only actual pinned closure scripts/ELFs. Fixed guest paths are
    # checked for existence, never inventoried for unrelated private content.
    if top(real) not in known:
        rec['inspection']='outside-closure';files.append(rec);continue
    try:
        fd=os.open(real,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as f:
            st=os.fstat(f.fileno())
            if not stat.S_ISREG(st.st_mode):
                rec['inspection']='not-regular';files.append(rec);continue
            header=f.read(256);f.seek(0)
            limit=256*1024 if header.startswith(b'#!') else 16*1024*1024
            raw=f.read(limit+1)
        rec.update(file_bytes=st.st_size,scanned_bytes=min(len(raw),limit),scanned_sha256=sha(raw[:limit]),
                   scan_complete=len(raw)<=limit)
        if len(raw)>limit: limited=True
    except OSError as error:
        rec.update(inspection='unreadable',errno=error.errno);files.append(rec);continue
    refs=[];local_path=inherited_path
    if header.startswith(b'#!'):
        line=header.split(b'\n',1)[0][2:]
        rec['kind']='script';rec['shebang_complete']=b'\n' in header
        try: tokens=shlex.split(line.decode('utf-8'))
        except (ValueError,UnicodeError): tokens=[]
        if tokens:
            refs.append((tokens[0],'shebang-interpreter'))
            if os.path.basename(tokens[0])=='env':
                args=[a for a in tokens[1:] if not a.startswith('-')]
                if args:
                    target=shutil.which(args[0])
                    rec['env_interpreter']=reference(target,'env-PATH-interpreter') if target else {'present':False}
                    if target: refs.append((target,'env-PATH-interpreter'))
        text=raw[:limit].decode('utf-8','replace')
        refs.extend((m.group(),'script-store-reference') for m in store.finditer(text))
        refs.extend((m.group(),'script-absolute-command-candidate') for m in absolute_command.finditer(text)
                    if m.start()==0 or text[m.start()-1] in ' \t\r\n\"\'=:(')
        path_dirs=[p for p,r in refs if p.endswith('/bin') and os.path.isdir(p)]
        local_path=':'.join(path_dirs+[inherited_path])
        for name in helpers:
            if re.search(r'(?<![\w-])'+re.escape(name)+r'(?![\w-])',text):
                target=shutil.which(name,path=local_path)
                rec.setdefault('PATH_candidates',[]).append({'tool':name,'present':bool(target),
                    **(path_fact(target) if target else {})})
                if target: refs.append((target,'script-PATH-candidate'))
        rec['error_file_option']=('--error-file' in text)
        rec['dynamic_reference_count']=len(re.findall(r'\$[A-Za-z_][A-Za-z_0-9]*',text))
        # Fixed guest runtime references are safe existence facts, not causal
        # claims. They are never recursively opened.
        for fixed in runtime_paths:
            if fixed in text: refs.append((fixed,'script-runtime-candidate'))
    else:
        rec['kind']='elf' if raw.startswith(b'\x7fELF') else 'data'
        try: loader=interp(raw[:limit])
        except (ValueError,UnicodeError,struct.error): loader=None
        if loader: refs.append((loader,'ELF-PT_INTERP'))
        refs.extend((m.group(),'ELF-store-candidate') for m in store.finditer(raw[:limit].decode('latin1')))
        refs.extend((m.group(),'ELF-absolute-command-candidate')
                    for m in absolute_command.finditer(raw[:limit].decode('latin1'))
                    if m.start()==0 or raw[m.start()-1] in b'\x00 \t\r\n\"\'=:(')
        refs.extend((fixed,'ELF-runtime-candidate') for fixed in runtime_paths if fixed.encode() in raw[:limit])
    distinct=list(dict.fromkeys(refs))
    if len(distinct)>64: limited=True
    for target,ref_role in distinct[:64]:
        rec['references'].append(reference(target,ref_role))
        if depth<4 and top(os.path.realpath(target)) in known and os.path.isfile(target):
            queue.append((target,ref_role,depth+1,local_path))
        elif depth>=4 and target not in seen and os.path.isfile(target): limited=True
    files.append(rec)
if queue: limited=True


''' + DBUS_AUDIT_SOURCE + r'''
dbus_audit=audit_dbus_config(spec) if 'dbus_session_config' in spec else None
out_status='fail' if dbus_audit and dbus_audit['status']=='fail' else 'observed'
doc={'schema':'rs9.proot-launch-audit.v1','status':out_status,'references_are_candidates':True,
    'roots':roots,'files':files,'audit_complete':not limited and (dbus_audit is None or dbus_audit['audit_complete']),
    'limits':{'files':64,'depth':4,'script_bytes':262144,'elf_bytes':16777216},
    'filesystem':{'cwd':path_fact(os.getcwd()),'tmp_present':os.path.isdir('/tmp'),
        'tmp_writable':os.access('/tmp',os.W_OK),'x11_socket_directory_present':os.path.isdir('/tmp/.X11-unix'),
        'foreign_interpreter':reference(spec['foreign_interpreter'],'released-ELF-interpreter'),
        'runtime_candidates':[reference(p,'runtime-file-candidate') for p in runtime_paths]}}
if dbus_audit is not None:doc['dbus_config']=dbus_audit
if out_status=='fail':doc['reason']=dbus_audit['reason']
print(json.dumps(doc))
'''


def guest_audit(rt):
    """Execute the audit in the real guest and retain only its bounded safe record."""
    roots = {k: rt.facts[k] for k in ("xvfb_run", "dbus_run_session", "dbus_daemon", "python", "node") if k in rt.facts}
    names = {"xvfb_run": "xvfb-run", "dbus_run_session": "dbus-run-session",
             "dbus_daemon": "dbus-daemon", "python": "python3", "node": "node"}
    spec = {"roots": roots, "names": {k: names[k] for k in roots},
            "closure": rt.closure, "foreign_interpreter": rt.facts["foreign_interpreter"],
            "host_binds": [str(p) for p in (rt.layout.tmp_dir, rt.layout.cache_dir, rt.layout.loader_tmp,
                                            rt.layout.etc_dir, *rt.layout.workspaces)]}
    if "dbus_session_config" in rt.facts:
        spec["dbus_session_config"] = rt.facts["dbus_session_config"]
    if "dbus_daemon" in rt.facts:
        spec["dbus_daemon"] = rt.facts["dbus_daemon"]
    run = rt.run("launch-chain-static-audit", [rt.facts["python"], "-I", "-S", "-B", "-c",
                                             GUEST_AUDIT_SOURCE, json.dumps(spec)], timeout=45, cwd="/tmp")
    streams = {"exit_code": run.returncode, "signal": -run.returncode if run.returncode is not None and run.returncode < 0 else None,
               "stdout_bytes": len(run.stdout), "stderr_bytes": len(run.stderr),
               "stdout_sha256": hashlib.sha256(run.stdout).hexdigest(),
               "stderr_sha256": hashlib.sha256(run.stderr).hexdigest(), "elapsed_seconds": round(run.elapsed, 3)}
    if run.error or run.returncode != 0:
        return {"status": "unobserved", "reason": run.error or "guest-audit-launch-failed", **streams}
    try:
        record = json.loads(run.stdout)
        if not isinstance(record, dict) or record.get("schema") != "rs9.proot-launch-audit.v1":
            raise ValueError
        # The source is fixed and bound to the probe; do not accept host bind
        # strings even if a malformed guest receipt places them elsewhere.
        public = json.dumps(record)
        if any(path and path in public for path in spec["host_binds"]):
            raise ValueError
    except (ValueError, UnicodeError, TypeError):
        return {"status": "unobserved", "reason": "guest-audit-frame-malformed", **streams}
    return {**record, "streams": streams, "source_sha256": hashlib.sha256(GUEST_AUDIT_SOURCE.encode()).hexdigest()}
