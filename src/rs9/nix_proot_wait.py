"""Diagnostic guest wait records; raw PRoot status is never repaired synthetically.

These records detect accidental mismatch. The same-uid guest can forge them,
so they are not authentication, isolation or application qualification.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat

SCHEMA = "rs9.proot-guest-wait.v1"
MAX_FRAME = 4096
FINAL_KEYS = {"schema", "nonce", "binding", "source_sha256", "argv_sha256", "supervisor_pid",
              "child_pid", "kind", "exit_code", "signal", "core_dumped", "forwarded_signals"}
START_KEYS = {"schema", "nonce", "binding", "source_sha256", "argv_sha256", "supervisor_pid", "child_pid"}

GUEST_SUPERVISOR_SOURCE = r'''
import hashlib,json,os,signal,sys
channel,nonce,binding,source_sha,argv_sha=sys.argv[1:6]
command=sys.argv[7:]
if sys.argv[6]!='--' or hashlib.sha256(json.dumps(command,separators=(',',':')).encode()).hexdigest()!=argv_sha:
    os._exit(254)
def frame(name,record):
    raw=json.dumps(record,separators=(',',':'),sort_keys=True).encode()
    if len(raw)>4096: os._exit(254)
    temp=os.path.join(channel,'.'+name+'.tmp')
    fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream: stream.write(raw)
    os.replace(temp,os.path.join(channel,name+'.json'))
forwarded=[];pending=[];pid=None
def forward(signum,_):
    if signum in forwarded: return
    forwarded.append(signum)
    if pid is None: pending.append(signum)
    elif pid>0:
        try: os.kill(pid,signum)
        except ProcessLookupError: pass
for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP,signal.SIGQUIT): signal.signal(sig,forward)
oldmask=signal.pthread_sigmask(signal.SIG_BLOCK,(signal.SIGTERM,signal.SIGINT,signal.SIGHUP,signal.SIGQUIT))
pid=os.fork()
if pid==0:
    for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP,signal.SIGQUIT): signal.signal(sig,signal.SIG_DFL)
    signal.pthread_sigmask(signal.SIG_SETMASK,oldmask)
    try: os.execvpe(command[0],command,os.environ)
    except OSError as error:
        os.write(2,('rs9 guest exec failed errno='+str(error.errno)+'\n').encode());os._exit(127)
base={'schema':'rs9.proot-guest-wait.v1','nonce':nonce,'binding':binding,'source_sha256':source_sha,
      'argv_sha256':argv_sha,'supervisor_pid':os.getpid(),'child_pid':pid}
frame('started',base)
signal.pthread_sigmask(signal.SIG_SETMASK,oldmask)
for sig in pending:
    try: os.kill(pid,sig)
    except ProcessLookupError: pass
while True:
    try: _,status=os.waitpid(pid,0);break
    except InterruptedError: continue
if os.WIFEXITED(status):
    record=dict(base,kind='exited',exit_code=os.WEXITSTATUS(status),signal=None,core_dumped=False,
                forwarded_signals=forwarded)
elif os.WIFSIGNALED(status):
    record=dict(base,kind='signaled',exit_code=None,signal=os.WTERMSIG(status),
                core_dumped=bool(hasattr(os,'WCOREDUMP') and os.WCOREDUMP(status)),forwarded_signals=forwarded)
else: os._exit(254)
frame('final',record)
if record['kind']=='signaled':
    if record['signal'] not in (signal.SIGKILL,signal.SIGSTOP): signal.signal(record['signal'],signal.SIG_DFL)
    os.kill(os.getpid(),record['signal']);os._exit(254)
os._exit(record['exit_code'])
'''
SOURCE_SHA256 = hashlib.sha256(GUEST_SUPERVISOR_SOURCE.encode()).hexdigest()


def argv_digest(command):
    return hashlib.sha256(json.dumps(list(command), separators=(",", ":")).encode()).hexdigest()


def _unique(pairs):
    record = {}
    for key, value in pairs:
        if key in record:
            raise ValueError("duplicate-frame-key")
        record[key] = value
    return record


def read_frame(path, expected, *, started=False):
    """No-follow, nonblocking, owner-bound closed frame; no raw errors escape."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return {"status": "missing", "reason": "guest-wait-record-missing"}
    except OSError:
        return {"status": "malformed", "reason": "guest-wait-record-malformed"}
    try:
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_size > MAX_FRAME:
                raise ValueError
            raw = stream.read(MAX_FRAME + 1)
        if len(raw) > MAX_FRAME:
            raise ValueError
        doc = json.loads(raw, object_pairs_hook=_unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        keys = START_KEYS if started else FINAL_KEYS
        if type(doc) is not dict or set(doc) != keys or doc["schema"] != SCHEMA:
            raise ValueError
        for key, size in (("nonce", 32), ("binding", 64), ("source_sha256", 64), ("argv_sha256", 64)):
            if type(doc[key]) is not str or not re.fullmatch("[0-9a-f]{" + str(size) + "}", doc[key]):
                raise ValueError
            if doc[key] != expected[key]:
                return {"status": "contradictory", "reason": "guest-wait-binding-mismatch"}
        if any(type(doc[k]) is not int or not 1 < doc[k] < 2 ** 31 for k in ("supervisor_pid", "child_pid")):
            raise ValueError
        if doc["supervisor_pid"] == doc["child_pid"]:
            raise ValueError
        if not started:
            if doc["kind"] not in {"exited", "signaled"} or type(doc["core_dumped"]) is not bool:
                raise ValueError
            sigs = doc["forwarded_signals"]
            if type(sigs) is not list or len(sigs) > 4 or any(type(s) is not int or s not in (1, 2, 3, 15) for s in sigs) or len(set(sigs)) != len(sigs):
                raise ValueError
            if doc["kind"] == "exited":
                if type(doc["exit_code"]) is not int or not 0 <= doc["exit_code"] <= 255 or doc["signal"] is not None or doc["core_dumped"]:
                    raise ValueError
            elif doc["exit_code"] is not None or type(doc["signal"]) is not int or not 1 <= doc["signal"] <= 64:
                raise ValueError
    except (OSError, ValueError, UnicodeError, TypeError, KeyError, RecursionError):
        return {"status": "malformed", "reason": "guest-wait-record-malformed"}
    return {"status": "valid", "record": doc, "frame_bytes": len(raw), "frame_sha256": hashlib.sha256(raw).hexdigest()}


def assess_status(raw_returncode, frame):
    """Expose collapse or contradiction while preserving the actual wrapper status."""
    if frame["status"] != "valid":
        return {**frame, "raw_returncode": raw_returncode, "status_mapped": False}
    record = frame["record"]
    expected = record["exit_code"] if record["kind"] == "exited" else -record["signal"]
    compatible = (raw_returncode == expected if record["kind"] == "exited"
                  else raw_returncode in {-record["signal"], 128 + record["signal"]})
    collapsed = record["kind"] == "signaled" and raw_returncode == 255
    contradictory = not compatible and not collapsed
    return {**frame, "status": "contradictory" if contradictory else "valid",
            "reason": "guest-wait-status-contradictory" if contradictory else
                      "guest-signal-status-not-propagated" if collapsed else None,
            "raw_returncode": raw_returncode, "compatible_status": compatible,
            "signal_status_collapsed": collapsed, "status_mapped": False,
            "deliberate_exit_255": record["kind"] == "exited" and record["exit_code"] == 255}


def diagnostic_guest_run(rt, probe, command, *, timeout=30, cwd="/tmp"):
    """Separate measured arm: return raw Run plus source/run/argv-bound wait evidence."""
    nonce = secrets.token_hex(16)
    guest_sha256 = hashlib.sha256(json.dumps({"facts": rt.facts, "closure": getattr(rt, "closure", [])},
                                            sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    expected = {"nonce": nonce, "source_sha256": SOURCE_SHA256, "argv_sha256": argv_digest(command)}
    expected["binding"] = hashlib.sha256(json.dumps({**expected, "probe": probe, "guest_sha256": guest_sha256},
                                                  sort_keys=True).encode()).hexdigest()
    channel = rt.layout.tmp_dir / ("rs9-wait-" + nonce)
    channel.mkdir(mode=0o700)
    guest_channel = "/tmp/" + channel.name
    run = rt.run(probe, [rt.facts["python"], "-I", "-S", "-B", "-c", GUEST_SUPERVISOR_SOURCE,
                         guest_channel, nonce, expected["binding"], SOURCE_SHA256, expected["argv_sha256"],
                         "--", *command], timeout=timeout, cwd=cwd)
    final = read_frame(channel / "final.json", expected)
    started = read_frame(channel / "started.json", expected, started=True)
    diagnostic = assess_status(run.returncode, final)
    if final["status"] == "valid" and started["status"] == "valid":
        if any(final["record"][k] != started["record"][k] for k in START_KEYS):
            diagnostic.update(status="contradictory", reason="guest-wait-start-final-mismatch", compatible_status=False)
    elif started["status"] != "valid":
        diagnostic.update(status=started["status"], reason=started["reason"], compatible_status=False)
    if run.error:
        diagnostic.update(status="unobserved", reason="guest-wait-" + run.error, compatible_status=False)
    diagnostic.update(schema="rs9.proot-host-wait-diagnostic.v1", **expected, guest_sha256=guest_sha256, authenticated=False,
                      cleanup_authority="proot-kill-on-exit-and-owned-process-group", raw_status_preserved=True)
    # The evaluation retains this safe bound record. Do not write host-owned
    # diagnostics into a channel writable by the guest. A forced group kill
    # makes guest final framing unavailable.
    raw = json.dumps(diagnostic, sort_keys=True, separators=(",", ":")).encode()
    if len(raw) > MAX_FRAME:
        diagnostic = {"schema": "rs9.proot-host-wait-diagnostic.v1", **expected, "guest_sha256": guest_sha256,
                      "status": "malformed", "reason": "host-wait-frame-limit", "compatible_status": False,
                      "raw_returncode": run.returncode, "raw_status_preserved": True, "status_mapped": False,
                      "authenticated": False, "frame_bytes": len(raw), "frame_sha256": hashlib.sha256(raw).hexdigest()}
    return run, diagnostic
