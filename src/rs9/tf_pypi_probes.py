"""Functional released CLI probes; never used with synthetic qualification claims."""
import json
from pathlib import Path
import subprocess
import sys

from rs9.tf_pypi_archive import fail, sha256


def receipt(command, operation, result):
    return {"command": command, "operation": operation, "exit": result.returncode,
            "stdout_sha256": sha256(result.stdout), "stderr_sha256": sha256(result.stderr)}


def installed_payload(pin, root):
    name = pin["project"].replace("-", "_")
    matches = list(root.glob("lib/python*/site-packages/" + name + "/payload/package"))
    if len(matches) != 1:
        fail("CONSUMER_PAYLOAD")
    return matches[0]


def _compile(pin, root, env, prefix, run):
    payload = installed_payload(pin, root)
    loom = pin["project"] == "theme-forge-stellar-loom"
    command = "tfsl" if loom else "tfss"
    source = payload / "examples" / ("amber-forge.theme.json" if loom else "forge-console.theme.json")
    output = Path(env["HOME"]) / (root.name + "-compiled.css")
    records = []
    for operation in ("validate", "compile"):
        argv = [root / "bin" / command, operation, source, "--json"]
        if operation == "compile":
            argv += ["--out", output]
        result = run(argv, env, prefix=prefix)
        if result.returncode or json.loads(result.stdout).get("status") != "success":
            fail("FUNCTIONAL_COMPILE")
        records.append(receipt(command, operation, result))
    css = (output / "theme.css" if loom else output).read_bytes()
    if len(css) < 100 or b"--" not in css:
        fail("FUNCTIONAL_COMPILE")
    records[-1]["output_sha256"] = sha256(css)
    if loom:
        request = {"action": "compile", "specification": json.loads(source.read_bytes())}
        result = run([root / "bin/tfsl-batch"], env, prefix=prefix,
                     input=json.dumps(request).encode())
        response = json.loads(result.stdout)
        if result.returncode or response.get("status") != "success" or len(response.get("compiledCss", "")) < 100:
            fail("FUNCTIONAL_BATCH")
        records.append(receipt("tfsl-batch", "compile", result))
    return records


STUDIO_DRIVER = '''import json,subprocess,sys,selectors
with subprocess.Popen([sys.argv[1]],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE) as p:
 try:
  def send(method,params,id=None):
   msg={"jsonrpc":"2.0","method":method,"params":params}
   if id is not None:msg['id']=id
   p.stdin.write((json.dumps(msg)+'\\n').encode());p.stdin.flush()
  def receive():
   with selectors.DefaultSelector() as s:
    s.register(p.stdout,selectors.EVENT_READ)
    if not s.select(10):raise RuntimeError('studio response timeout')
   return json.loads(p.stdout.readline())
  send('initialize',{'protocol':'tfsb.studio','minVersion':'1.0','maxVersion':'1.2','client':{'name':'rs9-offline-qualification','version':'1.0.0'},'capabilities':{'progress':False,'cancellation':False}},1)
  initialized=receive();assert initialized['id']==1
  nonce=initialized['result']['sessionNonce'];assert initialized['result']['server']['version']==sys.argv[2]
  send('initialized',{'sessionNonce':nonce})
  send('shutdown',{'sessionNonce':nonce},2)
  shutdown=receive();assert shutdown=={'jsonrpc':'2.0','id':2,'result':None}
  send('exit',{})
  p.stdin.close();p.wait(timeout=10);assert p.returncode==0
  print(json.dumps({'initialize':True,'shutdown':True,'exit':p.returncode,'selectedVersion':initialized['result']['selectedVersion']}))
 finally:
  if p.poll() is None:p.kill();p.wait()
'''


SOURCE_MAP = '''schema_version = 1
source_root = "."
[[collection]]
id = "icons"
name = "Icons"
root = "."
identity = "basename"
prefix = ""
include_paths = ["icon.svg"]
include_trees = []
exclude_paths = []
exclude_trees = []
'''


def _burst(pin, root, env, prefix, run):
    payload = installed_payload(pin, root)
    operation = Path(env["HOME"]) / (root.name + "-burst")
    source, project = operation / "source", operation / "project"
    source.mkdir(parents=True)
    project.mkdir()
    (source / "icon.svg").write_text('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M2 2h20v20H2z"/></svg>')
    (source / ".tfsb-source-map.toml").write_text(SOURCE_MAP)
    loader = (payload / "dist/directory-snapshot-native.js").as_uri()
    script = ("const {loadDirectorySnapshotNative}=await import(" + json.dumps(loader) + ");"
              "const r=loadDirectorySnapshotNative();console.log(JSON.stringify({ok:r.ok,artifact:r.artifact,reason:r.reason}));"
              "if(!r.ok)process.exitCode=1;")
    native = run([env["THEME_FORGE_NODE_BIN"], "--input-type=module", "-e", script], env, prefix=prefix)
    if native.returncode or json.loads(native.stdout).get("ok") is not True:
        fail("NATIVE_SELF_TEST")
    records = [receipt("native-loader", "load-and-self-test", native)]
    for command, args in [("import", [source, "--source-map", source / ".tfsb-source-map.toml", "--collection", "icons", "--normalize", "exact-common"]),
                          ("build", []), ("check", []), ("bundle", ["--output", "qualified.zip"])]:
        flags = [] if command == "build" else ["--json"]
        result = run([root / "bin/tfsb", command, *args, "--root", project, *flags], env, prefix=prefix)
        if result.returncode or (command != "build" and json.loads(result.stdout).get("status") != "ok"):
            fail("FUNCTIONAL_BURST_" + command.upper())
        records.append(receipt("tfsb", command, result))
    studio = run([root / "bin/python", "-I", "-B", "-c", STUDIO_DRIVER,
                  root / "bin/tfsb-studio-service", pin["version"]], env, prefix=prefix)
    if studio.returncode or json.loads(studio.stdout).get("exit") != 0:
        fail("FUNCTIONAL_STUDIO")
    records.append(receipt("tfsb-studio-service", "initialize-shutdown-exit", studio))
    return records


def functional_probes(pin, root, env, prefix, run):
    if pin["project"] == "theme-forge-stellar-burst":
        return _burst(pin, root, env, prefix, run)
    return _compile(pin, root, env, prefix, run)
