"""Controlled RPM header responses derived from complete fixture archives.

These are source test inputs, never claims of native RPM execution.
"""
import copy
import json
from pathlib import Path
import re
import stat

from rs9.archives import inspect_archive
from rs9.build_native import CommandReceipt
from rs9.release_core import digest
from rs9.rpm_lint_policy import load_policy


def fixture_members(scratch):
    sources = Path(scratch) / 'rpmbuild/SOURCES'
    spec = next((Path(scratch) / 'rpmbuild/SPECS').glob('*.spec')).read_text()
    name = re.search(r'^Name: (.+)$', spec, re.M)[1]
    source = sources / re.search(r'^Source0: (.+)$', spec, re.M)[1]
    files = {}
    for archive, destination in ((source, '/usr/lib/' + name),
                                 (sources / 'npm-closure.tar.gz', '/usr/lib/' + name + '/node_modules')):
        if not archive.exists():
            continue
        manifest = inspect_archive(archive, {})
        for row in manifest['members']:
            path = destination + row['path'].removeprefix(manifest['root'])
            files[path] = dict(row, path=path)
    for base in ('LICENSE', 'NOTICE'):
        path = '/usr/share/licenses/' + name + '/' + base
        files[path] = dict(files['/usr/lib/' + name + '/' + base], path=path, mode=0o644)
    # The spec's maintained launcher destinations and command targets are paired.
    commands = re.findall(r"cat << 'EOF' > '%\{buildroot\}(/usr/bin/[^']+)'\n#!/bin/sh\nexec node \"([^\"]+)\" \"\$@\"", spec)
    for path, target in commands:
        body = ('#!/bin/sh\nexec node "' + target + '" "$@"\n').encode()
        files[path] = dict(path=path,type='file',mode=0o755,size=len(body),sha256=digest(body))
    for target, path in re.findall(r"ln -s '([^']+)' '%\{buildroot\}([^']+)'", spec):
        files[path] = dict(path=path,type='symlink',mode=0o777,size=len(target),target=target)
    if not commands:
        for source_name, path in ((name + '.desktop','/usr/share/applications/' + name + '.desktop'),
                                  ('icon.png','/usr/share/icons/hicolor/256x256/apps/' + name + '.png')):
            body = (sources/source_name).read_bytes()
            files[path] = dict(path=path,type='file',mode=0o644,size=len(body),sha256=digest(body))
    return files


def inventory_response(argv, cwd):
    """Return only the new real query shapes; existing identity tests keep control."""
    if '--eval' in argv and '--target' in argv and argv[argv.index('--eval') + 1].startswith('%{_buildtime}|'):
        macros = dict(argv[i + 1].split(' ', 1) for i, arg in enumerate(argv) if arg == '--define')
        values = [macros['_buildtime'], macros['_buildhost'], '', 'noarch', 'linux',
                  macros['_target_platform'], macros['use_source_date_epoch_as_buildtime'],
                  macros['source_date_epoch_from_changelog'], macros['build_mtime_policy'], macros['_buildtime']]
        return CommandReceipt(argv, 0, ('|'.join(values) + '\n').encode(), b'', executed=True)
    if '-q' in argv and argv[-1] == 'rpmlint':
        return CommandReceipt(argv,0,b'rpmlint|2.8.0|2.fc43|noarch\n',b'')
    if '--provides' in argv:
        return CommandReceipt(argv,0,b'fixture-package = 1\n',b'')
    qf = argv[argv.index('--queryformat')+1] if '--queryformat' in argv else ''
    if '%{FILEDIGESTALGO}' in qf:
        return CommandReceipt(argv,0,b'8\n',b'')
    if '--dump' not in argv and '%{FILENAMES}' not in qf:
        return None
    files = fixture_members(cwd)
    lines = []
    for inode,(path,row) in enumerate(sorted(files.items()),1):
        if '--dump' in argv:
            file_type = {'file':stat.S_IFREG,'directory':stat.S_IFDIR,'symlink':stat.S_IFLNK}[row['type']]
            lines.append(f"{path} {row['size']} 1767225600 {row.get('sha256','0'*64)} {file_type|row['mode']:07o} root root 0 0 0 {row.get('target','X')}")
        else:
            lines.append(f'{path}|{inode}|1|0')
    return CommandReceipt(argv,0,('\n'.join(lines)+'\n').encode(),b'')


def write_source_rpm_fixture(argv, cwd):
    """Explicit source-RPM tool double for the -ba contract; no real RPM claim."""
    if '--target' not in argv or argv[argv.index('--target') + 1] != 'noarch':
        return
    topdir = Path(cwd)
    spec = next((topdir / 'SPECS').glob('*.spec')).read_bytes()
    name = re.search(rb'^Name: (.+)$', spec, re.M)[1].decode()
    version = re.search(rb'^Version: (.+)$', spec, re.M)[1].decode()
    directory = topdir / 'SRPMS'; directory.mkdir(exist_ok=True)
    (directory / f'{name}-{version}-1.fc43.src.rpm').write_bytes(b'fixture-source-rpm\n' + spec)


def fixture_policy(root):
    """Pin the policy to exact fixture archive hashes, with zero exceptions."""
    policy = copy.deepcopy(load_policy())
    policy['projects'] = {}
    policy['tool_constraints']['filtered_count'] = 0
    for sources in Path(root).rglob('rpmbuild/SOURCES'):
        spec = next((sources.parent/'SPECS').glob('*.spec')).read_text()
        name = re.search(r'^Name: (.+)$',spec,re.M)[1]
        version = re.search(r'^Version: (.+)$',spec,re.M)[1]
        source = sources/re.search(r'^Source0: (.+)$',spec,re.M)[1]
        closure = sources/'npm-closure.tar.gz'
        commands = re.findall(r"cat << 'EOF' > '%\{buildroot\}(/usr/bin/[^']+)'\n#!/bin/sh\nexec node \"([^\"]+)\" \"\$@\"", spec)
        policy['projects'][name] = dict(package_name=name,version=version,status='authorized',blocking=False,
            allowed_architectures=['noarch','x86_64','aarch64'],allowed_systems=['x86_64-linux','aarch64-linux'],exceptions={},
            launchers={path.rsplit('/',1)[-1]:dict(path=path,target=target,mode='0755',type='node_wrapper')
                       for path,target in commands},
            authenticated_inputs={'asset_sha256':digest(source.read_bytes()),'closure_sha256':digest(closure.read_bytes()) if closure.exists() else None})
    return policy
