"""Disposable GitHub Windows node. Self-check is local; --apply requires GitHub hosting."""
import argparse
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import uuid
import zipfile


def child(root, relative):
    name = PurePosixPath(relative)
    if not isinstance(relative, str) or '\\' in relative or ':' in relative or name.is_absolute() or '..' in name.parts:
        raise ValueError('Unsafe archive path')
    target = root.joinpath(*name.parts)
    if not target.is_relative_to(root):
        raise ValueError('Archive path escaped root')
    return target


def unpack(source, destination):
    destination.mkdir()
    with zipfile.ZipFile(source) as archive:
        for entry in archive.infolist():
            child(destination, entry.filename)
            if ((entry.external_attr >> 16) & 0o170000) == 0o120000:
                raise ValueError('Archive symlink refused')
        archive.extractall(destination)


def checked_identity(status, operator):
    own = status.get('Self', {})
    peer = next((row for row in (status.get('Peer') or {}).values() if row.get('ID') == operator), {})
    if (status.get('BackendState') != 'Running' or not peer.get('Online') or not own.get('UserID')
            or type(own['UserID']) is not type(peer.get('UserID')) or own['UserID'] != peer['UserID']
            or own.get('Tags') or peer.get('Tags')):
        raise ValueError('Expected online user-owned operator and untagged user-owned CI node')
    node = own.get('ID', '')
    if not re.fullmatch('[A-Za-z0-9]{1,64}', node) or node == operator:
        raise ValueError('Independent CI node identity required')
    address = next((value for value in own.get('TailscaleIPs', [])
                    if ipaddress.ip_address(value) in ipaddress.ip_network('100.64.0.0/10')), None)
    if address is None:
        raise ValueError('CI node has no Tailnet IPv4')
    return node, address


def checked_url(value):
    url = urllib.parse.urlsplit(value)
    if (url.scheme != 'https' or url.hostname != 'github.com' or url.username or url.password or url.query or url.fragment
            or not url.path.startswith('/RiceM001/AgentRemote/releases/download/') or not url.path.endswith('.zip')):
        raise ValueError('Expected the reviewed AgentRemote release archive URL')
    return value


def write_json(path, value):
    temporary = path.with_suffix('.' + uuid.uuid4().hex + '.tmp')
    temporary.write_text(json.dumps(value, indent=2, ensure_ascii=True), encoding='utf-8')
    os.replace(temporary, path)


def manifest_files(root, manifest):
    for name, expected in manifest.items():
        if not re.fullmatch('[0-9a-f]{64}', expected):
            raise ValueError('Invalid resource digest')
        path = child(root, name)
        with path.open('rb') as stream:
            if hashlib.file_digest(stream, 'sha256').hexdigest() != expected:
                raise ValueError('Resource digest mismatch: ' + name)


def wait_authenticated_probe(command, env, process, deadline, poll_seconds):
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or process.poll() is not None:
            raise RuntimeError('CI authenticated probe did not become ready before the startup deadline')
        try:
            completed = subprocess.run(command, env=env, capture_output=True, timeout=remaining)
        except subprocess.TimeoutExpired:
            raise RuntimeError('CI authenticated probe startup deadline expired') from None
        if completed.returncode == 0:
            if time.monotonic() >= deadline:
                raise RuntimeError('CI authenticated probe completed after the startup deadline')
            return
        time.sleep(min(poll_seconds, max(0, deadline - time.monotonic())))


def self_check():
    root = Path.cwd().resolve()
    assert child(root, 'a/b.txt') == root / 'a/b.txt'
    for value in ('../x', '/x', 'C:/x', 'a\\b', 'a/../../x'):
        try:
            child(root, value)
        except ValueError:
            pass
        else:
            raise AssertionError('Unsafe archive path accepted')
    status = {'BackendState': 'Running', 'Self': {'ID': 'ci01', 'UserID': 42, 'TailscaleIPs': ['100.66.1.2']},
              'Peer': {'key': {'ID': 'operator01', 'UserID': 42, 'Online': True}}}
    assert checked_identity(status, 'operator01') == ('ci01', '100.66.1.2')
    for fields in ({'UserID': 43}, {'UserID': '42'}, {'Tags': ['tag:ci']}, {'ID': 'operator01'}):
        changed = {**status, 'Self': {**status['Self'], **fields}}
        try:
            checked_identity(changed, 'operator01')
        except ValueError:
            pass
        else:
            raise AssertionError('Invalid CI identity accepted')
    assert checked_url('https://github.com/RiceM001/AgentRemote/releases/download/v2.1.29/test.zip')
    for url in ('http://github.com/RiceM001/AgentRemote/releases/download/v2.1.29/test.zip',
                'https://github.com.evil.test/RiceM001/AgentRemote/releases/download/v2.1.29/test.zip',
                'https://token@github.com/RiceM001/AgentRemote/releases/download/v2.1.29/test.zip',
                'https://github.com/RiceM001/AgentRemote/releases/download/v2.1.29/test.zip?token=secret',
                'https://github.com/another/repo/releases/download/v1/test.zip'):
        try:
            checked_url(url)
        except ValueError:
            pass
        else:
            raise AssertionError('Unsafe package URL accepted')
    from unittest.mock import Mock, patch
    process = Mock()
    process.poll.return_value = None
    with patch.object(subprocess, 'run', side_effect=[Mock(returncode=1), Mock(returncode=0)]) as run, \
            patch.object(time, 'monotonic', return_value=0), patch.object(time, 'sleep') as sleep:
        wait_authenticated_probe(['fixture-probe'], {}, process, 1, 0.25)
        assert run.call_count == 2 and sleep.call_count == 1
    with patch.object(subprocess, 'run', return_value=Mock(returncode=1)) as run, \
            patch.object(time, 'monotonic', side_effect=[0, 0.5, 1]), patch.object(time, 'sleep'):
        try:
            wait_authenticated_probe(['fixture-probe'], {}, process, 1, 0.25)
        except RuntimeError:
            pass
        else:
            raise AssertionError('Probe deadline ignored')
        assert run.call_count == 1
    process.poll.return_value = 1
    with patch.object(subprocess, 'run') as run, patch.object(time, 'monotonic', return_value=0):
        try:
            wait_authenticated_probe(['fixture-probe'], {}, process, 1, 0.25)
        except RuntimeError:
            pass
        else:
            raise AssertionError('Exited service accepted')
        assert not run.called
    print(json.dumps({'self_check': 'passed', 'network_used': False, 'processes_started': False}))


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError('Invalid CI arguments')


def run(result):
    parser = SafeParser()
    parser.add_argument('--preflight', action='store_true')
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--package-url', default=os.environ.get('AR_PACKAGE_URL', ''))
    parser.add_argument('--package-sha256', default=os.environ.get('AR_PACKAGE_SHA256', ''))
    parser.add_argument('--operator-node', default=os.environ.get('AR_OPERATOR_NODE', ''))
    parser.add_argument('--hold-seconds', type=int, default=int(os.environ.get('AR_HOLD_SECONDS', '1800')))
    parser.add_argument('--fixture-bytes', type=int, default=int(os.environ.get('AR_FIXTURE_BYTES', '67108864')))
    parser.add_argument('--poll-seconds', type=float, default=2)
    parser.add_argument('--request-timeout-seconds', type=int, default=30)
    args = parser.parse_args()
    result['stage'] = 'self_check'
    self_check()
    if args.apply and args.preflight:
        raise ValueError('Choose one execution mode')
    if not (args.apply or args.preflight):
        print(json.dumps({'plan': 'GitHub-hosted Windows only; fresh profile; normal pairing; file calls only'}))
        return
    result['stage'] = 'environment'
    if sys.version_info < (3, 11):
        raise RuntimeError('Host Python 3.11 or newer required')
    if not (os.name == 'nt' and os.environ.get('GITHUB_ACTIONS') == 'true'
            and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted' and os.environ.get('RUNNER_OS') == 'Windows'):
        raise ValueError('Refuse to bootstrap on a local or self-hosted computer')
    if not (re.fullmatch('[0-9a-f]{64}', args.package_sha256) and (args.preflight or re.fullmatch('[A-Za-z0-9]{1,64}', args.operator_node))
            and 30 <= args.hold_seconds <= 2700 and 0 < args.poll_seconds <= 10 and 1 <= args.request_timeout_seconds <= 120
            and 1 <= args.fixture_bytes <= 1073741824):
        raise ValueError('Invalid CI input')
    checked_url(args.package_url)
    nonce = uuid.uuid4().hex
    work = Path(os.environ['RUNNER_TEMP']).resolve() / ('agentremote-file-ci-' + nonce)
    work.mkdir()
    output = Path(os.environ['GITHUB_WORKSPACE']) / 'ci-output'
    write_json(output / 'boot-private.json', {'run_nonce': nonce, 'fixture_root': str(work / 'fixtures')})
    state_parent = work / 'profile'
    state_parent.mkdir()
    state = state_parent / 'WinRemotePersistent'
    env = {**os.environ, 'LOCALAPPDATA': str(state_parent), 'PYTHONUTF8': '1'}
    for name in ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy'):
        env.pop(name, None)
    cli = Path(os.environ['ProgramFiles']) / 'Tailscale/tailscale.exe'

    def ts_status():
        result = subprocess.run([str(cli), 'status', '--json'], capture_output=True, text=True,
                                encoding='utf-8', timeout=args.request_timeout_seconds, check=True)
        return json.loads(result.stdout)

    result['stage'] = 'identity'
    if not args.preflight:
        node, address = checked_identity(ts_status(), args.operator_node)
    result['stage'] = 'download'
    archive_path = work / 'reviewed-package.zip'
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(args.package_url, timeout=args.request_timeout_seconds) as response, archive_path.open('xb') as stream:
        while data := response.read(1024 * 1024):
            stream.write(data)
    with archive_path.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != args.package_sha256:
            raise ValueError('Reviewed package SHA256 mismatch')
    result['stage'] = 'package_manifest'
    unpack(archive_path, work / 'package')
    bundles = list((work / 'package').glob('*/app/resources'))
    if len(bundles) != 1:
        raise ValueError('Ambiguous package resources')
    bundle = bundles[0]
    manifest_files(bundle, json.loads((bundle / 'resources.json').read_text(encoding='utf-8-sig')))
    result['stage'] = 'runtime_manifest'
    unpack(bundle / 'remote.zip', work / 'runtime')
    roots = list((work / 'runtime').glob('*/manifest.json'))
    if len(roots) != 1:
        raise ValueError('Ambiguous runtime root')
    runtime = roots[0].parent
    manifest_files(runtime, json.loads(roots[0].read_text(encoding='utf-8-sig')))
    python = runtime / 'runtime/python.exe'
    result['stage'] = 'embedded_import'
    probe = '''import contextlib,io,json,sys
report = {'version': list(sys.version_info[:3]), 'passed': False}
try:
    with contextlib.redirect_stdout(io.StringIO()):
        sys.path.insert(0, sys.argv[1])
        import persistent, interactive_server
        assert persistent.config()
        assert interactive_server.server.mcp is not None
    report['passed'] = True
except Exception as error:
    report['error_type'] = type(error).__name__
print(json.dumps(report))
'''
    completed = subprocess.run([str(python), '-B', '-c', probe, str(runtime)], cwd=runtime,
                               env=env, capture_output=True, timeout=args.request_timeout_seconds)
    if completed.returncode:
        raise RuntimeError('Embedded import failed')
    embedded = json.loads(completed.stdout)
    version = embedded['version']
    if not isinstance(version, list) or len(version) != 3 or any(type(v) is not int or v < 0 for v in version):
        raise ValueError('Invalid embedded version')
    result['runtime_version']['embedded'] = version
    if embedded.get('passed') is not True:
        error_type = embedded.get('error_type', '')
        result['embedded_error_type'] = error_type if error_type in (
            'ImportError', 'ModuleNotFoundError', 'OSError', 'ValueError', 'RuntimeError',
            'AssertionError', 'AttributeError', 'TypeError', 'KeyError', 'FileNotFoundError') else 'EmbeddedImportError'
        raise RuntimeError('Embedded import failed')
    if args.preflight:
        result.update(passed=True, stage='complete', mode='preflight', package_sha256=args.package_sha256,
                      private_network_used=False, service_started=False, desktop_tool_calls=0)
        return
    result['stage'] = 'fixtures'
    settings = json.loads((bundle / 'installer-settings.json').read_text(encoding='utf-8-sig'))
    settings['operator_node_id'] = args.operator_node
    encoded = base64.b64encode(json.dumps(settings).encode()).decode()
    fixtures = work / 'fixtures'
    fixtures.mkdir()
    for name in ('incoming', 'outgoing'):
        (fixtures / name).mkdir()
    (fixtures / 'outgoing/中文😀.txt').write_text('独立 Windows 节点文件传输', encoding='utf-8')
    (fixtures / 'outgoing/zero.bin').touch()
    with (fixtures / 'outgoing/chunks.bin').open('xb') as stream:
        block = bytes(range(256)) * 4096
        remaining = args.fixture_bytes
        while remaining:
            piece = block[:remaining]
            stream.write(piece)
            remaining -= len(piece)
    timeout = settings['startup_timeout_seconds'] + settings['request_timeout_seconds']
    result['stage'] = 'pairing_preflight'
    for mode in ('preflight',):
        completed = subprocess.run([str(python), str(bundle / 'enroll-client.py'), mode, str(runtime), encoded],
                                env=env, capture_output=True, timeout=timeout)
        if completed.returncode:
            raise RuntimeError('Normal pairing preflight failed')
    process = None
    result.update(node_id=node, run_nonce=nonce)
    result['stage'] = 'worker_start'
    try:
        with (work / 'worker.log').open('wb') as log:
            process = subprocess.Popen([str(python), str(runtime / 'persistent.py'), '--serve'], cwd=runtime,
                                       env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                       creationflags=subprocess.CREATE_NO_WINDOW)
            deadline = time.monotonic() + timeout
            while not (state / 'connection.json').exists():
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError('CI-owned service failed to start')
                time.sleep(args.poll_seconds)
            wait_authenticated_probe([str(python), str(bundle / 'enroll-client.py'), 'probe', str(runtime), encoded],
                                     env, process, deadline, args.poll_seconds)
            result['stage'] = 'pair'
            completed = subprocess.run([str(python), str(bundle / 'enroll-client.py'), 'pair', str(runtime), encoded],
                                       env=env, capture_output=True, timeout=timeout)
            if completed.returncode:
                raise RuntimeError('Normal authenticated pairing failed: pair')
            ready = {'schema': 1, 'node_id': node, 'ipv4': address, 'same_user_verified': True,
                     'run_nonce': nonce, 'fixture_root': str(fixtures), 'package_sha256': args.package_sha256,
                     'hold_seconds': args.hold_seconds, 'fixture_bytes': args.fixture_bytes,
                     'desktop_tool_calls': 0}
            write_json(output / 'ready.json', ready)
            print('AGENTREMOTE_FILE_CI_READY ' + json.dumps(ready, ensure_ascii=True), flush=True)
            result['stage'] = 'controller_wait'
            deadline = time.monotonic() + args.hold_seconds
            while time.monotonic() < deadline:
                checked_identity(ts_status(), args.operator_node)
                if process.poll() is not None:
                    raise RuntimeError('CI-owned service exited')
                marker = fixtures / 'finished.json'
                if marker.exists():
                    controller = json.loads(marker.read_text(encoding='utf-8'))
                    if (controller.get('schema') != 1 or controller.get('run_nonce') != nonce
                            or controller.get('controller_completed') is not True or controller.get('passed') is not True):
                        raise ValueError('Controller result did not pass')
                    result['controller_result'] = controller
                    result['passed'] = True
                    break
                time.sleep(args.poll_seconds)
            else:
                raise TimeoutError('No completed controller result within the CI window')
    except Exception as error:
        result['error_type'] = type(error).__name__
        raise
    finally:
        try:
            if process is not None and process.poll() is None:
                (state / 'stop').touch()
                try:
                    process.wait(timeout=settings['shutdown_timeout_seconds'] + 15)
                except subprocess.TimeoutExpired:
                    process.terminate()
                    process.wait(timeout=settings['shutdown_timeout_seconds'] + 15)
        except Exception as error:
            result['cleanup_error_type'] = type(error).__name__
            result['passed'] = False
        try:
            result['fixture_sha256'] = {}
            for path in fixtures.rglob('*'):
                if path.is_file() and not path.is_symlink():
                    with path.open('rb') as stream:
                        result['fixture_sha256'][path.relative_to(fixtures).as_posix()] = hashlib.file_digest(stream, 'sha256').hexdigest()
        except Exception as error:
            result['fixture_error_type'] = type(error).__name__
            result['passed'] = False
        result['desktop_tool_calls'] = 0


def main():
    result = {'schema': 1, 'passed': False, 'stage': 'arguments',
              'runtime_version': {'host': list(sys.version_info[:3])}}
    output = None
    try:
        if os.environ.get('GITHUB_ACTIONS') == 'true':
            output = Path(os.environ['GITHUB_WORKSPACE']) / 'ci-output' / 'final.json'
            output.parent.mkdir(exist_ok=True)
        run(result)
    except BaseException as error:
        if isinstance(error, SystemExit) and error.code == 0:
            return 0
        result['error_type'] = type(error).__name__
        result['passed'] = False
    finally:
        if output is not None:
            write_json(output, result)
    if output is not None:
        print(json.dumps(result, ensure_ascii=True), flush=True)
        return 0 if result['passed'] else 1
    return 1 if 'error_type' in result else 0



if __name__ == '__main__':
    sys.exit(main())
