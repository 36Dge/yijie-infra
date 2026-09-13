#!/usr/bin/env python3
"""FEAT-153 explicit local lifecycle. Never deletes data volumes or force-stops processes."""
import argparse
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parent
GENERATED = ROOT / 'environments/local/generated/feat-153'
PRIVATE = GENERATED / 'private'
DOCKER_CONFIG = GENERATED / 'docker-cli'
LOGS = GENERATED / 'logs'
STATE = GENERATED / 'state.json'
EDITOR_BUNDLE = WORKSPACE / 'yijie-coze/bin/workflow-editor/dist'
EDITOR_OVERLAY = ROOT / 'compose/workflow-editor.yml'
PROJECT = 'yijie-feat153-workflow'
SERVICES = ['workflow-postgres', 'coze-workflow-mysql', 'coze-workflow-redis', 'coze-workflow-minio', 'coze-workflow', 'workflow-api']
DEPS = SERVICES[:4]
DOCKER_BUNDLES = [Path.home() / 'Applications/Docker.app', Path('/Applications/Docker.app')]
DOCKER_BUNDLE = next((bundle for bundle in DOCKER_BUNDLES if (bundle / 'Contents/Resources/bin/docker').is_file() and (bundle / 'Contents/Resources/cli-plugins/docker-compose').is_file()), DOCKER_BUNDLES[0])
DOCKER = str(DOCKER_BUNDLE / 'Contents/Resources/bin/docker')
COMPOSE = str(DOCKER_BUNDLE / 'Contents/Resources/cli-plugins/docker-compose')
SOCKET = 'unix://' + str(Path.home() / '.docker/run/docker.sock')

class WorkflowError(Exception):
    pass

def require(ok, text):
    if not ok:
        raise WorkflowError(text)

def private_write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.exists():
        secure_read(path)
    temporary = path.parent / ('.workflow-write-' + uuid.uuid4().hex)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'w') as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()

def secure_read(path, max_size=1048576):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'r') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= max_size, 'Private artifact owner/mode/size mismatch')
        return stream.read()

def write_json(path, value):
    private_write(path, json.dumps(value, indent=2, ensure_ascii=False) + '\n')

def read_state():
    require(STATE.is_file(), 'Run init first')
    state = json.loads(secure_read(STATE))
    require(isinstance(state, dict) and state.get('schema_version') == 1 and state.get('project') == PROJECT and state.get('dataset') == 'workflow-local-v1', 'Workflow state identity differs; no action taken')
    epoch = state.get('run_epoch')
    require(isinstance(epoch, str) and str(uuid.UUID(epoch)) == epoch and uuid.UUID(epoch).int != 0, 'Workflow state epoch is invalid')
    return state

def environment():
    env = os.environ.copy()
    for key in ['DOCKER_CONTEXT', 'DOCKER_HOST', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH']:
        env.pop(key, None)
    env['DOCKER_CONFIG'] = str(DOCKER_CONFIG)
    env['DOCKER_HOST'] = SOCKET
    env['PATH'] = str(Path(DOCKER).parent) + os.pathsep + env.get('PATH', '')
    return env

def docker_args(args):
    return [DOCKER, '--config', str(DOCKER_CONFIG), '--host', SOCKET, *args]

def output(args):
    result = subprocess.run(docker_args(args), env=environment(), capture_output=True, text=True)
    require(result.returncode == 0, 'Docker read failed; check original local Docker Desktop')
    return result.stdout

def run_logged(args, label, compose=False, state=None):
    LOGS.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = LOGS / (label + '.txt')
    print('START', label, flush=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as out:
        command = args if compose else docker_args(args)
        process = subprocess.Popen(command, env=environment(), stdout=out, stderr=subprocess.STDOUT, start_new_session=True)
        if state is not None:
            state['active_child'] = {'pid': process.pid, 'label': label, 'run_epoch': state['run_epoch']}
            write_json(STATE, state)
        # Normal completion only; no subprocess timeout that kills a child.
        while True:
            try:
                code = process.wait()
                break
            except KeyboardInterrupt:
                print('PENDING: child continues normally; waiting before recording owned container IDs', flush=True)
        if state is not None:
            state.pop('active_child', None)
            write_json(STATE, state)
    print('END', label, 'exit', code, flush=True)
    return code

def run_owned(args, label, state, compose=False):
    try:
        return run_logged(args, label, compose, state)
    finally:
        # run_logged retains the controller lock until the child has finished.
        record(state, allow_new=True)

def compose_args(args):
    files = ['-f', str(ROOT / 'compose/workflow-local.yml')]
    if read_state().get('editor') is not None:
        files += ['-f', str(EDITOR_OVERLAY)]
    return [COMPOSE, '--project-name', PROJECT, '--env-file', str(GENERATED / 'compose.env'), *files, *args]

def all_containers():
    ids = output(['ps', '-aq', '--filter', 'label=com.docker.compose.project=' + PROJECT]).split()
    if not ids:
        return []
    # Inspect is parsed privately; Config.Env is never printed or stored.
    result = []
    for item in json.loads(output(['inspect', *ids])):
        result.append({'id': item['Id'], 'name': item['Name'].lstrip('/'), 'image_id': item['Image'], 'labels': item['Config']['Labels'], 'state': {k: item['State'].get(k) for k in ['Status', 'Running', 'ExitCode', 'OOMKilled', 'StartedAt', 'FinishedAt']}, 'health': item['State'].get('Health', {}).get('Status'), 'mounts': [{'type': m['Type'], 'source': m.get('Name', m['Source']), 'target': m['Destination'], 'rw': m['RW']} for m in item['Mounts']]})
    return result

def expected_image(service, state):
    image_name = {'workflow-postgres': 'postgres', 'coze-workflow-mysql': 'mysql', 'coze-workflow-redis': 'redis', 'coze-workflow-minio': 'minio'}.get(service)
    build_name = {'workflow-api': 'api', 'workflow-pg-test': 'api-test'}.get(service, 'coze')
    return pins()[image_name]['image_id'] if image_name else state.get('built', {}).get(build_name, {}).get('image_id')

def validate_owned(items, state, allow_new=False):
    prior = {i['id']: i for i in state.get('containers', [])}
    for item in items:
        labels = item['labels']
        service = labels.get('com.docker.compose.service')
        require(labels.get('com.docker.compose.project') == PROJECT and service in [*SERVICES, 'workflow-pg-test'], 'Unexpected project or service; no action taken')
        recorded = prior.get(item['id'])
        # A stopped, recorded container retains its original immutable image after
        # build records a newer candidate. This permits normal cleanup, not readiness.
        expected = recorded['image_id'] if recorded is not None else expected_image(service, state)
        if recorded is not None:
            require(recorded['labels'].get('com.docker.compose.service') == service, 'Recorded container service differs; no action taken')
        require(item['image_id'] == expected, 'Unexpected container image; no action taken')
        require(labels.get('ai.yijie.feature') == 'FEAT-153' and labels.get('ai.yijie.dataset') == 'workflow-local-v1' and labels.get('ai.yijie.run-epoch') == state['run_epoch'], 'Unexpected container ownership; no action taken')
        require(allow_new or item['id'] in prior, 'Unknown container ID; refusing to adopt it')

def record(state, allow_new=False):
    items = all_containers()
    validate_owned(items, state, allow_new)
    state['containers'] = items
    write_json(STATE, state)
    return items

def candidate(repo):
    paths = subprocess.check_output(['git', '-C', str(repo), 'ls-files', '--cached', '--others', '--exclude-standard', '-z']).decode().split('\0')
    h = hashlib.sha256()
    for rel in sorted(set(filter(None, paths))):
        p = repo / rel
        if p.is_file():
            h.update(rel.encode() + b'\0' + hashlib.sha256(p.read_bytes()).digest())
    return h.hexdigest()

def public_bytes(path, limit):
    # Public build artifacts use ordinary file permissions, never private-file rules.
    require(path.is_absolute() and path.resolve() == path, 'Editor artifact path must be fixed and without symlinks')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= limit, 'Editor artifact is not a bounded regular file')
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
        current = path.lstat()
    signature = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns, item.st_mode)
    require(signature(before) == signature(after) == signature(current) and len(data) == before.st_size, 'Editor artifact changed while being read')
    return data

def editor_snapshot(state):
    node = shutil.which('node')
    require(node is not None, 'Node is required for canonical editor source checks')
    coze = WORKSPACE / 'yijie-coze'
    contracts = WORKSPACE / 'yijie-contracts'
    sampled_candidate = candidate(coze)
    schema = json.loads(public_bytes(WORKSPACE / 'yijie-api/config/workflow-editor-assets.schema.json', 262144))
    limits = schema['x-limits']
    raw = public_bytes(EDITOR_BUNDLE / 'manifest.json', limits['manifest_bytes'])
    manifest = json.loads(raw)
    require(isinstance(manifest, dict) and set(manifest) == set(schema['required']), 'Editor manifest fields differ from the API deployment authority')
    for name, spec in schema['properties'].items():
        value = manifest[name]
        if 'const' in spec:
            require(type(value) is type(spec['const']) and value == spec['const'], 'Editor manifest identity differs')
        if 'pattern' in spec:
            require(isinstance(value, str) and re.fullmatch(spec['pattern'], value) is not None, 'Editor manifest source identity is invalid')
    files_spec = schema['properties']['files']
    files = manifest['files']
    require(isinstance(files, list) and files_spec['minItems'] <= len(files) <= files_spec['maxItems'], 'Editor asset count differs from the deployment authority')
    mime = {'.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.webp': 'image/webp', '.woff': 'font/woff', '.woff2': 'font/woff2', '.ttf': 'font/ttf', '.ico': 'image/x-icon'}
    total = 0
    seen = set()
    entry = None
    fields = files_spec['items']['properties']
    for asset in files:
        require(isinstance(asset, dict) and set(asset) == set(files_spec['items']['required']), 'Editor asset fields differ')
        rel = asset['path']
        require(isinstance(rel, str) and len(rel) <= fields['path']['maxLength'] and re.fullmatch(fields['path']['pattern'], rel) is not None and rel not in seen, 'Editor asset path differs')
        seen.add(rel)
        require(type(asset['bytes']) is int and fields['bytes']['minimum'] <= asset['bytes'] <= fields['bytes']['maximum'], 'Editor asset size differs')
        require(isinstance(asset['sha256'], str) and re.fullmatch(fields['sha256']['pattern'], asset['sha256']) is not None, 'Editor asset digest is invalid')
        require(asset['content_type'] in fields['content_type']['enum'] and asset['content_type'] == mime.get(Path(rel).suffix), 'Editor asset MIME differs')
        total += asset['bytes']
        require(total <= limits['total_asset_bytes'], 'Editor bundle exceeds the deployment byte budget')
        content = public_bytes(EDITOR_BUNDLE / rel, fields['bytes']['maximum'])
        require(len(content) == asset['bytes'] and hashlib.sha256(content).hexdigest() == asset['sha256'], 'Editor asset bytes differ from the manifest')
        if rel == limits['required_entry']:
            entry = asset
    require(entry is not None, 'Editor entry is missing')
    source_hash = hashlib.sha256(public_bytes(contracts / 'compatibility/workflow-local/source.lock.json', 1048576)).hexdigest()
    require(manifest['contracts_lock_sha256'] == source_hash, 'Editor producer source lock differs')
    consumer_hashes = {}
    for consumer in ['api', 'coze', 'desktop']:
        command = [node, str(contracts / 'scripts/sync-workflow-consumer.mjs'), consumer, '--check']
        require(run_logged(command, 'editor-check-' + consumer, True, state) == 0, 'Canonical workflow consumer differs: ' + consumer)
        repo = WORKSPACE / ('yijie-' + consumer)
        consumer_hashes[consumer] = hashlib.sha256(public_bytes(repo / 'contracts/workflow-local.lock.json', 1048576)).hexdigest()
        if consumer in ['api', 'coze']:
            require(hashlib.sha256(public_bytes(repo / 'contracts/workflow-local.source-lock.json', 1048576)).hexdigest() == source_hash, 'Copied producer lock differs')
    command = [node, str(coze / 'scripts/yijie/workflow-editor.mjs'), 'check']
    require(run_logged(command, 'editor-check-bundle', True, state) == 0, 'Canonical editor bundle check failed; no build or activation performed')
    commit = subprocess.check_output(['git', '-C', str(coze), 'rev-parse', 'HEAD']).decode().strip()
    require(manifest['source_commit'] == commit and candidate(coze) == sampled_candidate, 'Editor source changed during registration checks')
    require(public_bytes(EDITOR_BUNDLE / 'manifest.json', limits['manifest_bytes']) == raw, 'Editor manifest changed during registration checks')
    require(hashlib.sha256(public_bytes(contracts / 'compatibility/workflow-local/source.lock.json', 1048576)).hexdigest() == source_hash, 'Producer source lock changed during registration checks')
    # These are independently observed fields, even if current producer and Infra
    # candidate algorithms happen to produce the same digest.
    return {'schema_version': 1, 'bundle_dir': str(EDITOR_BUNDLE), 'manifest_sha256': hashlib.sha256(raw).hexdigest(), 'source_commit': commit, 'manifest_source_digest': manifest['source_digest'], 'coze_candidate': sampled_candidate, 'contracts_source_lock_sha256': source_hash, 'consumer_lock_sha256': consumer_hashes, 'deployment_schema_sha256': hashlib.sha256(public_bytes(WORKSPACE / 'yijie-api/config/workflow-editor-assets.schema.json', 262144)).hexdigest(), 'file_count': len(files), 'total_asset_bytes': total, 'entry': entry}

def verify_editor(state):
    registered = state.get('editor')
    if registered is None:
        return
    require(editor_snapshot(state) == registered, 'Registered editor bundle or source drifted; stop normally and explicitly register the reviewed bundle before rebuilding')

def editor():
    state = read_state()
    items = record(state)
    require(state['phase'] == 'stopped' and not any(c['state']['Running'] or c['state']['OOMKilled'] or c['state']['ExitCode'] != 0 for c in items), 'Editor registration requires the normally stopped owned stack')
    registered = editor_snapshot(state)
    if state.get('editor') != registered:
        state.setdefault('editor_registrations', []).append({'registered_at_ms': int(time.time() * 1000), 'run_epoch': state['run_epoch'], **registered})
    state['editor'] = registered
    write_json(STATE, state)
    render(state)
    print('EDITOR_REGISTERED: reviewed public bundle recorded; no images built or services started')

def observed_editor(state):
    registered = state.get('editor')
    if registered is None:
        return True
    connection = http.client.HTTPConnection('127.0.0.1', 18888, timeout=3)
    try:
        connection.request('GET', '/editor/', headers={'Accept': 'text/html'})
        response = connection.getresponse()
        entry = registered['entry']
        body = response.read(entry['bytes'] + 1)
        headers = {'Content-Type': entry['content_type'], 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'none'; worker-src 'none'; frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors http://localhost:1420 tauri://localhost"}
        return response.status == 200 and len(body) == entry['bytes'] and hashlib.sha256(body).hexdigest() == entry['sha256'] and all(response.getheader(name) == value for name, value in headers.items())
    finally:
        connection.close()

def pins():
    return json.loads((ROOT / 'config/workflow-local/images.lock.json').read_text())['images']

def verify_images():
    for name, item in pins().items():
        local = json.loads(output(['image', 'inspect', item['image_id']]))[0]
        versioned, digest = item['reference'].split('@', 1)
        repository = versioned.rsplit(':', 1)[0]
        require(local['Id'] == item['image_id'] and local['Architecture'] == 'arm64' and local['Os'] == 'linux', 'Image pin differs: ' + name)
        require(versioned in local.get('RepoTags', []) and repository + '@' + digest in local.get('RepoDigests', []), 'Image version or registry digest differs: ' + name)

def credential_pair(state):
    result = []
    for name in ['k-na.json', 'k-ac.json']:
        item = json.loads(secure_read(PRIVATE / name, 1024))
        require(isinstance(item, dict) and set(item) == {'schema_version', 'run_epoch', 'token'} and item['schema_version'] == 1 and item['run_epoch'] == state['run_epoch'], 'Credential epoch differs from recorded state; no activation')
        token = item['token']
        require(isinstance(token, str) and len(token) == 64 and all(c in '0123456789abcdef' for c in token), 'Credential format differs; no activation')
        result.append(item)
    require(result[0]['token'] != result[1]['token'], 'Native and Coze credentials must remain separate')
    return result

def complete_credentials(state):
    if state.get('credentials_pending'):
        require(not any(c['state']['Running'] for c in record(state)), 'Credential rotation requires all owned processes to be stopped')
        credentials(state, rotate=True)
        credential_pair(state)
        state['credentials_pending'] = False
        write_json(STATE, state)
    else:
        credential_pair(state)

def require_free_port():
    sock = socket.socket()
    try:
        sock.bind(('127.0.0.1', 18888))
    except OSError:
        raise WorkflowError('Port 18888 is occupied; its process is left untouched')
    finally:
        sock.close()

def observed_ready(state, items):
    for service in SERVICES:
        primary = [c for c in items if c['labels'].get('com.docker.compose.service') == service and str(c['labels'].get('com.docker.compose.oneoff', 'false')).lower() != 'true']
        if len(primary) != 1 or not primary[0]['state']['Running'] or primary[0]['health'] != 'healthy' or primary[0]['state']['OOMKilled'] or primary[0]['image_id'] != expected_image(service, state):
            return False
    if state.get('credentials_pending'):
        return False
    try:
        native, _ = credential_pair(state)
        connection = http.client.HTTPConnection('127.0.0.1', 18888, timeout=3)
        try:
            connection.request('GET', '/v1/workflow-local/status', headers={'Authorization': 'Bearer ' + native['token'], 'X-Yijie-Run-Epoch': state['run_epoch'], 'Accept': 'application/json'})
            response = connection.getresponse()
            body = response.read(524289)
            if response.status != 200 or len(body) > 524288 or response.getheader('Content-Type', '').split(';')[0].strip() != 'application/json':
                return False
            status = json.loads(body)
            return status.get('protocol_version') == 1 and status.get('run_epoch') == state['run_epoch'] and status.get('ready') is True and status.get('state') == 'ready' and observed_editor(state)
        finally:
            connection.close()
    except (WorkflowError, OSError, ValueError, http.client.HTTPException):
        return False

def credentials(state, rotate=False):
    PRIVATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    for name in ['postgres-password', 'mysql-password', 'mysql-root-password', 'redis-password', 'minio-secret']:
        path = PRIVATE / name
        if not path.exists():
            private_write(path, secrets.token_hex(32))
    if not (PRIVATE / 'minio-access').exists():
        private_write(PRIVATE / 'minio-access', 'workflow' + secrets.token_hex(8))
    for name in ['k-na.json', 'k-ac.json']:
        if rotate or not (PRIVATE / name).exists():
            write_json(PRIVATE / name, {'schema_version': 1, 'run_epoch': state['run_epoch'], 'token': secrets.token_hex(32)})
    pg = secure_read(PRIVATE / 'postgres-password')
    mysql = secure_read(PRIVATE / 'mysql-password')
    redis = secure_read(PRIVATE / 'redis-password')
    private_write(PRIVATE / 'postgres-dsn', f'postgres://workflow:{pg}@workflow-postgres:5432/yijie_workflow_local?sslmode=disable')
    private_write(PRIVATE / 'mysql-dsn', f'workflow:{mysql}@tcp(coze-workflow-mysql:3306)/coze_workflow_local?charset=utf8mb4&parseTime=true')
    private_write(PRIVATE / 'redis.conf', 'bind 0.0.0.0\nport 6379\nprotected-mode yes\nappendonly yes\nappendfsync everysec\nsave 60 1\ndir /data\nrequirepass ' + redis + '\n')

def render(state):
    images = pins()
    built = state.get('built', {})
    values = {'WORKFLOW_EPOCH': state['run_epoch'], 'WORKFLOW_PRIVATE': str(PRIVATE), 'WORKFLOW_GENERATED': str(GENERATED), 'WORKFLOW_UID': str(os.getuid()), 'WORKFLOW_GID': str(os.getgid()), 'API_IMAGE': built.get('api', {}).get('image_id', 'not-built'), 'COZE_IMAGE': built.get('coze', {}).get('image_id', 'not-built')}
    values.update({name.upper() + '_IMAGE': images[name]['reference'] for name in ['postgres', 'mysql', 'redis', 'minio']})
    if state.get('editor') is not None:
        values.update({'WORKFLOW_EDITOR_BUNDLE': state['editor']['bundle_dir'], 'WORKFLOW_EDITOR_MANIFEST_SHA256': state['editor']['manifest_sha256']})
    private_write(GENERATED / 'compose.env', ''.join(f'{k}={v}\n' for k, v in values.items()))

def init():
    GENERATED.mkdir(parents=True, exist_ok=True, mode=0o700)
    # An empty named auth entry prevents automatic credential-helper discovery.
    write_json(DOCKER_CONFIG / 'config.json', {'auths': {'https://index.docker.io/v1/': {}, 'quay.io': {}}, 'cliPluginsExtraDirs': [str(Path(COMPOSE).parent)]})
    if STATE.exists():
        state = read_state()
        validate_owned(all_containers(), state)
        complete_credentials(state)
        print('Existing data set retained; no secrets rotated')
        return
    require(not all_containers(), 'Existing unrecorded workflow project; refusing to adopt it')
    baseline = []
    ids = output(['ps', '-aq']).split()
    if ids:
        for c in json.loads(output(['inspect', *ids])):
            baseline.append({'id': c['Id'], 'name': c['Name'], 'status': c['State']['Status'], 'started_at': c['State']['StartedAt'], 'finished_at': c['State']['FinishedAt']})
    require(not PRIVATE.exists() or not any(PRIVATE.iterdir()), 'Unrecorded private files exist; inspect before initialization')
    state = {'schema_version': 1, 'project': PROJECT, 'dataset': 'workflow-local-v1', 'run_epoch': str(uuid.uuid4()), 'phase': 'initializing', 'credentials_pending': True, 'containers': [], 'other_containers_before': baseline}
    write_json(STATE, state)
    complete_credentials(state)
    sql = GENERATED / 'upstream-schema.sql'
    if not sql.exists():
        subprocess.run([sys.executable, str(WORKSPACE / 'yijie-coze/scripts/yijie/prepare-workflow-schema.py'), '--output', str(sql)], check=True)
    render(state)
    state['phase'] = 'initialized'
    write_json(STATE, state)
    print('Initialized separate local data set and private files; values not displayed')

def build():
    state = read_state()
    require(not any(c['state']['Running'] for c in record(state)), 'Stop the owned stack normally before building a new candidate')
    verify_editor(state)
    verify_images()
    go_image = pins()['go']['reference']
    for name, repo, dockerfile, target in [('api', 'yijie-api', 'Dockerfile.workflow-local', 'workflow-runtime'), ('api-test', 'yijie-api', 'Dockerfile.workflow-local', 'workflow-test-runner'), ('coze', 'yijie-coze', 'docker/workflow-local/Dockerfile', None)]:
        folder = WORKSPACE / repo
        digest = candidate(folder)
        tag = 'yijie-local/feat153-' + name + ':' + digest[:16]
        args = ['build', '--build-arg', 'GO_IMAGE=' + go_image, '--label', 'ai.yijie.feature=FEAT-153', '--label', 'ai.yijie.source-digest=' + digest, '-f', str(folder / dockerfile), '-t', tag]
        if target:
            args += ['--target', target]
        args.append(str(folder))
        require(run_logged(args, 'build-' + name, state=state) == 0, 'Build failed: ' + name)
        require(candidate(folder) == digest, 'Source changed during build; inspect before activation')
        item = json.loads(output(['image', 'inspect', tag]))[0]
        state.setdefault('built', {})[name] = {'image_id': item['Id'], 'source_digest': digest, 'repository': repo, 'local_tag': tag, 'go_image': go_image}
        write_json(STATE, state)
    verify_editor(state)
    render(state)
    print('Built and recorded exact local image IDs; no services started')

def up():
    state = read_state()
    verify_editor(state)
    verify_images()
    for name in ['api', 'api-test', 'coze']:
        build = state.get('built', {}).get(name)
        repo = 'yijie-coze' if name == 'coze' else 'yijie-api'
        require(build and build['repository'] == repo and build['source_digest'] == candidate(WORKSPACE / repo), 'Missing or changed build candidate: ' + name)
    current = record(state)
    if any(c['state']['Running'] for c in current):
        require(state['phase'] == 'ready' and observed_ready(state, current), 'A partial or unhealthy stack is running; inspect or stop normally before retry')
        status()
        return
    require(not any(c['state']['OOMKilled'] or c['state']['ExitCode'] != 0 for c in current), 'Abnormal owned containers retained; inspect before reopening')
    require_free_port()
    complete_credentials(state)
    if current:
        require(output(['rm', *[c['id'] for c in current]]) is not None, 'Could not remove stopped owned containers')
        state['containers'] = []
        state['run_epoch'] = str(uuid.uuid4())
        state['phase'] = 'preparing'
        state['credentials_pending'] = True
        state.pop('pending_stop', None)
        write_json(STATE, state)
        complete_credentials(state)
    state['phase'] = 'starting'
    write_json(STATE, state)
    render(state)
    require(run_logged(compose_args(['config', '--quiet']), 'compose-config', True, state) == 0, 'Compose configuration is invalid')
    code = run_owned(compose_args(['up', '-d', '--no-recreate', '--pull', 'never', '--wait', '--wait-timeout', '180', *DEPS]), 'dependencies-up', state, True)
    require(code == 0, 'Dependency readiness pending; no containers forced off')
    for service, command, label in [('coze-workflow', ['-migrate-local'], 'coze-migrate'), ('workflow-api', ['/usr/local/bin/workflow-local-migrate', 'up'], 'api-migrate')]:
        args = ['run', '--no-deps', '--pull', 'never', '--name', PROJECT + '-' + label + '-' + state['run_epoch'][:8], service, *command]
        code = run_owned(compose_args(args), label, state, True)
        require(code == 0, label + ' failed; retained own container and data')
    for service in ['coze-workflow', 'workflow-api']:
        code = run_owned(compose_args(['up', '-d', '--no-deps', '--no-recreate', '--pull', 'never', '--wait', '--wait-timeout', '120', service]), service + '-up', state, True)
        require(code == 0, service + ' not ready; normal inspection required')
    verify_editor(state)
    state['phase'] = 'ready'
    record(state)
    require(status(), 'Host authenticated readiness is not available; owned services retained for inspection')

def status():
    state = read_state()
    items = record(state)
    ready = state['phase'] == 'ready' and observed_ready(state, items)
    phase = 'not_ready' if state['phase'] == 'ready' and not ready else state['phase']
    print(json.dumps({'project': PROJECT, 'phase': phase, 'ready': ready, 'run_epoch': state['run_epoch'], 'containers': [{'name': c['name'], 'service': c['labels'].get('com.docker.compose.service'), 'state': c['state'], 'health': c['health']} for c in items]}, indent=2))
    return ready

def qualify_pg(evidence_path):
    state = read_state()
    items = record(state)
    require(state['phase'] == 'ready' and observed_ready(state, items), 'PG qualification requires the normally ready owned stack and authenticated host gateway')
    require(not any(c['state']['Running'] and c['labels'].get('com.docker.compose.service') == 'workflow-pg-test' for c in items), 'A PG qualification is still running; wait for its normal completion')
    require(all(any(c['state']['Running'] and c['health'] == 'healthy' and c['labels'].get('com.docker.compose.service') == service for c in items) for service in SERVICES), 'Owned stack is not fully healthy; PG qualification not started')
    artifact = Path(evidence_path)
    require(artifact.is_absolute() and str(artifact) == os.path.normpath(evidence_path), 'Qualification evidence path must be absolute and clean')
    raw = secure_read(artifact, 524288)
    evidence = json.loads(raw)
    require(evidence.get('schema_version') == 1 and evidence.get('complete') is True, 'A completed real HTTP qualification artifact is required')
    workflow_id = evidence.get('workflow', {}).get('workflow_id')
    require(isinstance(workflow_id, str) and workflow_id.isascii() and workflow_id.isdigit() and 0 < len(workflow_id) <= 19 and workflow_id[0] != '0' and int(workflow_id) <= 9223372036854775807, 'HTTP evidence workflow identity is invalid')
    require(len(evidence.get('runs', [])) == 4 and all(r.get('workflow_id') == workflow_id and r.get('terminal') is True and r.get('state') == 'succeeded' for r in evidence['runs']), 'HTTP artifact does not contain the four actual successful normal runs')
    build = state.get('built', {}).get('api-test')
    require(build and build.get('repository') == 'yijie-api' and build['source_digest'] == candidate(WORKSPACE / 'yijie-api'), 'PG runner build is missing or source changed; inspect before qualification')
    network = PROJECT + '_workflow-private'
    inspected = json.loads(output(['network', 'inspect', network]))
    require(len(inspected) == 1 and inspected[0].get('Internal') is True and inspected[0].get('Labels', {}).get('com.docker.compose.project') == PROJECT and inspected[0].get('Labels', {}).get('com.docker.compose.network') == 'workflow-private', 'Dedicated internal workflow network identity differs')
    for name, limit in [('k-na.json', 1024), ('k-ac.json', 1024), ('postgres-dsn', 4096)]:
        secure_read(PRIVATE / name, limit)
    suffix = state['run_epoch'][:8] + '-' + uuid.uuid4().hex[:8]
    name = PROJECT + '-pg-test-' + suffix
    label = 'qualify-pg-' + suffix
    args = ['run', '--name', name, '--pull', 'never', '--restart', 'no', '--user', str(os.getuid()) + ':' + str(os.getgid()), '--network', network, '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--memory', '2g', '--cpus', '2', '--pids-limit', '256', '--tmpfs', '/tmp:rw,exec,nosuid,nodev,size=1g,mode=1777']
    for key, value in {'com.docker.compose.project': PROJECT, 'com.docker.compose.service': 'workflow-pg-test', 'ai.yijie.feature': 'FEAT-153', 'ai.yijie.dataset': 'workflow-local-v1', 'ai.yijie.run-epoch': state['run_epoch']}.items():
        args += ['--label', key + '=' + value]
    for source in ['k-na.json', 'k-ac.json', 'postgres-dsn']:
        args += ['--mount', 'type=bind,src=' + str(PRIVATE / source) + ',dst=/run/workflow-private/' + source + ',readonly']
    values = {'YIJIE_ENV': 'local', 'YIJIE_LOCAL_PROFILE': 'demo_fast', 'YIJIE_WORKFLOW_ENABLED': 'true', 'YIJIE_API_SERVICE_PROFILE': 'feat-153-workflow-local', 'YIJIE_WORKFLOW_NETWORK_SCOPE': 'container', 'YIJIE_WORKFLOW_CREDENTIAL_FILE': '/run/workflow-private/k-na.json', 'YIJIE_WORKFLOW_COZE_CREDENTIAL_FILE': '/run/workflow-private/k-ac.json', 'YIJIE_WORKFLOW_POSTGRES_DSN_FILE': '/run/workflow-private/postgres-dsn', 'YIJIE_WORKFLOW_COZE_URL': 'http://coze-workflow:18889', 'YIJIE_WORKFLOW_PG_QUALIFICATION': 'normal', 'YIJIE_WORKFLOW_QUALIFICATION_WORKFLOW_ID': workflow_id, 'GOTOOLCHAIN': 'local', 'CGO_ENABLED': '1', 'GOCACHE': '/tmp/workflow-go-build', 'GOPROXY': 'off', 'GOSUMDB': 'off'}
    for key, value in values.items():
        args += ['--env', key + '=' + value]
    args.append(build['image_id'])
    qualification = {'name': name, 'run_epoch': state['run_epoch'], 'workflow_id': workflow_id, 'evidence_path': str(artifact), 'evidence_sha256': hashlib.sha256(raw.encode()).hexdigest(), 'image_id': build['image_id'], 'source_digest': build['source_digest'], 'private_log': str(LOGS / (label + '.txt')), 'result': 'pending'}
    state.setdefault('pg_qualifications', []).append(qualification)
    write_json(STATE, state)
    code = None
    try:
        # No --rm and no timeout. Retain the test container and private output.
        code = run_logged(args, label, state=state)
    finally:
        final_items = record(state, allow_new=True)
        own = [c for c in final_items if c['name'] == name]
        qualification['command_exit_code'] = code
        qualification['container_ids'] = [c['id'] for c in own]
        if code == 0 and len(own) == 1 and not own[0]['state']['Running'] and own[0]['state']['ExitCode'] == 0 and not own[0]['state']['OOMKilled']:
            qualification['result'] = 'pass'
        elif code is not None:
            qualification['result'] = 'failed'
        write_json(STATE, state)
    require(qualification['result'] == 'pass', 'PG qualification did not pass; retained test container, data and private evidence')
    print('PG_QUALIFICATION_PASS: normal fixed-scope storage checks completed; test container retained')

def stop():
    state = read_state()
    items = record(state)
    state['phase'] = 'stopping'
    write_json(STATE, state)
    # Test runners finish naturally before API/dependencies stop. Never send a
    # stop signal to a running qualification or restart it after a timeout.
    deadline = time.monotonic() + 20
    while any(c['state']['Running'] and c['labels'].get('com.docker.compose.service') == 'workflow-pg-test' for c in items):
        if time.monotonic() >= deadline:
            print('STOP_PENDING: PG qualification is still finishing normally; API and dependencies retained')
            return
        time.sleep(0.5)
        items = record(state)
    # Dependencies stay alive until the real Coze engine has exited normally.
    for stage in [['workflow-api'], ['coze-workflow'], DEPS]:
        items = record(state)
        targets = [c['id'] for c in items if c['state']['Running'] and c['labels'].get('com.docker.compose.service') in stage]
        if not targets:
            continue
        pending = state.get('pending_stop')
        if pending and any(i in pending['containers'] for i in targets):
            print('STOP_PENDING: prior normal stop still draining; dependencies retained')
            return
        path = LOGS / ('stop-' + stage[0] + '.txt')
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, 'w') as log:
            # This is the documented non-forcing stop: SIGTERM, infinite grace.
            process = subprocess.Popen(docker_args(['stop', '--signal', 'SIGTERM', '--timeout', '-1', *targets]), env=environment(), stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            state['pending_stop'] = {'pid': process.pid, 'containers': targets}
            write_json(STATE, state)
            try:
                code = process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                print('STOP_PENDING: normal stop remains in progress; no forced termination')
                return
        require(code == 0, 'Normal stop did not complete; inspect retained state')
        state.pop('pending_stop', None)
        record(state)
    require(not any(c['state']['Running'] or c['state']['OOMKilled'] or c['state']['ExitCode'] != 0 for c in record(state)), 'Containers retained; inspect nonzero exit or OOM before claiming normal stop')
    state['phase'] = 'stopped'
    state.pop('pending_stop', None)
    record(state)
    print('STOPPED: owned containers exited normally; named volumes and other projects retained')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['init', 'editor', 'build', 'up', 'status', 'stop', 'qualify-pg'])
    parser.add_argument('--evidence', help='absolute completed normal HTTP qualification artifact; only for qualify-pg')
    args = parser.parse_args()
    require(Path(DOCKER).is_file() and Path(COMPOSE).is_file(), 'Original Docker Desktop tools were not found in either Applications location')
    require(bool(args.evidence) == (args.action == 'qualify-pg'), '--evidence is required only for qualify-pg')
    GENERATED.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(GENERATED / 'controller.lock', os.O_RDWR | os.O_CREAT, 0o600)
    with os.fdopen(fd, 'w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise WorkflowError('Another workflow lifecycle command is active')
        if args.action == 'qualify-pg':
            qualify_pg(args.evidence)
        else:
            globals()[args.action]()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('WORKFLOW: PENDING; child operation continues in its own session; inspect state before another action', file=sys.stderr)
        sys.exit(130)
    except WorkflowError as err:
        print('WORKFLOW:', str(err), file=sys.stderr)
        sys.exit(1)
    except Exception:
        print('WORKFLOW: operation did not complete; private state retained, inspect before retry', file=sys.stderr)
        sys.exit(1)
