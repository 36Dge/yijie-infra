"""Explicit recovery of recorded local containers; old failures remain evidence."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import time
import uuid

API_POLICY = 'yijie-api/internal/modules/workflows/infrastructure/postgres/operations/recovery_read.py'
COZE_POLICY = 'yijie-coze/backend/domain/workflow/localadapter/recovery_read.py'
API_SQL = 'yijie-api/internal/modules/workflows/infrastructure/postgres/operations/recovery-read.sql'
COZE_SQL = 'yijie-coze/backend/domain/workflow/localadapter/recovery-read.sql'
DATA_TARGETS = {'workflow-postgres': '/var/lib/postgresql/data', 'coze-workflow-mysql': '/var/lib/mysql', 'coze-workflow-redis': '/data', 'coze-workflow-minio': '/data'}


def digest(value):
    return hashlib.sha256(value).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def immutable_json(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as out:
        json.dump(value, out, ensure_ascii=False, indent=2)
        out.write('\n')
        out.flush()
        os.fsync(out.fileno())


def event(folder, name, **values):
    path = folder / 'events.jsonl'
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as out:
        out.write(json.dumps({'at_ms': int(time.time() * 1000), 'event': name, **values}, sort_keys=True) + '\n')
        out.flush()
        os.fsync(out.fileno())


def select_primaries(ctl, items):
    result = {}
    for service in ctl.SERVICES:
        candidates = [c for c in items if c['labels'].get('com.docker.compose.service') == service and str(c['labels'].get('com.docker.compose.oneoff', 'false')).lower() == 'false']
        ctl.require(len(candidates) == 1, 'Recovery requires exactly one recorded primary: ' + service)
        result[service] = candidates[0]
    return result


def identities(ctl, items):
    details = json.loads(ctl.output(['inspect', *[c['id'] for c in items]]))
    result = {}
    for item in details:
        # Hash private configuration in memory; never persist Config.Env values.
        result[item['Id']] = {'image_id': item['Image'], 'configuration_sha256': digest(canonical({'config': item['Config'], 'host': item['HostConfig']})), 'networks': {name: v['NetworkID'] for name, v in item['NetworkSettings']['Networks'].items()}}
    return result


def bound_files(ctl, items):
    result = {}
    for c in items:
        for mount in c['mounts']:
            if mount['type'] != 'bind':
                continue
            path = Path(mount['source'])
            # Docker Desktop retains this VM prefix on some old bind mounts.
            # Resolve only the exact recorded dataset subtree, never arbitrary paths.
            vm_prefix = '/host_mnt' + str(ctl.GENERATED) + '/'
            if str(path).startswith(vm_prefix):
                path = Path(str(path)[len('/host_mnt'):])
            if path == ctl.EDITOR_BUNDLE:
                ctl.require(not mount['rw'] and mount['target'] == '/opt/yijie/workflow-editor', 'Original editor mount differs')
                continue
            ctl.require(not mount['rw'] and path.resolve() == path and path.is_file(), 'Original file mount must remain a regular read-only file')
            ctl.require(path.parent == ctl.PRIVATE or path == ctl.GENERATED / 'upstream-schema.sql', 'Unexpected recovery bind source')
            result[str(path)] = digest(path.read_bytes())
    return result


def check_old_assets(ctl, registered):
    ctl.require(registered and registered['bundle_dir'] == str(ctl.EDITOR_BUNDLE), 'Original editor registration is required')
    raw = ctl.public_bytes(ctl.EDITOR_BUNDLE / 'manifest.json', 4 * 1024 * 1024)
    ctl.require(digest(raw) == registered['manifest_sha256'], 'Original editor manifest changed')
    manifest = json.loads(raw)
    names = set()
    for item in manifest['files']:
        path = Path(item['path'])
        ctl.require(not path.is_absolute() and '..' not in path.parts and item['path'] not in names, 'Original asset path differs')
        data = ctl.public_bytes(ctl.EDITOR_BUNDLE / path, 16 * 1024 * 1024)
        ctl.require(len(data) == item['bytes'] and digest(data) == item['sha256'], 'Original editor asset changed')
        names.add(item['path'])
    actual = {str(p.relative_to(ctl.EDITOR_BUNDLE)) for p in ctl.EDITOR_BUNDLE.rglob('*') if p.is_file() and p.name != 'manifest.json'}
    ctl.require(actual == names, 'Original editor asset inventory changed')
    return {'manifest_sha256': digest(raw), 'files': len(names), 'bytes': sum(f['bytes'] for f in manifest['files'])}


def sources(ctl):
    paths = [API_POLICY, COZE_POLICY, API_SQL, COZE_SQL, 'yijie-infra/scripts/workflow_recovery.py', 'yijie-infra/scripts/workflow-local.py']
    return {p: digest((ctl.WORKSPACE / p).read_bytes()) for p in paths}


def plan(ctl):
    state = ctl.read_state()
    ctl.require(not state.get('active_child') and not state.get('pending_stop'), 'Controller has an unresolved child or normal stop')
    ctl.require(not state.get('recovery_active'), 'Existing recovery retained; resume its exact ID')
    items = ctl.all_containers()
    ctl.validate_owned(items, state)
    ctl.require(items and not any(c['state']['Running'] for c in items), 'Recovery plan requires all recorded containers stopped')
    ctl.require({c['id'] for c in items} == {c['id'] for c in state['containers']}, 'Recorded container inventory differs')
    primaries = select_primaries(ctl, items)
    for c in items:
        oneoff = str(c['labels'].get('com.docker.compose.oneoff', 'false')).lower() == 'true'
        ctl.require(not oneoff or (c['state']['ExitCode'] == 0 and not c['state']['OOMKilled']), 'Abnormal one-off needs separate inspection')
    ctl.verify_images()
    for c in items:
        ctl.require(json.loads(ctl.output(['image', 'inspect', c['image_id']]))[0]['Id'] == c['image_id'], 'Original image is unavailable')
    ctl.credential_pair(state)
    ctl.require_free_port()
    assets = check_old_assets(ctl, state.get('editor'))
    volumes = []
    for service, target in DATA_TARGETS.items():
        matches = [m for m in primaries[service]['mounts'] if m['type'] == 'volume' and m['target'] == target]
        ctl.require(len(matches) == 1, 'Recorded data mount differs: ' + service)
        m = matches[0]
        volume = json.loads(ctl.output(['volume', 'inspect', m['source']]))[0]
        ctl.require(volume.get('Labels', {}).get('com.docker.compose.project') == ctl.PROJECT, 'Data volume ownership differs')
        others = set(ctl.output(['ps', '-aq', '--filter', 'volume=' + m['source']]).split())
        ctl.require(others <= {c['id'][:12] for c in items} | {c['id'] for c in items}, 'Data volume is attached to an unrecorded container')
        volumes.append({'service': service, 'container_id': primaries[service]['id'], 'name': m['source'], 'target': target, 'created_at': volume.get('CreatedAt')})
    ctl.require(shutil.disk_usage(ctl.GENERATED).free >= 4 * 1024 ** 3, 'Recovery copies require at least 4 GiB free space')
    recovery_id = str(uuid.uuid4())
    folder = ctl.GENERATED / 'recoveries' / recovery_id
    folder.mkdir(parents=True, mode=0o700)
    snapshot = {'schema_version': 1, 'recovery_id': recovery_id, 'created_at_ms': int(time.time() * 1000), 'run_epoch': state['run_epoch'], 'original_phase': state['phase'], 'containers': items, 'primaries': {s: c['id'] for s, c in primaries.items()}, 'identities': identities(ctl, items), 'bound_file_sha256': bound_files(ctl, items), 'assets': assets, 'volumes': volumes, 'source_sha256': sources(ctl)}
    immutable_json(folder / 'original.json', snapshot)
    # State contains paths and public fingerprints, never credential values.
    immutable_json(folder / 'original-state.json', state)
    event(folder, 'planned', snapshot_sha256=digest((folder / 'original.json').read_bytes()))
    ctl.write_json(folder / 'progress.json', {'stage': 'planned', 'copy_attempts': [], 'copies': {}, 'start_attempts': []})
    print('RECOVERY_PLAN', recovery_id, '— six primaries, four stopped data copies; no containers started')


def accepted_sources(ctl, folder, snapshot):
    expected = snapshot['source_sha256']
    for path in sorted(folder.glob('source-revision-*.json')):
        revision = json.loads(ctl.secure_read(path))
        ctl.require(revision['previous_sha256'] == digest(canonical(expected)), 'Recovery source revision chain differs')
        expected = revision['sources']
    return expected


def verify(ctl, folder, snapshot, check_sources=True):
    state = ctl.read_state()
    ctl.require(state['run_epoch'] == snapshot['run_epoch'], 'Recovery epoch changed')
    items = ctl.all_containers()
    ctl.validate_owned(items, state)
    ctl.require({c['id'] for c in items} == {c['id'] for c in snapshot['containers']}, 'Recovery container set changed')
    ctl.require(identities(ctl, items) == snapshot['identities'], 'Original container image/config/network changed')
    ctl.require(bound_files(ctl, items) == snapshot['bound_file_sha256'], 'Original mounted configuration changed')
    if check_sources:
        ctl.require(sources(ctl) == accepted_sources(ctl, folder, snapshot), 'Recovery source changed; inspect before resuming')
    check_old_assets(ctl, json.loads(ctl.secure_read(folder / 'original-state.json'))['editor'])
    ctl.credential_pair(state)
    return state, items


def copy_inventory(folder):
    rows = []
    for base, dirs, files in os.walk(folder, followlinks=False):
        for name in sorted(dirs + files):
            path = Path(base) / name
            info = path.lstat()
            row = {'path': str(path.relative_to(folder)), 'mode': stat.S_IMODE(info.st_mode)}
            if path.is_symlink():
                row.update(type='symlink', target=os.readlink(path))
            elif path.is_dir():
                row.update(type='directory')
            elif path.is_file():
                h = hashlib.sha256()
                with path.open('rb') as inp:
                    for block in iter(lambda: inp.read(1024 * 1024), b''):
                        h.update(block)
                row.update(type='file', bytes=info.st_size, sha256=h.hexdigest())
            else:
                raise ValueError('Unexpected special file in data copy')
            rows.append(row)
    return sorted(rows, key=lambda x: x['path'])


def backup(ctl, folder, snapshot, progress):
    state, items = verify(ctl, folder, snapshot)
    ctl.require(not any(c['state']['Running'] for c in items), 'Stopped source data required for protective copy')
    (folder / 'copies').mkdir(exist_ok=True, mode=0o700)
    for volume in snapshot['volumes']:
        name = volume['service']
        if name in progress['copies']:
            expected = json.loads(ctl.secure_read(folder / (name + '-inventory.json'), 16 * 1024 * 1024))
            ctl.require(copy_inventory(folder / 'copies' / name) == expected, 'Protective data copy changed')
            continue
        ctl.require(name not in progress['copy_attempts'], 'Incomplete prior copy retained for inspection: ' + name)
        progress['copy_attempts'].append(name)
        ctl.write_json(folder / 'progress.json', progress)
        target = folder / 'copies' / name
        target.mkdir(mode=0o700)
        event(folder, 'copy-start', service=name, volume=volume['name'])
        code = ctl.run_logged(['cp', volume['container_id'] + ':' + volume['target'] + '/.', str(target)], 'recovery-copy-' + name, state=state)
        ctl.require(code == 0, 'Protective copy incomplete; source retained')
        inventory = copy_inventory(target)
        ctl.require(inventory, 'Protective copy is empty')
        immutable_json(folder / (name + '-inventory.json'), inventory)
        progress['copies'][name] = {'files': len(inventory), 'bytes': sum(r.get('bytes', 0) for r in inventory), 'inventory_sha256': digest(canonical(inventory))}
        ctl.write_json(folder / 'progress.json', progress)
        event(folder, 'copy-complete', service=name, **progress['copies'][name])
    _, after = verify(ctl, folder, snapshot)
    ctl.require([c['state'] for c in after] == [c['state'] for c in snapshot['containers']], 'Source container state changed during copy')
    progress['stage'] = 'copied'
    ctl.write_json(folder / 'progress.json', progress)


def start_stage(ctl, folder, snapshot, progress, services):
    for service in services:
        state, items = verify(ctl, folder, snapshot)
        current = next(c for c in items if c['id'] == snapshot['primaries'][service])
        if not current['state']['Running']:
            ctl.require(service not in progress['start_attempts'], 'An attempted primary exited; inspect before another start: ' + service)
            progress['start_attempts'].append(service)
            ctl.write_json(folder / 'progress.json', progress)
            event(folder, 'primary-start', service=service, container_id=current['id'])
            ctl.require(ctl.run_logged(['start', current['id']], 'recovery-start-' + service, state=state) == 0, 'Original primary start did not complete')
        deadline = time.monotonic() + 180
        while True:
            _, items = verify(ctl, folder, snapshot)
            current = next(c for c in items if c['id'] == snapshot['primaries'][service])
            ctl.require(current['state']['Running'], 'Original primary exited during recovery: ' + service)
            if current['health'] == 'healthy':
                break
            ctl.require(time.monotonic() < deadline, 'Recovery readiness pending; existing processes retained: ' + service)
            time.sleep(2)
        event(folder, 'primary-healthy', service=service)


def load_policy(path, name):
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_storage(ctl, snapshot):
    facts = {}
    for name, service, query, command in [
        ('api', 'workflow-postgres', API_SQL, ['psql', '-X', '-qAt', '-U', 'workflow', '-d', 'yijie_workflow_local', '-v', 'ON_ERROR_STOP=1']),
        ('coze', 'coze-workflow-mysql', COZE_SQL, ['sh', '-c', 'MYSQL_PWD="$(cat /run/private/mysql-password)" exec mysql --protocol=TCP -h127.0.0.1 -uworkflow --batch --raw --skip-column-names coze_workflow_local']),
    ]:
        # Query text comes only from the owning repository. Never accept caller SQL.
        result = subprocess.run(ctl.docker_args(['exec', '-i', snapshot['primaries'][service], *command]), env=ctl.environment(), input=(ctl.WORKSPACE / query).read_text(), capture_output=True, text=True)
        ctl.require(result.returncode == 0 and len(result.stdout) <= 8 * 1024 * 1024, 'Private read-only storage report failed: ' + name)
        facts[name] = json.loads(result.stdout)
    return facts


def review_storage(ctl, facts):
    coze = load_policy(ctl.WORKSPACE / COZE_POLICY, 'coze_recovery_policy').review(facts['coze'])
    api = load_policy(ctl.WORKSPACE / API_POLICY, 'api_recovery_policy').review(facts['api'], {r['operation_id'] for r in facts['coze']['operations']})
    binding = facts['api']['scope_bindings'][0]
    principal = facts['coze']['principals'][0]
    ctl.require(binding['coze_user_id'] == principal['user_id'] and binding['coze_space_id'] == principal['space_id'], 'Cross-store principal differs')
    ctl.require({w['id'] for w in coze['workflows']} <= set(facts['api']['resources']), 'Cross-store workflow ownership differs')
    return {'api': api, 'coze': coze}


def recover(ctl, recovery_id):
    ctl.require(str(uuid.UUID(recovery_id)) == recovery_id, 'Recovery ID must be the exact planned UUID')
    folder = ctl.GENERATED / 'recoveries' / recovery_id
    snapshot = json.loads(ctl.secure_read(folder / 'original.json', 4 * 1024 * 1024))
    ctl.require(snapshot['recovery_id'] == recovery_id, 'Recovery identity differs')
    progress = json.loads(ctl.secure_read(folder / 'progress.json'))
    state, items = verify(ctl, folder, snapshot)
    if progress['stage'] == 'complete':
        ctl.require(state['phase'] == 'stopped' and not any(c['state']['Running'] or c['state']['ExitCode'] != 0 for c in items), 'Completed recovery no longer matches stopped state')
        print('RECOVERY_ALREADY_COMPLETE', recovery_id)
        return
    ctl.require(not state.get('active_child') and (not state.get('pending_stop') or progress['stage'] == 'stopping'), 'An earlier child/stop is still unresolved')
    ctl.require(state.get('recovery_active') in [None, recovery_id], 'Another recovery owns this dataset')
    state['recovery_active'] = recovery_id
    state['phase'] = 'recovering'
    ctl.write_json(ctl.STATE, state)
    try:
        if progress['stage'] == 'planned':
            backup(ctl, folder, snapshot, progress)
        if progress['stage'] == 'copied':
            start_stage(ctl, folder, snapshot, progress, ctl.DEPS)
            progress['stage'] = 'dependencies-healthy'
            ctl.write_json(folder / 'progress.json', progress)
        if progress['stage'] == 'dependencies-healthy':
            facts = read_storage(ctl, snapshot)
            immutable_json(folder / ('storage-read-' + str(int(time.time() * 1000)) + '.json'), facts)
            reviewed = review_storage(ctl, facts)
            immutable_json(folder / 'storage-before-apps.json', facts)
            event(folder, 'storage-review-pass', review=reviewed)
            progress['stage'] = 'storage-reviewed'
            ctl.write_json(folder / 'progress.json', progress)
        if progress['stage'] == 'storage-reviewed':
            # Re-read before starting apps, including an explicit resume later.
            facts = read_storage(ctl, snapshot)
            review_storage(ctl, facts)
            start_stage(ctl, folder, snapshot, progress, ['coze-workflow', 'workflow-api'])
            state, items = verify(ctl, folder, snapshot)
            ctl.require(ctl.observed_ready(state, items), 'Original authenticated readiness not confirmed')
            after = read_storage(ctl, snapshot)
            review_storage(ctl, after)
            before = json.loads(ctl.secure_read(folder / 'storage-before-apps.json', 8 * 1024 * 1024))
            ctl.require(canonical(after['coze']) == canonical(before['coze']), 'Original startup changed Coze workflow/operation facts; inspect retained records')
            startup_review = load_policy(ctl.WORKSPACE / API_POLICY, 'api_startup_review').review_startup(before['api'], after['api'])
            event(folder, 'original-apps-ready-storage-unchanged', startup_audit=startup_review)
            progress['stage'] = 'stopping'
            ctl.write_json(folder / 'progress.json', progress)
        if progress['stage'] == 'stopping':
            ctl.stop()
            state = ctl.read_state()
            ctl.require(state['phase'] == 'stopped', 'Normal recovery stop remains pending')
            event(folder, 'normal-stop-complete', containers=ctl.all_containers())
            progress['stage'] = 'complete'
            ctl.write_json(folder / 'progress.json', progress)
            state.pop('recovery_active', None)
            state.setdefault('recovery_history', []).append({'recovery_id': recovery_id, 'original_sha256': digest((folder / 'original.json').read_bytes()), 'completed_at_ms': int(time.time() * 1000)})
            ctl.write_json(ctl.STATE, state)
        print('RECOVERY_COMPLETE', recovery_id, '— original data retained, historical failure archived, normal stop verified')
    except Exception as error:
        event(folder, 'recovery-paused', stage=progress['stage'], reason=str(error))
        raise


def revise(ctl, recovery_id, expected_sha256):
    """Record one reviewed source correction while only original dependencies run."""
    ctl.require(str(uuid.UUID(recovery_id)) == recovery_id, 'Exact recovery UUID required')
    folder = ctl.GENERATED / 'recoveries' / recovery_id
    snapshot = json.loads(ctl.secure_read(folder / 'original.json', 4 * 1024 * 1024))
    progress = json.loads(ctl.secure_read(folder / 'progress.json'))
    state, items = verify(ctl, folder, snapshot, check_sources=False)
    ctl.require(state.get('recovery_active') == recovery_id and progress['stage'] in ['dependencies-healthy', 'storage-reviewed'], 'Source correction requires paused storage review')
    ctl.require(not state.get('active_child') and not state.get('pending_stop'), 'Earlier child/stop unresolved')
    allowed_running = {snapshot['primaries'][name] for name in (ctl.DEPS if progress['stage'] == 'dependencies-healthy' else ctl.SERVICES)}
    ctl.require(all(not c['state']['Running'] or c['id'] in allowed_running for c in items), 'Unrecorded running process during source correction')
    if progress['stage'] == 'storage-reviewed':
        ctl.require(ctl.observed_ready(state, items), 'Original applications must remain healthy for startup-audit review')
        before = json.loads(ctl.secure_read(folder / 'storage-before-apps.json', 8 * 1024 * 1024))
        after = read_storage(ctl, snapshot)
        review_storage(ctl, after)
        ctl.require(canonical(before['coze']) == canonical(after['coze']), 'Coze facts changed during startup-audit review')
        load_policy(ctl.WORKSPACE / API_POLICY, 'api_startup_correction').review_startup(before['api'], after['api'])
    new = sources(ctl)
    ctl.require(digest(canonical(new)) == expected_sha256, 'Reviewed replacement source digest differs')
    previous = accepted_sources(ctl, folder, snapshot)
    changed = {key for key in new if new[key] != previous[key]}
    # This scoped correction addresses the observed Go private receipt JSON key
    # mapping. It cannot silently substitute the engine policy or arbitrary SQL.
    allowed = {API_SQL, API_POLICY, 'yijie-infra/scripts/workflow_recovery.py', 'yijie-infra/scripts/workflow-local.py'}
    ctl.require(changed and changed <= allowed, 'Source correction exceeds the reviewed receipt mapping/controller scope')
    for name in progress['copies']:
        inventory = json.loads(ctl.secure_read(folder / (name + '-inventory.json'), 16 * 1024 * 1024))
        ctl.require(copy_inventory(folder / 'copies' / name) == inventory, 'Original protective copy differs')
    sequence = len(list(folder.glob('source-revision-*.json'))) + 1
    revision = {'reason': 'Correct private Receipt JSON mapping and account for repository EnsurePrincipal startup audit; preserve all original records and exact source provenance', 'previous_sha256': digest(canonical(previous)), 'sources': new, 'changed': sorted(changed), 'reviewed_at_ms': int(time.time() * 1000)}
    immutable_json(folder / ('source-revision-%04d.json' % sequence), revision)
    event(folder, 'source-correction-recorded', sequence=sequence, sources_sha256=expected_sha256)
    print('RECOVERY_SOURCE_CORRECTION_RECORDED', recovery_id, '— no service or data mutation')
