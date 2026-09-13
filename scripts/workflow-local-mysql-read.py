#!/usr/bin/env python3
"""Independent FEAT-153 qualification: read owned MySQL facts, never application SQL writes.

contract-impact = additive: an opt-in Infra qualification command and safe local
evidence artifact. No API access to private tables, wire changes or service builds.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

CONTROLLER = Path(__file__).resolve().with_name('workflow-local.py')
spec = importlib.util.spec_from_file_location('workflow_local_controller', CONTROLLER)
controller = importlib.util.module_from_spec(spec)
spec.loader.exec_module(controller)

SCOPE = '12500000-0000-4000-8000-000000000001:12500000-0000-4000-8000-100000000001'
MIGRATION_CHECKSUM = 'f242370466196b5f0f760b9dd5dc752b09cb55de696078b25324de1b76ddb728'
UUID = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
KINDS = Counter({'create': 1, 'save': 2, 'test': 2, 'publish': 3, 'run': 2})


def positive_id(value):
    return isinstance(value, str) and re.fullmatch(r'[1-9][0-9]{0,18}', value) is not None and int(value) <= 9223372036854775807


def absolute_path(value):
    path = Path(value)
    controller.require(path.is_absolute() and str(path) == os.path.normpath(value), 'Artifact path must be absolute and clean')
    return path


def evidence_input(path):
    raw = controller.secure_read(path, 524288)
    data = json.loads(raw)
    controller.require(data.get('schema_version') == 1 and data.get('complete') is True, 'A completed real HTTP qualification artifact is required')
    workflow = data.get('workflow', {})
    wid = workflow.get('workflow_id')
    controller.require(positive_id(wid) and positive_id(workflow.get('revision')) and workflow.get('published_version') == 'v0.0.3', 'HTTP workflow identity, revision or publication differs')
    runs = data.get('runs', [])
    controller.require(isinstance(runs, list) and len(runs) == 4 and all(isinstance(r, dict) for r in runs), 'HTTP artifact must contain four normal runs')
    controller.require(len({r.get('run_id') for r in runs}) == 4 and Counter(r.get('mode') for r in runs) == Counter({'debug': 2, 'release': 2}), 'HTTP run identities or modes differ')
    controller.require(all(positive_id(r.get('run_id')) and positive_id(r.get('revision')) and r.get('workflow_id') == wid and r.get('terminal') is True and r.get('state') == 'succeeded' and len(r.get('nodes', [])) == 3 for r in runs), 'HTTP artifact does not contain four actual successful three-node runs')
    receipts = data.get('operations', [])
    controller.require(isinstance(receipts, list) and all(isinstance(r, dict) for r in receipts), 'HTTP operation evidence differs')
    completed = [r for r in receipts if r.get('phase') == 'completed']
    rejected = [r for r in receipts if r.get('phase') == 'rejected']
    controller.require(len(completed) == 10 and Counter(r.get('kind') for r in completed) == KINDS, 'HTTP completed operation inventory differs')
    controller.require(len(completed) + len(rejected) == len(receipts) and all(r.get('kind') == 'save' for r in rejected), 'HTTP operation phases differ from the normal qualification')
    controller.require(all(isinstance(r.get('operation_id'), str) and UUID.fullmatch(r['operation_id']) for r in receipts) and len({r['operation_id'] for r in receipts}) == len(receipts), 'HTTP operation identities differ')
    controller.require(all(r.get('workflow_id') == wid for r in completed), 'HTTP completed operations belong to another workflow')
    return data, completed, rejected, hashlib.sha256(raw.encode()).hexdigest()


def sql_for(wid):
    # The only interpolated value is a validated positive int64 identity. No
    # user SQL, table names, passwords, graph content or URLs are accepted.
    controller.require(positive_id(wid), 'Workflow identity is invalid')
    return f"""START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY;
SELECT 'database', JSON_OBJECT('name', DATABASE(), 'table_count', (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE'));
SELECT 'migration', JSON_OBJECT('version', version, 'checksum', checksum) FROM yijie_workflow_local_migration ORDER BY version;
SELECT 'principal', JSON_OBJECT('scope_key', p.scope_key, 'user_id', CAST(p.user_id AS CHAR), 'space_id', CAST(p.space_id AS CHAR), 'active_run_id', CAST(p.active_run_id AS CHAR), 'user_exists', u.id IS NOT NULL, 'space_owner_matches', s.owner_id = p.user_id, 'membership_count', (SELECT COUNT(*) FROM space_user su WHERE su.user_id = p.user_id AND su.space_id = p.space_id AND su.role_type = 1)) FROM yijie_workflow_local_principal p LEFT JOIN user u ON u.id = p.user_id AND u.deleted_at IS NULL LEFT JOIN space s ON s.id = p.space_id AND s.deleted_at IS NULL;
SELECT 'workflow', JSON_OBJECT('workflow_id', CAST(m.id AS CHAR), 'space_id', CAST(m.space_id AS CHAR), 'creator_id', CAST(m.creator_id AS CHAR), 'app_id', CAST(m.app_id AS CHAR), 'latest_version', m.latest_version, 'status', m.status, 'revision', d.commit_id, 'modified', d.modified, 'test_run_success', d.test_run_success) FROM workflow_meta m JOIN workflow_draft d ON d.id = m.id AND d.deleted_at IS NULL WHERE m.id = {wid} AND m.deleted_at IS NULL;
SELECT 'operation', JSON_OBJECT('scope_key', scope_key, 'operation_id', operation_id, 'kind', kind, 'workflow_id', CAST(workflow_id AS CHAR), 'run_id', CAST(run_id AS CHAR), 'run_epoch', run_epoch, 'phase', JSON_UNQUOTE(JSON_EXTRACT(receipt, '$.phase')), 'receipt_operation_id', JSON_UNQUOTE(JSON_EXTRACT(receipt, '$.operation_id')), 'receipt_kind', JSON_UNQUOTE(JSON_EXTRACT(receipt, '$.kind')), 'receipt_workflow_id', JSON_UNQUOTE(JSON_EXTRACT(receipt, '$.workflow_id')), 'receipt_run_id', JSON_UNQUOTE(JSON_EXTRACT(receipt, '$.run_id')), 'revision', JSON_UNQUOTE(JSON_EXTRACT(receipt, '$.revision')), 'version', JSON_UNQUOTE(JSON_EXTRACT(receipt, '$.version'))) FROM yijie_workflow_local_operation WHERE workflow_id = {wid} ORDER BY created_at, operation_id;
SELECT 'version', JSON_OBJECT('version', version, 'revision', commit_id, 'creator_id', CAST(creator_id AS CHAR)) FROM workflow_version WHERE workflow_id = {wid} AND deleted_at IS NULL ORDER BY version;
SELECT 'execution', JSON_OBJECT('run_id', CAST(id AS CHAR), 'workflow_id', CAST(workflow_id AS CHAR), 'space_id', CAST(space_id AS CHAR), 'operator_id', CAST(operator_id AS CHAR), 'mode', mode, 'status', status, 'version', version, 'revision', commit_id, 'root_execution_id', CAST(root_execution_id AS CHAR), 'parent_node_id', parent_node_id, 'app_id', CAST(app_id AS CHAR), 'agent_id', CAST(agent_id AS CHAR), 'node_count', node_count, 'input_tokens', input_tokens, 'output_tokens', output_tokens) FROM workflow_execution WHERE workflow_id = {wid} ORDER BY created_at, id;
SELECT 'node', JSON_OBJECT('run_id', CAST(n.execute_id AS CHAR), 'node_id', n.node_id, 'node_type', n.node_type, 'status', n.status, 'parent_node_id', n.parent_node_id, 'sub_execute_id', CAST(n.sub_execute_id AS CHAR), 'input_tokens', n.input_tokens, 'output_tokens', n.output_tokens) FROM node_execution n JOIN workflow_execution e ON e.id = n.execute_id WHERE e.workflow_id = {wid} ORDER BY n.execute_id, n.node_id;
COMMIT;
"""


def command_script(wid):
    # Only the stock image's bash/mysql are used. The password is read inside
    # the container, stays an unexported shell variable, and is never argv/env.
    # umask protects a newly created temporary option file; no existing modes
    # are modified. The EXIT trap removes only that newly created file.
    return """set +x
set -eu
umask 077
option_file=$(mktemp /tmp/yijie-workflow-mysql-read.XXXXXXXXXX)
trap 'rm -f -- "$option_file"' EXIT
password=''
IFS= read -r password < /run/private/mysql-password || [ -n "$password" ]
[[ "$password" =~ ^[0-9a-f]{64}$ ]] || exit 1
printf '[client]\\nuser=workflow\\npassword=%s\\nhost=127.0.0.1\\nport=3306\\nprotocol=tcp\\n' "$password" > "$option_file"
unset password
mysql --defaults-file="$option_file" --no-login-paths --batch --raw --skip-column-names --connect-timeout=5 coze_workflow_local <<'WORKFLOW_READ_ONLY_SQL'
""" + sql_for(wid) + 'WORKFLOW_READ_ONLY_SQL\n'


def mysql_facts(container_id, wid):
    command = controller.docker_args(['exec', '--user', '0:0', container_id, '/bin/bash', '--noprofile', '--norc', '-c', command_script(wid)])
    # No timeout that kills a Docker client or database process. SQL is read-only
    # and finite; on a pending normal operation the orchestrator retains state.
    process = subprocess.Popen(command, env=controller.environment(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
    stdout, _ = process.communicate()
    controller.require(process.returncode == 0 and len(stdout.encode()) <= 524288, 'Read-only MySQL qualification did not complete; no database writes requested')
    facts = {name: [] for name in ['database', 'migration', 'principal', 'workflow', 'operation', 'version', 'execution', 'node']}
    for line in stdout.splitlines():
        name, value = line.split('\t', 1)
        controller.require(name in facts, 'Unexpected MySQL qualification section')
        row = json.loads(value)
        controller.require(isinstance(row, dict), 'Unexpected MySQL qualification row')
        facts[name].append(row)
    return facts


def validate_facts(facts, evidence, receipts, rejected, checks):
    def check(name, condition):
        checks[name] = bool(condition)
        controller.require(condition, 'MySQL qualification check failed: ' + name)

    wid = evidence['workflow']['workflow_id']
    check('dedicated_database_and_58_tables', facts['database'] == [{'name': 'coze_workflow_local', 'table_count': 58}])
    check('exact_private_migration', facts['migration'] == [{'version': 1, 'checksum': MIGRATION_CHECKSUM}])
    check('one_fixed_principal', len(facts['principal']) == 1)
    principal = facts['principal'][0]
    check('native_principal_membership', principal['scope_key'] == SCOPE and positive_id(principal['user_id']) and positive_id(principal['space_id']) and principal['user_exists'] == 1 and principal['space_owner_matches'] == 1 and principal['membership_count'] == 1)
    check('one_native_workflow', len(facts['workflow']) == 1)
    workflow = facts['workflow'][0]
    check('native_workflow_scope_and_draft', workflow['workflow_id'] == wid and workflow['space_id'] == principal['space_id'] and workflow['creator_id'] == principal['user_id'] and workflow['app_id'] == '0' and workflow['status'] == 1 and workflow['modified'] == 0 and workflow['test_run_success'] == 1 and workflow['latest_version'] == evidence['workflow']['published_version'] and workflow['revision'] == evidence['workflow']['revision'])
    ops = facts['operation']
    expected = {r['operation_id']: r for r in receipts}
    check('ten_completed_operation_ids_and_kinds', len(ops) == 10 and {r['operation_id'] for r in ops} == set(expected) and Counter(r['kind'] for r in ops) == KINDS)
    check('rejected_save_absent_from_committed_operations', not ({r['operation_id'] for r in rejected} & {r['operation_id'] for r in ops}))
    check('one_valid_historical_operation_epoch', len({r['run_epoch'] for r in ops}) == 1 and all(UUID.fullmatch(r['run_epoch']) for r in ops))
    for op in ops:
        receipt = expected[op['operation_id']]
        check('operation_' + op['operation_id'], op['scope_key'] == SCOPE and op['workflow_id'] == wid and op['phase'] == 'completed' and op['kind'] == receipt['kind'] and op['receipt_kind'] == receipt['kind'] and op['receipt_operation_id'] == receipt['operation_id'] and op['receipt_workflow_id'] == wid and op['run_id'] == receipt.get('run_id', '0') and op['receipt_run_id'] == receipt.get('run_id') and op['revision'] == receipt.get('revision') and op['version'] == receipt.get('version'))
    versions = {v['version']: v for v in facts['version']}
    check('three_internal_versions', len(facts['version']) == 3 and set(versions) == {'v0.0.1', 'v0.0.2', 'v0.0.3'})
    check('publication_revision_proof', versions['v0.0.1']['revision'] != versions['v0.0.2']['revision'] and versions['v0.0.2']['revision'] == versions['v0.0.3']['revision'] == workflow['revision'] and all(v['creator_id'] == principal['user_id'] for v in versions.values()) and all(versions[r['version']]['revision'] == r['revision'] for r in receipts if r['kind'] == 'publish'))
    runs = {r['run_id']: r for r in evidence['runs']}
    check('four_real_successful_execution_ids', len(facts['execution']) == 4 and {r['run_id'] for r in facts['execution']} == set(runs) and Counter(r['mode'] for r in facts['execution']) == Counter({1: 2, 2: 2}))
    for execution in facts['execution']:
        run = runs[execution['run_id']]
        check('execution_' + execution['run_id'], execution['workflow_id'] == wid and execution['space_id'] == principal['space_id'] and execution['operator_id'] == principal['user_id'] and execution['status'] == 2 and execution['mode'] == {'debug': 1, 'release': 2}[run['mode']] and (execution['version'] or None) == run.get('version') and execution['revision'] == run['revision'] and execution['root_execution_id'] == execution['run_id'] and execution['parent_node_id'] == '' and execution['app_id'] == '0' and execution['agent_id'] == '0' and execution['node_count'] == 3 and execution['input_tokens'] == 0 and execution['output_tokens'] == 0)
        receipt = expected.get(run['operation_id'], {})
        check('run_operation_relation_' + execution['run_id'], receipt.get('run_id') == execution['run_id'] and receipt.get('kind') == {'debug': 'test', 'release': 'run'}[run['mode']] and receipt.get('revision') == execution['revision'] and receipt.get('version') == run.get('version'))
    check('twelve_native_nodes', len(facts['node']) == 12 and Counter(n['run_id'] for n in facts['node']) == Counter({rid: 3 for rid in runs}))
    for run_id in runs:
        nodes = [n for n in facts['node'] if n['run_id'] == run_id]
        check('nodes_' + run_id, {n['node_id']: n['node_type'] for n in nodes} == {'100001': 'Entry', '200001': 'TextProcessor', '900001': 'Exit'} and all(n['status'] == 3 and n['parent_node_id'] == '' and n['sub_execute_id'] == '0' and n['input_tokens'] == 0 and n['output_tokens'] == 0 for n in nodes))
    check('scope_slot_points_to_observed_terminal_run', principal['active_run_id'] in runs)


def qualify(evidence_path, output_path):
    evidence, receipts, rejected, digest = evidence_input(evidence_path)
    state = controller.read_state()
    items = controller.record(state)
    controller.validate_owned(items, state)
    controller.require(state['phase'] == 'ready', 'MySQL qualification requires the normally ready owned stack')
    matches = [item for item in items if item['labels'].get('com.docker.compose.service') == 'coze-workflow-mysql' and item['state']['Running'] and item['health'] == 'healthy']
    controller.require(len(matches) == 1, 'One running healthy owned MySQL container is required')
    mysql = matches[0]
    controller.require(any(m['type'] == 'bind' and m['source'] in [str(controller.PRIVATE / 'mysql-password'), '/host_mnt' + str(controller.PRIVATE / 'mysql-password')] and m['target'] == '/run/private/mysql-password' and not m['rw'] for m in mysql['mounts']), 'Owned MySQL private password mount differs')
    fd = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    result = {'schema_version': 1, 'qualification': 'independent_coze_mysql_readonly', 'result': 'failed', 'project': controller.PROJECT, 'run_epoch': state['run_epoch'], 'workflow_id': evidence['workflow']['workflow_id'], 'http_evidence_sha256': digest, 'mysql_container_id': mysql['id'], 'checks': {}}
    with os.fdopen(fd, 'w') as out:
        try:
            facts = mysql_facts(mysql['id'], result['workflow_id'])
            validate_facts(facts, evidence, receipts, rejected, result['checks'])
            final = controller.record(state)
            controller.require(any(c['id'] == mysql['id'] and c['state']['Running'] and c['health'] == 'healthy' for c in final), 'Owned MySQL readiness changed before recording qualification')
            result['facts'] = facts
            result['result'] = 'pass'
        finally:
            result['observed_at'] = datetime.now(timezone.utc).isoformat()
            json.dump(result, out, ensure_ascii=False, indent=2)
            out.write('\n')
    print('MYSQL_READONLY_PASS: dedicated schema, exact operations, versions, four executions and twelve nodes matched real HTTP evidence')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', required=True, help='Absolute completed real HTTP qualification artifact')
    parser.add_argument('--output', required=True, help='Absolute new safe JSON result; existing files are never overwritten')
    args = parser.parse_args()
    evidence_path, output_path = absolute_path(args.evidence), absolute_path(args.output)
    controller.require(output_path.parent.is_dir() and not output_path.exists(), 'Output must be a new file in an existing directory')
    fd = os.open(controller.GENERATED / 'controller.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as lock:
        info = os.fstat(lock.fileno())
        controller.require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600, 'Controller lock ownership differs')
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise controller.WorkflowError('Another workflow lifecycle command is active')
        qualify(evidence_path, output_path)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('MYSQL_READONLY: PENDING; inspect the normal read before another lifecycle action; no forced stop', file=sys.stderr)
        sys.exit(130)
    except controller.WorkflowError as error:
        print('MYSQL_READONLY: NOT PASS; ' + str(error), file=sys.stderr)
        sys.exit(1)
    except Exception:
        print('MYSQL_READONLY: NOT PASS; read evidence did not complete; no database writes requested', file=sys.stderr)
        sys.exit(1)
