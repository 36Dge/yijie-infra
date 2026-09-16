"""Normal in-memory recovery states; no Docker/process/permission fault injection."""
import hashlib
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import workflow_recovery as recovery

def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

api = load(ROOT.parent / recovery.API_POLICY, 'api_policy_test')
coze = load(ROOT.parent / recovery.COZE_POLICY, 'coze_policy_test')

class Guard:
    SERVICES = ['postgres', 'mysql', 'coze']
    @staticmethod
    def require(ok, message):
        if not ok:
            raise ValueError(message)

class RecoveryTest(unittest.TestCase):
    def test_exact_primary_selection_excludes_migration(self):
        rows = [{'id': s, 'labels': {'com.docker.compose.service': s, 'com.docker.compose.oneoff': 'False'}} for s in Guard.SERVICES]
        rows.append({'id': 'one-time-migration', 'labels': {'com.docker.compose.service': 'coze', 'com.docker.compose.oneoff': 'True'}})
        self.assertEqual({k: v['id'] for k, v in recovery.select_primaries(Guard, rows).items()}, {s: s for s in Guard.SERVICES})
        with self.assertRaisesRegex(ValueError, 'exactly one'):
            recovery.select_primaries(Guard, rows[:-2])

    def api_facts(self):
        return {'schema_version': 1, 'database': 'yijie_workflow_local', 'scope_bindings': [{'scope_key': 'feat-153-local-v1'}], 'resources': ['123'], 'operations': [], 'audit': []}

    def test_known_qualification_requires_per_operation_declaration_and_audit(self):
        facts = self.api_facts()
        oid = '00000000-0000-4000-8000-000000000001'
        declaration = 'FEAT-153 declared storage qualification; no engine dispatch; ' + oid
        facts['operations'] = [{'operation_id': oid, 'scope_key': 'feat-153-local-v1', 'phase': 'unknown', 'receipt_phase': 'unknown', 'kind': 'save', 'workflow_id': '123', 'request_sha256': hashlib.sha256(declaration.encode()).hexdigest()}]
        facts['audit'] = [{'operation_id': oid, 'workflow_id': '123', 'action': 'save', 'outcome_code': phase} for phase in ['recorded', 'unknown']]
        facts['audit'].append({'operation_id': None, 'workflow_id': '123', 'action': 'storage_qualification', 'outcome_code': 'normal_readback'})
        self.assertEqual(api.review(facts, set())['known_storage_qualification_unknown'], [oid])
        with self.assertRaisesRegex(ValueError, 'Unresolved'):
            api.review(facts, {oid})
        facts['audit'].pop()
        with self.assertRaisesRegex(ValueError, 'Unresolved'):
            api.review(facts, set())

    def test_recorded_intent_remains_unresolved(self):
        facts = self.api_facts()
        facts['operations'] = [{'operation_id': 'normal-pending', 'scope_key': 'feat-153-local-v1', 'phase': 'recorded', 'receipt_phase': 'recorded', 'kind': 'save', 'workflow_id': '123', 'request_sha256': '0' * 64}]
        with self.assertRaisesRegex(ValueError, 'Unresolved'):
            api.review(facts, set())

    def coze_facts(self):
        return {'schema_version': 1, 'database': 'coze_workflow_local', 'principals': [{'scope_key': coze.SCOPE, 'active_run_id': '10'}], 'executions': [{'id': '10', 'terminal': 1}], 'node_executions': [{'id': '20', 'execution_id': '10', 'terminal': 1}], 'operations': [], 'workflows': []}

    def test_terminal_last_run_slot_is_retained(self):
        facts = self.coze_facts()
        self.assertEqual(coze.review(facts)['active_run_id_retained'], '10')
        self.assertEqual(facts['principals'][0]['active_run_id'], '10')

    def test_missing_or_nonterminal_execution_blocks_recovery(self):
        facts = self.coze_facts()
        facts['executions'][0]['terminal'] = 0
        with self.assertRaisesRegex(ValueError, 'Unresolved Coze execution'):
            coze.review(facts)
        facts = self.coze_facts()
        facts['principals'][0]['active_run_id'] = '11'
        with self.assertRaisesRegex(ValueError, 'active slot'):
            coze.review(facts)

    def test_source_queries_are_read_only_and_use_native_terminal_meanings(self):
        mysql = (ROOT.parent / recovery.COZE_SQL).read_text()
        pg = (ROOT.parent / recovery.API_SQL).read_text()
        self.assertIn('status IN (2,3,4)', mysql)
        self.assertIn('status IN (3,4)', mysql)
        for sql in [mysql, pg]:
            self.assertIn('READ ONLY', sql)
            self.assertIn('ROLLBACK;', sql)
            statements = '\n'.join(line for line in sql.splitlines() if not line.startswith('--')).upper()
            for mutation in ['INSERT ', 'UPDATE ', 'DELETE ', 'TRUNCATE ', 'DROP ', 'ALTER ']:
                self.assertNotIn(mutation, statements)


    def test_resume_healthy_primary_does_not_start_it_twice(self):
        row = {'id': 'primary-1', 'state': {'Running': True}, 'health': 'healthy'}
        with patch.object(recovery, 'verify', return_value=({}, [row])), patch.object(recovery, 'event') as events:
            recovery.start_stage(Guard, Path('/unused'), {'primaries': {'coze': 'primary-1'}}, {'start_attempts': ['coze']}, ['coze'])
            events.assert_called_once()

    def test_exited_previous_start_is_observed_without_automatic_restart(self):
        row = {'id': 'primary-1', 'state': {'Running': False}, 'health': None}
        with patch.object(recovery, 'verify', return_value=({}, [row])):
            with self.assertRaisesRegex(ValueError, 'attempted primary exited'):
                recovery.start_stage(Guard, Path('/unused'), {'primaries': {'coze': 'primary-1'}}, {'start_attempts': ['coze']}, ['coze'])


    def test_normal_startup_appends_only_its_documented_principal_audit(self):
        import copy
        before = self.api_facts()
        after = copy.deepcopy(before)
        after['audit'].append({'id': 1, 'operation_id': None, 'workflow_id': None, 'action': 'principal', 'outcome_code': 'success'})
        self.assertEqual(api.review_startup(before, after)['normal_principal_audit_added'], 1)
        after['resources'].append('456')
        with self.assertRaisesRegex(ValueError, 'stored resources'):
            api.review_startup(before, after)

if __name__ == '__main__':
    unittest.main()
