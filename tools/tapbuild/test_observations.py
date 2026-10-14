import json
from pathlib import Path
import tempfile
import unittest

import verify_observations as verifier


class ObservationTest(unittest.TestCase):
    def rows(self):
        config = {key: '1' for key in verifier.CONFIG}
        config.update(Address='0x' + '0' * 39 + '1', Transitions=0, SystemContractUpgrades=0)
        rows = [
            {'type': 'runtime_start', 'config': config},
            {'type': 'operation_start', 'id': 1, 'operation': 'insert_chain', 'height': '17', 'hash': '', 'count': 2},
            {'type': 'operation_end', 'id': 1, 'result': 'error', 'height': '17', 'hash': '', 'index': 1},
            {'type': 'runtime_stop', 'result': 'ok'},
            {'type': 'capture_end', 'dropped': 0},
        ]
        for index, row in enumerate(rows):
            row.update(v=1, node=config['Address'], run='test-run', seq=index,
                       t_wall='2026-01-01T00:00:00Z', t_mono_ns=index)
        return rows

    def inspect(self, rows):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'observations.jsonl'
            path.write_text('\n'.join(json.dumps(row) for row in rows) + '\n')
            return verifier.inspect(path)

    def test_complete_calls_do_not_prove_full_runtime_or_commit(self):
        result = self.inspect(self.rows())
        self.assertTrue(result['capture_complete'])
        self.assertEqual(result['call_intervals']['insert_chain']['count'], 1)
        self.assertFalse(result['runtime_model_complete'])
        self.assertFalse(result['application_request_completion_proven'])
        self.assertFalse(result['delivery_coverage_proven'])

    def test_stages_require_exact_worker_parent(self):
        rows = self.rows()
        rows[1]['operation'] = 'worker_commit_work'
        stage = dict(rows[2], type='operation_stage', id=1, stage='seal_return', height='17', hash='0x'+'2'*64)
        for key in ['result','index']:
            stage.pop(key, None)
        rows.insert(3, stage)
        for i, row in enumerate(rows):
            row['seq'] = i
        result = self.inspect(rows)
        self.assertFalse(result['problems'])
        self.assertEqual(result['format'], 'wbft-tap-observations/2')
        self.assertFalse(result['application_request_completion_proven'])
        rows[3]['id'] = 2
        self.assertTrue(self.inspect(rows)['problems'])

    def test_engine_stages_require_concrete_instance_and_parent(self):
        rows=self.rows()
        rows[1]['operation']='backend_start'
        rows[2]['result']='ok'
        rows[2:2]=[dict(v=1,type='engine_created',node=rows[1]['node'],run='test-run',seq=0,t_wall=rows[1]['t_wall'],t_mono_ns=0,id=7,parent_id=1),dict(v=1,type='engine_stage',node=rows[1]['node'],run='test-run',seq=0,t_wall=rows[1]['t_wall'],t_mono_ns=0,id=7,parent_id=1,stage='start_enter')]
        for i,r in enumerate(rows):
            r['seq']=i
            r['t_mono_ns']=i
        result=self.inspect(rows)
        self.assertEqual(result['problems'],[])
        self.assertEqual(result['engine_instances'],1)
        self.assertEqual(result['format'],'wbft-tap-observations/3')
        rows[3]['parent_id']=2
        self.assertTrue(self.inspect(rows)['problems'])

    def test_instance_configuration_requires_its_own_start_parent(self):
        rows=self.rows()
        rows[1]['operation']='backend_start';rows[2]['result']='ok'
        common={key:rows[1][key] for key in verifier.COMMON}
        rows[2:2]=[dict(common,type='engine_created',id=7,parent_id=1),dict(common,type='engine_config',id=7,parent_id=1,config=rows[0]['config'])]
        for i,r in enumerate(rows):r.update(seq=i,t_mono_ns=i)
        result=self.inspect(rows)
        self.assertEqual(result['problems'],[])
        self.assertEqual(result['format'],'wbft-tap-observations/4')
        self.assertEqual(len(result['engine_configs']),1)
        rows[3]['parent_id']=2
        self.assertTrue(self.inspect(rows)['problems'])

    def test_noop_close_does_not_establish_engine_stop(self):
        rows = self.rows()
        rows[3].pop('result')
        rows[3].update(type='runtime_close', engine_stopped=False)
        result = self.inspect(rows)
        self.assertTrue(result['capture_complete'])
        self.assertFalse(result['runtime_stop_observed'])
        rows[3]['engine_stopped'] = True
        self.assertTrue(self.inspect(rows)['problems'])

    def test_known_drop_and_unknown_tail_remain_incomplete(self):
        rows = self.rows()
        rows[-1]['dropped'] = 1
        rows.pop(2)
        result = self.inspect(rows)
        self.assertFalse(result['capture_complete'])
        self.assertEqual(result['sequence_gaps'], 1)
        self.assertEqual(result['problems'], [])
        self.assertIn('operation boundary absent: 1', result['unavailable'])
        result = self.inspect(self.rows()[:-1])
        self.assertIn('normal capture end absent', result['unavailable'])

    def test_malformed_identity_endpoint_and_extra_engine_fields_refused(self):
        for change in ['identity', 'reversed', 'boolean', 'extra']:
            rows = self.rows()
            if change == 'identity':
                rows[2]['node'] = '0x' + '0' * 40
            elif change == 'reversed':
                rows[2]['t_mono_ns'] = 0
            elif change == 'boolean':
                rows[2]['id'] = True
            else:
                rows[2]['engine_outcome'] = 'ACCEPTED'
            self.assertTrue(self.inspect(rows)['problems'], change)

    def test_wall_regression_preserved_and_duplicate_key_refused(self):
        rows = self.rows()
        rows[2]['t_wall'] = '2025-01-01T00:00:00Z'
        self.assertTrue(self.inspect(rows)['capture_complete'])
        with self.assertRaises(ValueError):
            json.loads('{"id":1,"id":2}', object_pairs_hook=verifier.unique_object)


if __name__ == '__main__':
    unittest.main()
