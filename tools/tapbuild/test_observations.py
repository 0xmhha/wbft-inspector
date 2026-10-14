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
