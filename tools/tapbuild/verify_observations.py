#!/usr/bin/env python3
"""Validate bounded runtime sidecars without importing them as engine events."""
import argparse
from collections import Counter
from datetime import datetime
import json
from pathlib import Path
import re

COMMON = {'v', 'type', 'node', 'run', 'seq', 't_wall', 't_mono_ns'}
FIELDS = {
    'runtime_start': {'config'}, 'runtime_stop': {'result'}, 'runtime_close': {'engine_stopped'},
    'operation_start': {'id', 'operation', 'height', 'hash', 'count'},
    'operation_end': {'id', 'result', 'height', 'hash', 'index'},
    'capture_end': {'dropped'},
    'operation_stage': {'id','stage','height','hash'},
}
CONFIG = {'Address', 'Height', 'RequestTimeoutMS', 'BlockPeriodSeconds', 'Epoch',
          'AllowedFutureBlockSeconds', 'MaxRequestTimeoutSeconds', 'ProposerPolicy',
          'Transitions', 'SystemContractUpgrades'}
OPERATIONS = {'backend_start', 'worker_commit_work', 'insert_chain', 'write_block_and_set_head'}
RESULTS = {'ok', 'error', 'returned', 'syncing', 'missing_etherbase', 'prepare_error',
           'new_head_discard', 'commit_error'}
STAGES={'task_offer','task_sent','task_received','task_duplicate','task_skipped','task_abandoned','seal_enter','seal_return','seal_unsupported','request_post_enter','request_post_return','seal_result','seal_cancel'}


def unique_object(items):
    row = {}
    for key, value in items:
        if key in row:
            raise ValueError('duplicate JSON key')
        row[key] = value
    return row


def integer(value):
    return type(value) is int and 0 <= value <= (1 << 64) - 1


def decimal(value, optional=False):
    return isinstance(value, str) and (optional and value == '' or
                                     re.fullmatch(r'0|[1-9][0-9]*', value) is not None)


def inspect(path):
    path = Path(path)
    problems, unavailable = [], []
    starts, ends, durations = {}, {}, {}
    stages=[]
    kinds = Counter()
    previous = -1
    identity = None
    missing = 0
    final = None
    for line, raw in enumerate(path.read_text().splitlines(), 1):
        try:
            r = json.loads(raw, object_pairs_hook=unique_object)
            kind = r.get('type') if isinstance(r, dict) else None
            if kind not in FIELDS or set(r) != COMMON | FIELDS[kind]:
                raise ValueError('unknown type or fields')
            if type(r['v']) is not int or r['v'] != 1:
                raise ValueError('unsupported version')
            for key in ['seq', 't_mono_ns']:
                if not integer(r[key]):
                    raise ValueError('invalid ' + key)
            if not isinstance(r['t_wall'], str) or not r['t_wall'].endswith('Z'):
                raise ValueError('invalid wall clock')
            datetime.fromisoformat(r['t_wall'].replace('Z', '+00:00'))
            if not isinstance(r['node'], str) or not re.fullmatch(r'0x[0-9a-f]{40}', r['node']):
                raise ValueError('invalid node')
            if not isinstance(r['run'], str) or not r['run']:
                raise ValueError('invalid run')
            current = (r['node'], r['run'])
            if identity is not None and identity != current:
                raise ValueError('mixed identity')
            identity = current
            if r['seq'] <= previous:
                raise ValueError('sequence repeated or reversed')
            missing += r['seq'] - previous - 1
            previous = r['seq']
            if final is not None:
                raise ValueError('record after capture end')
            if kind == 'runtime_start':
                c = r['config']
                if not isinstance(c, dict) or set(c) != CONFIG or c['Address'].lower() != r['node']:
                    raise ValueError('invalid runtime identity/configuration')
                for key in CONFIG - {'Address', 'Transitions', 'SystemContractUpgrades'}:
                    if not decimal(c[key], key == 'ProposerPolicy'):
                        raise ValueError('invalid configuration ' + key)
                if not integer(c['Transitions']) or not integer(c['SystemContractUpgrades']):
                    raise ValueError('invalid transition counts')
            elif kind.startswith('operation_'):
                if not integer(r['id']) or r['id'] == 0 or not decimal(r['height'], True):
                    raise ValueError('invalid operation identity or height')
                if not isinstance(r['hash'], str) or r['hash'] and not re.fullmatch(r'0x[0-9a-fA-F]{64}', r['hash']):
                    raise ValueError('invalid block hash')
                if kind == 'operation_start':
                    if r['operation'] not in OPERATIONS or not integer(r['count']) or r['id'] in starts:
                        raise ValueError('invalid or duplicate operation start')
                    starts[r['id']] = r
                elif kind == 'operation_stage':
                    if r['stage'] not in STAGES or not r['height'] or not r['hash']:
                        raise ValueError('invalid task stage')
                    stages.append(r)
                else:
                    if r['result'] not in RESULTS or not integer(r['index']) or r['id'] in ends:
                        raise ValueError('invalid or duplicate operation end')
                    ends[r['id']] = r
            elif kind == 'runtime_close':
                if r['engine_stopped'] is not False:
                    raise ValueError('no-op close cannot establish engine stop')
            elif kind == 'runtime_stop':
                if r['result'] not in {'ok', 'error'}:
                    raise ValueError('invalid stop result')
            else:
                if not integer(r['dropped']):
                    raise ValueError('invalid dropped count')
                final = r
            kinds[kind] += 1
        except (TypeError, KeyError, ValueError, AttributeError) as error:
            problems.append({'line': line, 'error': str(error)})
    if final is None:
        unavailable.append('normal capture end absent')
    else:
        if final['dropped']:
            unavailable.append('observation records dropped')
        if missing != final['dropped']:
            problems.append({'error': 'sequence gaps differ from dropped count'})
    for key in starts.keys() | ends.keys():
        if key not in starts or key not in ends:
            unavailable.append('operation boundary absent: ' + str(key))
            continue
        start, end = starts[key], ends[key]
        delta = end['t_mono_ns'] - start['t_mono_ns']
        if delta < 0:
            problems.append({'error': 'operation monotonic interval reversed', 'id': key})
            continue
        durations.setdefault(start['operation'], []).append(delta)
    if not kinds['runtime_start']:
        unavailable.append('runtime_start absent')
    if not kinds['runtime_stop'] and not kinds['runtime_close']:
        unavailable.append('runtime stop/close observation absent')
    for stage in stages:
        if stage['id'] not in starts or starts[stage['id']]['operation']!='worker_commit_work':
            problems.append({'error':'stage has no exact worker operation'})
    return {'format': 'wbft-tap-observations/2' if stages else 'wbft-tap-observations/1', 'identity': identity,
            'records': sum(kinds.values()), 'kinds': dict(kinds), 'sequence_gaps': missing,
            'problems': problems, 'unavailable': unavailable,
            'capture_complete': not problems and not unavailable,
            'call_intervals': {key: {'count': len(values), 'min_ns': min(values), 'max_ns': max(values)}
                               for key, values in durations.items()},
            'runtime_stop_observed': bool(kinds['runtime_stop']),
            'runtime_model_complete': False, 'delivery_coverage_proven': False,
            'application_request_completion_proven': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('path', type=Path)
    args = parser.parse_args()
    try:
        result = inspect(args.path)
    except (OSError, UnicodeError) as error:
        parser.exit(64, str(error) + '\n')
    print(json.dumps(result, indent=2))
    raise SystemExit(64 if result['problems'] else 0 if result['capture_complete'] else 65)


if __name__ == '__main__':
    main()
