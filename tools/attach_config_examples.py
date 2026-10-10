#!/usr/bin/env python3
"""Attach guide config examples to their tables, and mark how often each field is set.

Nothing in the CLI Reference says which fields a table actually needs -- FortiOS only
complains at `end`. But Fortinet's own guides configure these tables hundreds of times,
and that is evidence: across the Administration Guide's `config firewall policy` examples,
srcintf, dstintf, action, srcaddr, schedule, dstaddr and service appear in over 90%.

So each parameter gets `fq`, the percentage of that table's examples which set it, and
each table keeps a few worked examples. `fq` is only written where there are at least
MIN_EX examples to count, so a lone example never looks like a rule.
"""
import json, os, re
from collections import defaultdict, Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SC = os.environ.get('WORK', 'work')
D = os.environ.get('OUT', 'site/data')
CFG = json.load(open(os.path.join(ROOT, 'sources.json')))

import importlib.util
_spec = importlib.util.spec_from_file_location(
    'check_bundles', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'check_bundles.py'))
_cb = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_cb)


MIN_EX = 5          # below this, a percentage is noise
MAX_KEEP = 3        # worked examples kept per table

# every example from every output guide, by table
TARGET = {e['key']: e['target'] for e in CFG['output']}
by_table = defaultdict(list)
for e in CFG['output']:
    path = f"{SC}/{e['key']}/config-examples.json"
    if not os.path.exists(path):
        continue
    for r in json.load(open(path)):
        r['src'] = e['key']
        r['rank'] = e.get('rank', 0)
        by_table[r['t']].append(r)

# Don't show the same example twice *within a bundle* -- but each build gets its own
# pool. Two builds of one platform are alternative views of the same CLI, not two halves
# of it, so the second must not be left with whatever the first declined.
for e in CFG['cli']:
    seen_global = set()
    pid = _cb.bundle_id(e)
    path = f'{D}/{pid}.json'
    b = json.load(open(path))
    n_ex = n_fq = 0
    for s in b['secs']:
        if s['k'] != 'config' or s.get('dv'):
            continue
        rows = by_table.get(s['p'], [])
        if not rows:
            continue
        # how often each field is set, counted once per example
        total = len(rows)
        hits = Counter()
        for r in rows:
            for f in r['f']:
                hits[f] += 1
        if total >= MIN_EX:
            for p in s['x']:
                if p.get('t'):
                    continue            # sub-table fields are counted in their own block
                c = hits.get(p['k'], 0)
                if c:
                    p['fq'] = min(100, round(c * 100 / total))
                    n_fq += 1
            s['ex'] = total
        # keep a few short, complete, distinct examples, current firmware first
        keep, sigs = [], set()
        for r in sorted(rows, key=lambda r: (r['rank'], len(r['x']))):
            # A table name is not unique across platforms -- `system global` exists on all
            # four -- so honour the guide's target the way attach_outputs.py does, or a
            # FortiGate example turns up under a FortiSwitch table.
            if pid not in TARGET.get(r['src'], ()):
                continue
            sig = '\n'.join(r['x'])
            if sig in sigs or sig in seen_global or len(r['x']) < 3:
                continue
            sigs.add(sig)
            seen_global.add(sig)
            keep.append('\n'.join(r['x']))
            if len(keep) >= MAX_KEEP:
                break
        if keep:
            s['e'] = keep
            n_ex += len(keep)
    json.dump(b, open(path, 'w'), ensure_ascii=False, separators=(',', ':'))
    tables = sum(1 for s in b['secs'] if s.get('e'))
    print(f'{pid:14s} {n_ex:4d} examples on {tables:3d} tables, {n_fq:5d} fields given a frequency')
