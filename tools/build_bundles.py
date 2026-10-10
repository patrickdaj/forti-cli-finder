#!/usr/bin/env python3
"""Turn the parsed CLI trees (work/<key>/tree.json) into one bundle per build in site/data/.

A platform may have several builds (FortiOS 7.6.7 and 8.0.1), each its own bundle file.
Which file an entry writes to is bundle_id() in check_bundles.py, not `product`.

Keys are short because the whole bundle ships to the browser:
  k kind   p path   d description   pg page   s syntax   n notes   e examples
  x parameters: n name  k key  d description  t sub-table  ty type  sz size  df default
                o options [[value, description]]  f model flag  el element placeholder
                m 1 if the parameter takes a list of values
"""
import json, gzip, importlib.util, os, re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORK = os.environ.get('WORK', 'work')
OUT = os.environ.get('OUT', 'site/data')
CFG = json.load(open(os.path.join(ROOT, 'sources.json')))

# bundle_id lives in check_bundles.py so the build and its checker cannot disagree
# about which file an entry writes to.
_spec = importlib.util.spec_from_file_location(
    'check_bundles', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'check_bundles.py'))
_cb = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_cb)
bundle_id = _cb.bundle_id

for e in CFG['cli']:
    S = json.load(open(f"{WORK}/{e['key']}/tree.json"))
    secs = []
    # the same 133-model list is repeated by dozens of sections; store each one once
    model_lists, model_idx = [], {}
    for s in S:
        if s.get('index'):
            continue
        if not s['syntax'] and not s['params']:
            continue
        syn = '\n'.join(l for l in s['syntax'] if not l.strip().startswith('Description:')).strip('\n')
        syn = re.sub(r'\n{2,}', '\n\n', syn)
        o = {'k': s['kind'], 'p': s['path'], 'd': s['desc'], 'pg': s['page'], 's': syn}
        if s.get('models'):
            sig = '\u0000'.join(s['models'])
            if sig not in model_idx:
                model_idx[sig] = len(model_lists)
                model_lists.append(s['models'])
            o['mi'] = model_idx[sig]
        if s.get('notes'):
            o['n'] = s['notes']
        if s.get('examples'):
            o['e'] = s['examples']
        ps, seen = [], set()
        for p in s['params']:
            if (p.get('table', ''), p['name']) in seen:
                continue
            seen.add((p.get('table', ''), p['name']))
            q = {'n': p['name'], 'k': p['key'], 'd': p['desc']}
            if p.get('table') and p['table'] != s['path']:
                q['t'] = p['table']
            if p.get('type'):
                q['ty'] = p['type']
            if p.get('size') and p['size'] not in ('-', ''):
                q['sz'] = p['size']
            if p.get('default'):
                q['df'] = p['default']
            if p.get('options'):
                q['o'] = [[x['v'], x['desc']] for x in p['options']]
            if p.get('flag'):
                q['f'] = p['flag']
            if p.get('elem'):
                # the CLI Reference prints a list parameter's element on its own row;
                # keeping it says both "what goes here" and "more than one may go here"
                q['el'] = p['elem']
                q['m'] = 1
            ps.append(q)
        o['x'] = ps
        secs.append(o)
    b = {'id': e['product'], 'bundle': bundle_id(e), 'label': e['label'],
         'short': e['short'], 'doc': e['title'], 'ver': e.get('ver', ''),
         'src': e.get('src', e['title']), 'secs': secs}
    if model_lists:
        b['models'] = model_lists
    raw = json.dumps(b, ensure_ascii=False, separators=(',', ':'))
    bid = bundle_id(e)
    open(f'{OUT}/{bid}.json', 'w').write(raw)
    gz = gzip.compress(raw.encode(), 9)
    print(f"{bid:16s} {len(secs):5d} secs {sum(len(s['x']) for s in secs):6d} params  "
          f"{len(raw)//1024:5d} KB raw {len(gz)//1024:4d} KB gz")
