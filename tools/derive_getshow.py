#!/usr/bin/env python3
"""Derive `get` and `show` entries for every configuration table.

The FortiOS CLI Reference documents no get and no show commands at all -- it is generated
from the configuration tree, and that tree only describes `config`. But the relationship is
exact: wherever `config firewall policy` exists, `show firewall policy` and
`get firewall policy` are valid and display what it sets, optionally narrowed to one entry
by the table's key. So those are derivable, and this writes them.

What is NOT derivable, and is deliberately not invented here: the diagnostic read tree
(`get router info bgp network`, `get system performance status`). Those are not views of a
config object, they are their own commands with their own arguments, and nothing in the
reference describes them. They stay as whatever the guides happen to show.

Entries written here carry "dv":1 so the page can say where they came from, and they are
skipped where the platform's reference already documents the command.
"""
import json, os, re

OUT = os.environ.get('OUT', 'site/data')
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CFG = json.load(open(os.path.join(ROOT, 'sources.json')))

import importlib.util
_spec = importlib.util.spec_from_file_location(
    'check_bundles', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'check_bundles.py'))
_cb = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_cb)


EDIT = re.compile(r'^\s*edit\s+(<[^>]+>)', re.M)

for e in CFG['cli']:
    pid = _cb.bundle_id(e)
    path = f'{OUT}/{pid}.json'
    b = json.load(open(path))
    have = {(s['k'], s['p']) for s in b['secs']}
    add = []
    # The hand guides give several config subsections one path -- five share
    # `fmupdate fds-setting` -- and one `show` covers them all. Take the key from
    # whichever of them documents one, rather than from whichever comes first: it is the
    # same table, and an `edit <id>` seen on any subsection is true of the whole.
    keyof = {}
    for s in b['secs']:
        if s['k'] != 'config' or s.get('dv') or keyof.get(s['p']):
            continue
        m = EDIT.search(s.get('s') or '')
        if m:
            keyof[s['p']] = m.group(1)

    for s in list(b['secs']):
        if s['k'] != 'config' or s.get('dv'):
            continue
        key = keyof.get(s['p'])
        for kind, what in (('show', 'the configuration'), ('get', 'the settings')):
            if (kind, s['p']) in have:
                continue            # the reference documents this one already, or a
                                    # sibling config section already derived it: the hand
                                    # guides give several subsections one path (five share
                                    # `fmupdate fds-setting`), and one `show` covers them
            have.add((kind, s['p']))
            o = {'k': kind, 'p': s['p'],
                 'd': f"Display {what} that config {s['p']} sets.",
                 'pg': s['pg'], 's': f"{kind} {s['p']}" + (f" [{key}]" if key else ''),
                 'x': [], 'dv': 1}
            if key:
                o['x'] = [{'n': key, 'k': key,
                           'd': 'Limit the output to this entry. Omit it to show them all.',
                           'ty': 'string'}]
            add.append(o)
    b['secs'].extend(add)
    json.dump(b, open(path, 'w'), ensure_ascii=False, separators=(',', ':'))
    n_show = sum(1 for o in add if o['k'] == 'show')
    print(f"{pid:14s} +{len(add):5d} derived ({n_show} show, {len(add)-n_show} get) "
          f"from {sum(1 for s in b['secs'] if s['k']=='config')} config tables")
