#!/usr/bin/env python3
"""Attach sample outputs mined from the guides to commands in the Finder bundles.

Which guides, what they are called and which bundle each may land in all come from
sources.json; this script only does the matching. A sample attaches to the longest
command path it starts with (CLI-style prefixes allowed, so `diag sys ha stat` finds
`diagnose system ha status`). A sample that matches no command becomes a new get/show
entry, which is how commands the CLI Reference omits still show up.

Ranking per command, best first: hand-annotated samples (they carry a "look for" note),
then by source rank from sources.json (current firmware before older), then the sample
whose command is exactly the section's path, then the longest output. Max 8 per command.
"""
import json, os, re, sys
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SC = os.environ.get('WORK', 'work')
D = os.environ.get('OUT', 'site/data')
CFG = json.load(open(os.path.join(ROOT, 'sources.json')))

# ---- sources ---------------------------------------------------------------
SRC = {}          # key -> human title, written into the bundle for the source line
RANK = {}         # key -> tie-break weight
TARGET = {}       # key -> bundles a sample from here may attach to
for e in CFG['output'] + CFG['hand']:
    SRC[e['key']] = e['title']
    RANK[e['key']] = e.get('rank', 0)
    TARGET[e['key']] = e['target']
    if e.get('lab_key'):                      # annotated course material splits study/lab
        SRC[e['lab_key']] = e['lab_title']
        RANK[e['lab_key']] = e.get('rank', 0)

PRODUCTS = [e['product'] for e in CFG['cli']]
B = {p: json.load(open(f'{D}/{p}.json')) for p in PRODUCTS}
for p, b in B.items():
    assert not any(s.get('ag') or s.get('o') for s in b['secs']), \
        f'{p}: bundle already has samples -- run build_bundles.py first'

# ---- index the command paths ------------------------------------------------
idx = {p: defaultdict(list) for p in B}
for p, b in B.items():
    for i, s in enumerate(b['secs']):
        pw = []
        for w in s['p'].split():
            if w[:1] in '<{[':
                break                         # placeholder: the rest is an argument
            pw.append(w)
        if pw:
            idx[p][s['k']].append((pw, i))
tops = {p: {s['p'].split()[0] for s in b['secs'] if s['k'] == 'config'} for p, b in B.items()}

ARG = re.compile(r'^\d|[./:"\'<>=,*\[\]{}|$?]|[A-Z]')


def pathwords(words):
    out = []
    for w in words:
        if ARG.search(w) or w.startswith('-'):
            break
        out.append(w)
    return out


def match(product, kind, rest):
    best = None
    for pw, i in idx[product].get(kind, []):
        if len(pw) <= len(rest) and all(
                a == b or (len(a) >= 2 and b.startswith(a)) or (len(b) >= 3 and a.startswith(b))
                for a, b in zip(rest, pw)):
            sc = (len(pw), sum(a == b for a, b in zip(rest, pw)))
            if best is None or sc > best[1]:
                best = (i, sc)
    return best


# ---- load the mined samples -------------------------------------------------
def load_samples(e):
    key = e['key']
    if 'file' in e:                           # transcribed by hand, each with a "look for" note
        out = []
        for o in json.load(open(os.path.join(ROOT, e['file']))):
            out.append({'cmd': o['cmd'], 'out': o['out'], 'cap': o['cap'], 'pg': o['pg'],
                        'g': o['g'], 'src': e['lab_key'] if o.get('lab') else key})
        return out
    path = f'{SC}/{key}/samples.json'
    return json.load(open(path)) if os.path.exists(path) else []


att = {p: defaultdict(list) for p in B}
new = {p: {} for p in B}
stats = defaultdict(lambda: defaultdict(int))

for e in CFG['output'] + CFG['hand']:
    key = e['key']
    for smp in load_samples(e):
        cmd = re.sub(r'\s+', ' ', smp['cmd'].replace('​', '')).strip()
        w = cmd.split()
        if len(w) < 2:
            stats[key]['dropped'] += 1
            continue
        kind, rest = w[0], w[1:]
        o = {'c': cmd, 't': smp['out'], 'cap': re.sub(r'\s*:\s*$', '', smp['cap']),
             'pg': smp['pg'], 'src': smp.get('src', key)}
        if smp.get('g'):
            o['g'] = smp['g']

        cands = [p for p in TARGET[key] if p in B]
        hits = [(p, m) for p, m in ((p, match(p, kind, rest)) for p in cands) if m]
        if hits:
            if len(hits) > 1:
                # A guide that covers both ends of a FortiLink pair: decide by where the
                # command actually runs.
                on_fgt = 'switch-controller' in cmd or (
                    'FortiGate' in smp['cap'] and 'FortiSwitch' not in smp['cap'])
                hits.sort(key=lambda h: (h[1][1][0], (h[0] == 'fortios') == on_fgt), reverse=True)
            product, (i, _) = hits[0]
            att[product][i].append(o)
            stats[key]['attached:' + product] += 1
            continue

        # no match: keep it as a new entry, but only where that is safe
        p = ' '.join(pathwords(rest))
        if not p:
            stats[key]['dropped'] += 1
            continue
        if len(cands) == 1:
            product = cands[0]
        else:
            product = 'fortios' if ('switch-controller' in cmd or (
                'FortiGate' in smp['cap'] and 'FortiSwitch' not in smp['cap'])) else 'fortiswitch'
        # For a guide that spans products, an unmatched command is as likely to be a third
        # party's ('show run' on a Cisco switch) as ours -- keep only plausible ones.
        if len(cands) > 1 and (kind not in ('get', 'show') or p.split()[0] not in tops[product]):
            stats[key]['dropped'] += 1
            continue
        new[product].setdefault((kind, p), []).append(o)
        stats[key]['new:' + product] += 1


def rank(lst, base):
    seen, out = set(), []
    for o in sorted(lst, key=lambda o: ('g' not in o, RANK.get(o['src'], 0), o['c'] != base,
                                        -len([x for x in o['t'].split('\n')
                                              if x.strip() and x.strip() != '...']))):
        sig = o['t'][:200]
        if sig in seen:
            continue
        seen.add(sig)
        out.append(o)
    return out[:8]


for product, b in B.items():
    for i, lst in att[product].items():
        s = b['secs'][i]
        s['o'] = rank(lst, s['k'] + ' ' + s['p'])
    for (kind, p), lst in sorted(new[product].items()):
        r = rank(lst, kind + ' ' + p)
        b['secs'].append({'k': kind, 'p': p, 'd': '', 'pg': r[0]['pg'], 's': '', 'x': [],
                          'o': r, 'ag': r[0]['src']})
    b['srcs'] = SRC
    json.dump(b, open(f'{D}/{product}.json', 'w'), ensure_ascii=False, separators=(',', ':'))
    n_out = sum(1 for s in b['secs'] if s.get('o'))
    print(f'{product:14s} {n_out:5d} commands with output, '
          f'{sum(len(s.get("o", [])) for s in b["secs"]):5d} samples, '
          f'{len(new[product]):4d} new entries   ({n_out*100.0/len(b["secs"]):.1f}% of {len(b["secs"])})')
for key, st in stats.items():
    print('  ', key, dict(st))
