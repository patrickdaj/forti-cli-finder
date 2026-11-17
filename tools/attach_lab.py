#!/usr/bin/env python3
"""Attach the lab's sample output (lab-overlay.json) to the commands in the bundles.

lab-overlay.json is written by import_lab.py, already anonymised. This only decides where
each sample goes:

- The bundle is the platform's build on the sample's train: a 7.6.7 lab box feeds the
  7.6.7 bundle, an 8.0.2 box the 8.0 bundle. A train we ship no bundle for is dropped,
  never folded into the nearest one -- its output is not that build's.
- The command is the longest one the sample's command starts with, as attach_outputs.py
  matches guide samples, with `show full-configuration X` read as `show X`. The words
  left over must be arguments, so the command has to take some; otherwise the sample
  is dropped. A lab command is never added as a new entry: its paths carry object
  names (`list name H1_T11`) that would read as commands.
- It goes after the guide samples (a guide is the citation; the lab is one box) and,
  by being the command's own, ahead of the parent's output the page would otherwise
  borrow.

Its source line is the build string and the date, where a guide's is a page number.
Idempotent: a rebuild starts from fresh bundles, and a second run adds nothing.

  python3 tools/attach_lab.py             # attach, print counts
  python3 tools/attach_lab.py --selftest
"""
import collections, json, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.environ.get('OUT', 'site/data')
OVERLAY = os.path.join(ROOT, 'lab-overlay.json')
PREFIX = 'lab:'                      # srcs key prefix; the page tells lab samples by it


def train(ver):
    return '.'.join(ver.split('.')[:2])


def bundle_id(entry):
    return entry.get('bundle') or entry['product']


def index(bun):
    """kind -> [(path words before the first placeholder, section index)]."""
    idx = collections.defaultdict(list)
    for i, s in enumerate(bun['secs']):
        pw = []
        for w in s['p'].split():
            if w[:1] in '<{[':
                break
            pw.append(w)
        if pw:
            idx[s['k']].append((pw, i))
    return idx


def takes_args(s):
    return bool(s.get('x')) or any(w[:1] in '<{[' for w in s['p'].split())


def find(bun, idx, k, p):
    """The section a sample of `k p` belongs to, or None."""
    words = p.split()
    if k == 'show' and words[:1] == ['full-configuration']:
        words = words[1:]
    best = None
    for pw, i in idx.get(k, ()):
        if len(pw) <= len(words) and words[:len(pw)] == pw:
            if best is None or len(pw) > best[0]:
                best = (len(pw), i)
    if best is None:
        return None
    n, i = best
    if n < len(words) and not takes_args(bun['secs'][i]):
        return None
    return i


def attach(bundles, by_train, samples):
    """bundles: {bundle id: bundle}; by_train: {(product, train): bundle id}.
    Mutates the bundles; returns a Counter of what happened."""
    st = collections.Counter()
    idx = {}
    for prod, lst in sorted(samples.items()):
        for smp in lst:
            b = by_train.get((prod, smp['train']))
            if b is None or b not in bundles:
                st['dropped: no bundle for the train'] += 1
                continue
            bun = bundles[b]
            if b not in idx:
                idx[b] = index(bun)
            i = find(bun, idx[b], smp['k'], smp['p'])
            if i is None:
                st['dropped: no command it fits'] += 1
                continue
            key = PREFIX + smp['build']
            o = {'c': smp['c'], 't': smp['t'], 'cap': smp['cap'], 'pg': '',
                 'src': key, 'dt': smp['date']}
            sec = bun['secs'][i]
            have = sec.setdefault('o', [])
            if any(x['t'][:200] == o['t'][:200] for x in have):
                st['already there'] += 1
                continue
            st['attached, beside guide output' if have else 'attached, the only output'] += 1
            have.append(o)
            bun.setdefault('srcs', {})[key] = 'lab, ' + smp['build']
            st['bundle:' + b] += 1
    return st


def main():
    if not os.path.exists(OVERLAY):
        print('  no lab-overlay.json -- nothing to attach')
        return 0
    cfg = json.load(open(os.path.join(ROOT, 'sources.json')))
    by_train = {(e['product'], train(e['ver'])): bundle_id(e) for e in cfg['cli']}
    paths = {b: os.path.join(ROOT, OUT, f'{b}.json') for b in by_train.values()}
    bundles = {b: json.load(open(p)) for b, p in paths.items() if os.path.exists(p)}
    st = attach(bundles, by_train, json.load(open(OVERLAY))['samples'])
    for b, bun in sorted(bundles.items()):
        if st['bundle:' + b]:
            open(paths[b], 'w').write(json.dumps(bun, ensure_ascii=False, separators=(',', ':')))
    for k, v in sorted(st.items()):
        print(f'  {k:36s} {v:4d}')
    return 0


def selftest():
    fails = []

    def check(name, got, want):
        if got != want:
            fails.append(f'  {name}: got {got!r}, want {want!r}')
        else:
            print(f'  ok   {name}')

    def bun():
        return {'secs': [
            {'k': 'diagnose', 'p': 'vpn ike gateway list', 'x': [{'n': 'name', 'k': 'name', 'd': ''}]},
            {'k': 'diagnose', 'p': 'vpn ike', 'x': []},
            {'k': 'get', 'p': 'system status', 'x': [],
             'o': [{'c': 'get system status', 't': 'guide text', 'pg': '12', 'src': 'g'}]},
            {'k': 'show', 'p': 'system settings', 'x': []},
            {'k': 'get', 'p': 'router info routing-table details <A.B.C.D>', 'x': []},
        ]}

    def smp(c, train='7.6', t='out'):
        k, p = c.split(' ', 1)
        return {'k': k, 'p': p, 'c': c, 't': t, 'cap': 'cap', 'train': train,
                'build': 'FortiGate-VM64-KVM v7.6.7 build3704', 'date': '2026-11-03'}

    b = bun()
    ix = index(b)
    check('arguments after a command that takes them',
          find(b, ix, 'diagnose', 'vpn ike gateway list name H1_T11'), 0)
    check('the longest command wins over its parent',
          find(b, ix, 'diagnose', 'vpn ike gateway list'), 0)
    check('leftover words on a command with no arguments are not arguments',
          find(b, ix, 'get', 'system status extra'), None)
    check('a placeholder in the path counts as taking arguments',
          find(b, ix, 'get', 'router info routing-table details 10.0.0.1'), 4)
    check('show full-configuration X is show X',
          find(b, ix, 'show', 'full-configuration system settings'), 3)
    check('no fit at all', find(b, ix, 'diagnose', 'netlink brctl name host sw1'), None)

    bundles = {'fortios': bun(), 'fortios-8.0': bun()}
    by_train = {('fortios', '7.6'): 'fortios', ('fortios', '8.0'): 'fortios-8.0'}
    st = attach(bundles, by_train, {'fortios': [
        smp('get system status'),
        smp('diagnose vpn ike gateway list name T1', train='8.0'),
        smp('get system status', train='9.9'),
        smp('diagnose netlink brctl name host sw1'),
    ], 'fortimanager': [smp('get system status')]})
    o = bundles['fortios']['secs'][2]['o']
    check('a lab sample goes after the guide one', [x['src'][:4] for x in o], ['g', 'lab:'])
    check('it carries no page and a date', (o[1]['pg'], o[1]['dt']), ('', '2026-11-03'))
    check('the source names the build',
          bundles['fortios']['srcs'][o[1]['src']], 'lab, FortiGate-VM64-KVM v7.6.7 build3704')
    check('an 8.0 sample lands in the 8.0 bundle only',
          ('o' in bundles['fortios-8.0']['secs'][0], 'o' in bundles['fortios']['secs'][0]),
          (True, False))
    check('a train with no bundle, or a platform with none, is dropped',
          st['dropped: no bundle for the train'], 2)
    check('an unfitted command is dropped, not added',
          (st['dropped: no command it fits'], len(bundles['fortios']['secs'])), (1, 5))
    st2 = attach(bundles, by_train, {'fortios': [smp('get system status')]})
    check('a second run adds nothing', (st2['already there'], len(o)), (1, 2))

    if fails:
        print('\nFAIL\n' + '\n'.join(fails))
        return 1
    print('\nselftest: all good')
    return 0


if __name__ == '__main__':
    sys.exit(selftest() if '--selftest' in sys.argv[1:] else main())
