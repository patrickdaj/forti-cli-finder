#!/usr/bin/env python3
"""Say what a rebuild changed in the bundles, in commands rather than in bytes.

The bundles are minified JSON on one line, so `git diff --stat` reports every rebuild as
"1 insertion, 1 deletion" whatever happened inside. The weekly refresh workflow opens a
pull request on the promise that a human glances at the data diff before it goes live;
without this that glance has nothing to look at.

Compares the built bundles against a git revision (HEAD by default):

  python3 tools/diff_bundles.py                 # working tree vs HEAD
  python3 tools/diff_bundles.py --rev main      # vs another revision
  python3 tools/diff_bundles.py --full          # list every added/removed command

Exit status is 0 whether or not anything changed -- this reports, it does not gate.
"""
import collections, json, os, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.environ.get('OUT', 'site/data')
LIST = 12          # commands listed per section before it is summarised


def at_rev(rev, path):
    try:
        blob = subprocess.run(['git', '-C', ROOT, 'show', f'{rev}:{path}'],
                              capture_output=True, check=True).stdout
    except subprocess.CalledProcessError:
        return None
    return json.loads(blob)


def index(b):
    """(kind, path) -> what we care about having changed."""
    return {(s['k'], s['p']): (len(s.get('x') or ()), len(s.get('o') or ()),
                               len(s.get('e') or ())) for s in b['secs']}


def names(keys):
    return sorted(f'{k} {p}' for k, p in keys)


def show(title, keys):
    if not keys:
        return
    n = names(keys)
    print(f'  {title}: {len(n)}')
    for x in n[:LIST]:
        print(f'      {x}')
    if len(n) > LIST:
        print(f'      ... and {len(n) - LIST} more')


def main():
    rev = 'HEAD'
    if '--rev' in sys.argv:
        rev = sys.argv[sys.argv.index('--rev') + 1]
    full = '--full' in sys.argv
    global LIST
    if full:
        LIST = 10 ** 9

    here = os.path.join(ROOT, OUT)
    files = sorted(f for f in os.listdir(here) if f.endswith('.json'))
    old_files = subprocess.run(['git', '-C', ROOT, 'ls-tree', '--name-only', rev, OUT + '/'],
                               capture_output=True, text=True).stdout.split()
    old_names = sorted(os.path.basename(f) for f in old_files if f.endswith('.json'))

    for f in sorted(set(files) | set(old_names)):
        path = f'{OUT}/{f}'
        old = at_rev(rev, path)
        new = json.load(open(os.path.join(here, f))) if f in files else None
        if old is None:
            print(f'\n=== {f}  NEW BUNDLE ({len(new["secs"])} commands)')
            continue
        if new is None:
            print(f'\n=== {f}  REMOVED (was {len(old["secs"])} commands)')
            continue

        a, b = index(old), index(new)
        added, gone = set(b) - set(a), set(a) - set(b)
        both = set(a) & set(b)
        argc = [k for k in both if a[k][0] != b[k][0]]
        outc = [k for k in both if a[k][1] != b[k][1]]
        exc = [k for k in both if a[k][2] != b[k][2]]

        def tot(d, i):
            return sum(v[i] for v in d.values())

        changed = added or gone or argc or outc or exc
        head = f'\n=== {f}'
        if not changed:
            print(f'{head}  unchanged ({len(b)} commands)')
            continue
        print(head)
        ka = collections.Counter(k for k, _ in added)
        kg = collections.Counter(k for k, _ in gone)
        print(f'  commands {len(a)} -> {len(b)}'
              + (f'   +{len(added)} {dict(sorted(ka.items()))}' if added else '')
              + (f'   -{len(gone)} {dict(sorted(kg.items()))}' if gone else ''))
        print(f'  arguments {tot(a,0)} -> {tot(b,0)}'
              f'   output samples {tot(a,1)} -> {tot(b,1)}'
              f'   worked examples {tot(a,2)} -> {tot(b,2)}')
        show('added', added)
        show('removed', gone)
        if argc:
            lost = [k for k in argc if b[k][0] < a[k][0]]
            print(f'  argument counts changed on {len(argc)} commands '
                  f'({len(lost)} lost arguments)')
            for k in names(lost)[:LIST]:
                kk = tuple(k.split(' ', 1))
                print(f'      {k}: {a[kk][0]} -> {b[kk][0]}')
        if outc:
            lost = [k for k in outc if b[k][1] < a[k][1]]
            print(f'  output samples changed on {len(outc)} commands '
                  f'({len(lost)} lost output)')
        if exc:
            lost = [k for k in exc if b[k][2] < a[k][2]]
            print(f'  worked examples changed on {len(exc)} commands '
                  f'({len(lost)} lost examples)')
    print()
    return 0


if __name__ == '__main__':
    sys.exit(main())
