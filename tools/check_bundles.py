#!/usr/bin/env python3
"""Check the built bundles hold together. Run by build.sh; also runnable alone.

There is no test suite here -- the bundles are the thing worth asserting about, so this
is where the build's invariants live. Every failure names the bundle and what broke.
"""
import json, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.environ.get('OUT', 'site/data')
NAME = re.compile(r'^[a-z0-9]+(-[0-9.]+)?$')


def bundle_id(entry):
    """The bundle a cli entry builds into.

    Defaults to the platform id, so an entry written before there was more than one build
    per platform keeps its present filename. This is the one definition of the rule --
    build_bundles, the attach steps and stamp_build all import it rather than repeat it.
    """
    return entry.get('bundle') or entry['product']


def main():
    cfg = json.load(open(os.path.join(ROOT, 'sources.json')))
    fail = []

    ids = [bundle_id(e) for e in cfg['cli']]
    for b in ids:
        if not NAME.match(b):
            fail.append(f'bundle id {b!r} is not [a-z0-9]+(-[0-9.]+)?')
    if len(set(ids)) != len(ids):
        dupes = sorted({b for b in ids if ids.count(b) > 1})
        fail.append(f'two cli entries build into the same bundle: {dupes}')

    for e in cfg['cli']:
        b = bundle_id(e)
        path = f'{OUT}/{b}.json'
        if not os.path.exists(path):
            fail.append(f'{b}: {path} was not built')
            continue
        d = json.load(open(path))
        if d.get('id') != e['product']:
            fail.append(f"{b}: bundle id is {d.get('id')!r}, expected {e['product']!r}")
        if not d.get('secs'):
            fail.append(f'{b}: no sections')

    page = open(os.path.join(ROOT, 'site/index.html'), encoding='utf-8').read()
    for e in cfg['cli']:
        b = bundle_id(e)
        if f'f:"{b}"' not in page:
            fail.append(f'{b}: not named in index.html PRODUCTS -- run stamp_build.py')
        if not e.get('ver'):
            fail.append(f'{b}: sources.json entry has no "ver", so /ver cannot label it')
    seen = {}
    for e in cfg['cli']:
        seen.setdefault(e['product'], []).append(e.get('ver'))
    for p, vs in sorted(seen.items()):
        if len(vs) != len(set(vs)):
            fail.append(f'{p}: two builds claim version {vs}')

    for f in fail:
        print(f'  FAIL {f}', file=sys.stderr)
    print(f'{len(ids)} bundles checked, {len(fail)} problems')
    return 1 if fail else 0


if __name__ == '__main__':
    sys.exit(main())
