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
        path = os.path.join(ROOT, OUT, f'{b}.json')
        if not os.path.exists(path):
            fail.append(f'{b}: {path} was not built')
            continue
        d = json.load(open(path))
        if d.get('id') != e['product']:
            fail.append(f"{b}: bundle id is {d.get('id')!r}, expected {e['product']!r}")
        if not d.get('secs'):
            fail.append(f'{b}: no sections')
        # The page does p.k.toLowerCase() on every parameter while indexing, so a
        # parameter MISSING its key throws and leaves the page stuck on "loading
        # reference data". An empty key is harmless -- ''.toLowerCase() is fine -- and
        # three of those exist from a `threshold(default)` field the parser splits oddly.
        nok = [(x['k'], x['p'], p2.get('n'))
               for x in d['secs'] for p2 in (x.get('x') or []) if 'k' not in p2]
        if nok:
            fail.append(f'{b}: {len(nok)} parameters have no "k" key at all '
                        f'(the page throws on these) -- first: {nok[0]}')
        empty = [x for x in d['secs'] if not (x.get('p') or '').strip()]
        if empty:
            fail.append(f'{b}: {len(empty)} sections have no path')
        # Same failure, one level up: the page indexes with s.x.forEach(...), so a
        # section with no "x" at all throws inside the async load. The rejection is
        # swallowed and the whole page sits on "loading reference data" -- which is how
        # this was found the first time, so it is asserted rather than remembered.
        nox = [(x.get('k'), x.get('p')) for x in d['secs'] if 'x' not in x]
        if nox:
            fail.append(f'{b}: {len(nox)} sections have no "x" list '
                        f'(the page throws on these) -- first: {nox[0]}')

    # One derived `show`/`get` per path. The hand guides give several config subsections
    # one path, and a guard that missed that shipped five identical rows for one command.
    for e in cfg['cli']:
        b = bundle_id(e)
        path = os.path.join(ROOT, OUT, f'{b}.json')
        if not os.path.exists(path):
            continue
        d = json.load(open(path))
        for kind in ('show', 'get'):
            seen, dupe = set(), set()
            for sec in d['secs']:
                if sec['k'] != kind:
                    continue
                if sec['p'] in seen:
                    dupe.add(sec['p'])
                seen.add(sec['p'])
            if dupe:
                fail.append(f'{b}: duplicate {kind} entries for {sorted(dupe)[:3]}')

    # Two builds of one platform are alternative views of the same CLI. If one has worked
    # examples and the other has almost none, something is sharing a pool it should not --
    # which is invisible in the section counts, so assert it here.
    byplat = {}
    for e in cfg['cli']:
        byplat.setdefault(e['product'], []).append(bundle_id(e))
    for plat, bs in sorted(byplat.items()):
        have = {}
        for b in bs:
            path = os.path.join(ROOT, OUT, f'{b}.json')
            if not os.path.exists(path):
                continue
            d = json.load(open(path))
            have[b] = sum(len(s.get('e') or ()) for s in d['secs'])
        if len(have) > 1 and max(have.values()):
            lo, hi = min(have.values()), max(have.values())
            if lo < hi * 0.5:
                fail.append(f'{plat}: worked examples are lopsided across builds {have} '
                            f'-- a shared example pool is starving one of them')

    # Check the generated literal itself. A substring search over the whole file would
    # pass on a literal that closed early and left JS dangling -- which is a blank page,
    # not a missing bundle, and exactly the failure a generated literal invites.
    page = open(os.path.join(ROOT, 'site/index.html'), encoding='utf-8').read()
    m = re.search(r'const PRODUCTS=\[[\s\S]*?\];', page)
    if not m:
        fail.append('index.html has no PRODUCTS literal -- run stamp_build.py')
    else:
        named = set(re.findall(r'f:"([^"]*)"', m.group(0)))
        want = set(ids)
        for b in sorted(want - named):
            fail.append(f'{b}: not named in index.html PRODUCTS -- run stamp_build.py')
        for b in sorted(named - want):
            fail.append(f'{b}: named in index.html PRODUCTS but not in sources.json '
                        f'-- stale literal, run stamp_build.py')
        if page.count('const PRODUCTS=[') != 1:
            fail.append('index.html has more than one PRODUCTS literal')
    for e in cfg['cli']:
        b = bundle_id(e)
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
