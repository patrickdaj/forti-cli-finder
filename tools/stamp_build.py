#!/usr/bin/env python3
"""Stamp the bundles' content hash into site/index.html.

Without it a freshly deployed page can pair with a data file a CDN or browser is still
serving from cache. The page then looks subtly broken -- code expecting fields the stale
data does not carry -- for as long as the cache lasts, which is exactly as confusing as
it sounds. The hash goes on the data URLs, so new code always fetches its own data.
"""
import glob, hashlib, importlib.util, json, os, re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CFG = json.load(open(os.path.join(ROOT, 'sources.json')))
_spec = importlib.util.spec_from_file_location(
    'check_bundles', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'check_bundles.py'))
_cb = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_cb)

# The page needs to know which builds exist. Keeping that list in index.html by hand means
# two places to update and one of them gets forgotten, so it is generated here from the
# same sources.json the build reads.
plats = {}
for e in CFG['cli']:
    pl = plats.setdefault(e['product'], {'id': e['product'], 'short': e['short'],
                                         'name': '', 'vers': []})
    pl['name'] = (e.get('label') or '').rsplit(' ', 1)[0] or e['product']
    pl['vers'].append({'v': e.get('ver', ''), 'f': _cb.bundle_id(e),
                       'src': e.get('src', e['title'])})

# json.dumps escapes for JS, not for HTML, and the literal is terminated by the first
# `];`. Either in a label or src would produce a page that parses as a syntax error --
# a blank screen from a build that printed nothing wrong. Refuse instead.
for pl in plats.values():
    for text in [pl['name'], pl['short'], pl['id']] + [x[k] for x in pl['vers']
                                                       for k in ('v', 'f', 'src')]:
        for bad in ('];', '</', '\\'):
            if bad in text:
                raise SystemExit(
                    f'sources.json: {text!r} contains {bad!r}, which would break the '
                    f'generated PRODUCTS literal in site/index.html')

j = json.dumps
products = 'const PRODUCTS=[\n' + ',\n'.join(
    '  {id:%s,short:%s,name:%s,vers:[%s]}' % (
        j(pl['id']), j(pl['short']), j(pl['name']),
        ','.join('{v:%s,f:%s,src:%s}' % (j(x['v']), j(x['f']), j(x['src'])) for x in pl['vers']))
    for pl in plats.values()) + '];'

h = hashlib.sha256()
for f in sorted(glob.glob('site/data/*.json')):
    h.update(open(f, 'rb').read())
stamp = h.hexdigest()[:12]

p = open('site/index.html', encoding='utf-8').read()
p, n = re.subn(r'const PRODUCTS=\[[\s\S]*?\];', lambda _: products, p, count=1)
if not n:
    raise SystemExit('no PRODUCTS literal in site/index.html')
p, n = re.subn(r"const BUILD='[^']*';", f"const BUILD='{stamp}';", p, count=1)
if not n:
    raise SystemExit("no BUILD placeholder in site/index.html")
open('site/index.html', 'w', encoding='utf-8').write(p)
print(f'stamped BUILD={stamp}, {len(plats)} platforms, '
      f'{sum(len(v["vers"]) for v in plats.values())} builds')
