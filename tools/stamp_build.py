#!/usr/bin/env python3
"""Stamp the bundles' content hash into site/index.html.

Without it a freshly deployed page can pair with a data file a CDN or browser is still
serving from cache. The page then looks subtly broken -- code expecting fields the stale
data does not carry -- for as long as the cache lasts, which is exactly as confusing as
it sounds. The hash goes on the data URLs, so new code always fetches its own data.
"""
import glob, hashlib, re

h = hashlib.sha256()
for f in sorted(glob.glob('site/data/*.json')):
    h.update(open(f, 'rb').read())
stamp = h.hexdigest()[:12]

p = open('site/index.html', encoding='utf-8').read()
p2, n = re.subn(r"const BUILD='[^']*';", f"const BUILD='{stamp}';", p, count=1)
if not n:
    raise SystemExit("no BUILD placeholder in site/index.html")
open('site/index.html', 'w', encoding='utf-8').write(p2)
print(f'stamped BUILD={stamp}')
