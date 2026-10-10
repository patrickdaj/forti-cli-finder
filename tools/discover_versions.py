#!/usr/bin/env python3
"""Ask docs.fortinet.com which firmware versions exist that sources.json does not ship.

discover_sources.py answers "has Fortinet re-released a document we already name?".
This answers the other question -- "has a new version appeared at all?" -- which is the
one nobody asks until a release is six months old. A document path pins a version
(/document/fortigate/7.6.7/cli-reference), so a new version is a path we have never
looked at and the weekly refresh will never find.

One sitemap lists every product/version Fortinet publishes. For each document in
sources.json this prints the newer versions of that same document that actually resolve
to a PDF -- not every version in the sitemap, because a version existing does not mean
the guide was published for it.

  python3 tools/discover_versions.py            # what is newer than what we ship
  python3 tools/discover_versions.py --check    # exit 1 if anything newer exists
  python3 tools/discover_versions.py --all      # include documents already current

Nothing is downloaded and nothing is written: adding a version is a sources.json edit,
and whether a newer reference is worth shipping is a judgement (measure it with
`make probe DOC=...` first). See docs/sources.md.
"""
import importlib.util, json, os, re, sys, urllib.error, urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SITEMAP = 'https://docs.fortinet.com/product_software_1.xml'
UA = {'User-Agent': 'Mozilla/5.0 (compatible; forti-cli-finder; +https://docs.fortinet.com)'}
DOC = re.compile(r'^/document/([^/]+)/([0-9][0-9.]*)/(.+)$')

_spec = importlib.util.spec_from_file_location(
    'discover_sources', os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                     'discover_sources.py'))
_ds = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_ds)


def vkey(v):
    return [int(x) if x.isdigit() else 0 for x in v.split('.')]


def published():
    """product slug -> every version docs.fortinet.com lists for it."""
    req = urllib.request.Request(SITEMAP, headers=UA)
    with urllib.request.urlopen(req, timeout=120) as r:
        xml = r.read().decode('utf-8', 'replace')
    out = {}
    for slug, ver in re.findall(
            r'<loc>https://docs\.fortinet\.com/product/([^/]+)/([^<]+)</loc>', xml):
        out.setdefault(slug, set()).add(ver.strip())
    return out


def main():
    check = '--check' in sys.argv
    show_all = '--all' in sys.argv
    try:
        vers = published()
    except urllib.error.URLError as e:
        print(f'could not read the version sitemap: {e}', file=sys.stderr)
        return 2

    cfg = json.load(open(os.path.join(ROOT, 'sources.json')))
    docs = [('cli', e) for e in cfg['cli']] + [('output', e) for e in cfg['output']]
    rows, newer = [], 0

    for kind, e in docs:
        m = DOC.match(e['doc'])
        if not m:
            continue
        slug, cur, tail = m.groups()
        cands = sorted((v for v in vers.get(slug, ()) if vkey(v) > vkey(cur)),
                       key=vkey, reverse=True)
        found = []
        for v in cands:
            path = f'/document/{slug}/{v}/{tail}'
            try:
                r = _ds.resolve({'doc': path})
            except Exception:
                continue        # that version exists, this document was not published for it
            found.append((v, path, r['name'], r['bytes']))
            if len(found) >= 3:
                break           # the three newest are enough to decide with
        if found:
            newer += 1
        if found or show_all:
            rows.append((kind, e['key'], cur, found))

    w = max((len(r[1]) for r in rows), default=8)
    for kind, key, cur, found in rows:
        if not found:
            print(f'  {key:{w}}  {cur:9} current')
            continue
        for i, (v, path, name, size) in enumerate(found):
            lead = f'  {key:{w}}  {cur:9}' if i == 0 else f'  {"":{w}}  {"":9}'
            print(f'{lead}  -> {v:9} {size/1e6:6.1f}MB  {name}')
            print(f'  {"":{w}}  {"":9}     {path}')

    if not rows:
        print('  everything in sources.json is the newest published version')
    print(f'\n{newer} of {len(docs)} documents have a newer version published.')
    if newer:
        print('Adding one is a sources.json edit -- see "Adding a firmware build" in the '
              'README. Measure a guide first with: make probe DOC=<path>')
    return 1 if (check and newer) else 0


if __name__ == '__main__':
    sys.exit(main())
