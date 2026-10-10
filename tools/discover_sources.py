#!/usr/bin/env python3
"""Resolve every document in sources.json to the PDF docs.fortinet.com is serving today.

Writes sources.lock.json: the exact URL, file name and byte size each build used. The
lock file is committed, so a build is reproducible and `--check` can tell whether
Fortinet has re-released anything -- which is all the scheduled workflow needs to know.

  python3 tools/discover_sources.py            # resolve and write the lock file
  python3 tools/discover_sources.py --check    # exit 1 if the lock file is out of date
"""
import json, os, re, sys, urllib.request, urllib.error

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = 'https://docs.fortinet.com'
UA = {'User-Agent': 'Mozilla/5.0 (compatible; forti-cli-finder; +https://docs.fortinet.com)'}
PDF = re.compile(r'https://fortinetweb\.s3\.amazonaws\.com/[^"\'\s<>]+\.pdf')


def get(url, head=False):
    req = urllib.request.Request(url, headers=UA, method='HEAD' if head else 'GET')
    return urllib.request.urlopen(req, timeout=120)


def resolve(entry):
    """doc page -> {url, name, bytes}. Raises on anything unexpected."""
    with get(BASE + entry['doc']) as r:
        page = r.read().decode('utf-8', 'replace')
    urls = sorted(set(PDF.findall(page)))
    if not urls:
        raise LookupError('no PDF link on ' + entry['doc'])
    # A guide page links only its own PDF; if several appear, prefer one matching `expect`.
    url = urls[0]
    exp = entry.get('expect')
    if exp:
        for u in urls:
            if exp in urllib.request.unquote(u):
                url = u
                break
        else:
            raise LookupError(f"{entry['doc']}: expected {exp}, got {urls[0].rsplit('/', 1)[-1]}")
    name = urllib.request.unquote(url.rsplit('/', 1)[-1])
    with get(url, head=True) as r:
        size = int(r.headers.get('Content-Length') or 0)
    return {'url': url, 'name': name, 'bytes': size}


def main():
    check = '--check' in sys.argv
    cfg = json.load(open(os.path.join(ROOT, 'sources.json')))
    lock_path = os.path.join(ROOT, 'sources.lock.json')
    old = {}
    if os.path.exists(lock_path):
        old = json.load(open(lock_path)).get('documents', {})

    new, failed, changed = {}, [], []
    for entry in cfg['cli'] + cfg['output']:
        key = entry['key']
        try:
            got = resolve(entry)
        except Exception as e:
            failed.append((key, str(e)[:120]))
            if key in old:
                new[key] = old[key]          # keep the last known good link
            continue
        got['doc'] = entry['doc']
        got['title'] = entry['title']
        new[key] = got
        was = old.get(key)
        if was and was.get('url') != got['url']:
            changed.append((key, was['name'], got['name']))
        elif not was:
            changed.append((key, '-', got['name']))

    for key, msg in failed:
        print(f'  !! {key}: {msg}', file=sys.stderr)
    for key, a, b in changed:
        print(f'  ~~ {key}: {a} -> {b}')
    if not changed and not failed:
        print(f'  {len(new)} documents, all unchanged')

    if check:
        if failed:
            sys.exit(2)
        sys.exit(1 if changed else 0)

    json.dump({'documents': new}, open(lock_path, 'w'), indent=1, sort_keys=True)
    total = sum(d.get('bytes', 0) for d in new.values())
    print(f'  wrote sources.lock.json: {len(new)} documents, {total/1e6:.0f}MB')
    sys.exit(2 if failed else 0)


if __name__ == '__main__':
    main()
