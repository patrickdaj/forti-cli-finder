#!/usr/bin/env python3
"""Download the PDFs named in sources.lock.json into sources/.

Resumable and idempotent: a file whose size already matches the lock file is left alone,
so re-running costs nothing. Run tools/discover_sources.py first to create or refresh
the lock file.

  python3 tools/fetch_sources.py           # everything in the lock file
  python3 tools/fetch_sources.py ag nf76   # just these keys
"""
import json, os, sys, urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEST = os.path.join(ROOT, 'sources')
UA = {'User-Agent': 'Mozilla/5.0 (compatible; forti-cli-finder; +https://docs.fortinet.com)'}


def fetch(key, doc):
    path = os.path.join(DEST, key + '.pdf')
    want = doc.get('bytes') or 0
    if os.path.exists(path) and (not want or os.path.getsize(path) == want):
        print(f'  have {key}.pdf')
        return True
    print(f'  get  {key}.pdf  ({want/1e6:.0f}MB)  {doc["name"]}', flush=True)
    tmp = path + '.part'
    try:
        req = urllib.request.Request(doc['url'], headers=UA)
        with urllib.request.urlopen(req, timeout=300) as r, open(tmp, 'wb') as f:
            while chunk := r.read(1 << 20):
                f.write(chunk)
        got = os.path.getsize(tmp)
        if want and got != want:
            raise IOError(f'size mismatch: expected {want}, got {got}')
        os.replace(tmp, path)
        return True
    except Exception as e:
        if os.path.exists(tmp):
            os.remove(tmp)
        print(f'  FAIL {key}: {e}', file=sys.stderr)
        return False


def main():
    lock_path = os.path.join(ROOT, 'sources.lock.json')
    if not os.path.exists(lock_path):
        sys.exit('no sources.lock.json -- run tools/discover_sources.py first')
    docs = json.load(open(lock_path))['documents']
    only = set(sys.argv[1:])
    os.makedirs(DEST, exist_ok=True)
    bad = [k for k, d in sorted(docs.items()) if (not only or k in only) and not fetch(k, d)]
    if bad:
        sys.exit('could not download: ' + ', '.join(bad))


if __name__ == '__main__':
    main()
