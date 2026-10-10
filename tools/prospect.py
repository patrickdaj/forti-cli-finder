#!/usr/bin/env python3
"""Measure how much CLI sample output a candidate guide would add.

For each doc path: resolve its PDF on docs.fortinet.com, download it to work/probe/,
run the extractor, and report distinct commands found. Use it to decide which guides
are worth adding to build.sh -- most Fortinet guides are GUI-facing and yield nothing.

  python3 tools/prospect.py /document/fortigate/7.6.4/new-features ...
"""
import re, sys, os, json, subprocess, urllib.request, urllib.error

UA = {'User-Agent': 'Mozilla/5.0 (compatible; forti-cli-finder/1.0; +https://github.com/)'}
PROBE = 'work/probe'
os.makedirs(PROBE, exist_ok=True)

def fetch(url):
    return urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=120)

def resolve(path):
    """doc path -> (pdf url, page title)"""
    with fetch('https://docs.fortinet.com' + path) as r:
        s = r.read().decode('utf-8', 'replace')
    pdfs = sorted(set(re.findall(r'https://fortinetweb\.s3\.amazonaws\.com/[^"\'\s<>]+\.pdf', s)))
    return (pdfs[0] if pdfs else None)

def probe(path):
    key = re.sub(r'[^a-z0-9]+', '-', path.lower()).strip('-')[-60:]
    pdf, txt, js = f'{PROBE}/{key}.pdf', f'{PROBE}/{key}.txt', f'{PROBE}/{key}.json'
    if not os.path.exists(js):
        try:
            url = resolve(path)
        except Exception as e:
            return path, None, f'resolve failed: {e}'
        if not url:
            return path, None, 'no pdf link'
        name = url.rsplit('/', 1)[-1]
        if not os.path.exists(pdf):
            try:
                with fetch(url) as r, open(pdf + '.part', 'wb') as f:
                    f.write(r.read())
                os.replace(pdf + '.part', pdf)
            except Exception as e:
                return path, None, f'download failed: {e}'
        if not os.path.exists(txt):
            subprocess.run(['pdftotext', '-layout', pdf, txt], check=True)
        r = subprocess.run([sys.executable, 'tools/extract_outputs.py', txt, js],
                           capture_output=True, text=True)
        if r.returncode:
            return path, None, 'extract failed: ' + r.stderr.strip()[:120]
        json.dump({'url': url, 'name': name}, open(js + '.meta', 'w'))
    S = json.load(open(js))
    meta = json.load(open(js + '.meta'))
    return path, {'samples': len(S), 'cmds': len(set(x['cmd'] for x in S)),
                  'pdf': meta['name'], 'mb': round(os.path.getsize(pdf) / 1e6)}, None

if __name__ == '__main__':
    rows = []
    for p in sys.argv[1:]:
        path, res, err = probe(p)
        if err:
            print(f'{"-":>5} {"-":>5} {path}  ({err})', flush=True)
        else:
            rows.append((res['cmds'], res['samples'], path, res))
            print(f'{res["cmds"]:>5} {res["samples"]:>5} {path}  [{res["mb"]}MB {res["pdf"]}]', flush=True)
    print('\n== by yield ==')
    for c, s, p, r in sorted(rows, reverse=True):
        print(f'{c:>5} cmds {s:>5} samples  {p}')
