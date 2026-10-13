#!/usr/bin/env python3
"""Turn device captures into a committed overlay the build can apply.

The captures in work/live/ are gitignored -- a status banner carries a serial number and
a hostname, and nobody should have to trust a reviewer to notice. But what we learn from
them has to ship, so this distils them into device-overlay.json, which carries only the
command facts and a provenance string naming the model and build:

    "FortiGate-70G-POE v7.6.7 build3704"

Three kinds of fact come out of a capture, none of which any document has:

  * `get` commands. fgt01 answers `?` for 1350 of them; our bundle documents 6. The
    diagnostic read tree -- `get router info bgp neighbors <A.B.C.D>` and its family --
    exists nowhere else, because the generated CLI Reference omits `get` entirely and
    even the device's own `tree` cannot expand the routing daemon's subtree.
  * arguments for commands the reference prints bare, with their descriptions.
  * `<Enter>`, which is the box saying a command is complete -- requiredness, direct.

  python3 tools/merge_device.py                 # read work/live/, write the overlay
  python3 tools/merge_device.py --report        # what it would add, without writing
  python3 tools/merge_device.py --apply         # fold the overlay into site/data/

`--apply` is what build.sh runs. It is idempotent and additive: it never overwrites a
documented argument list with a captured one, because the PDF has descriptions and
defaults the device does not. It only fills what is empty and adds what is absent.
"""
import collections, glob, json, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.environ.get('OUT', 'site/data')
LIVE = os.path.join(ROOT, 'work/live')
OVERLAY = os.path.join(ROOT, 'device-overlay.json')

_sp = __import__('importlib.util', fromlist=['util']).spec_from_file_location(
    'parse_tree', os.path.join(ROOT, 'tools/parse_tree.py'))
_pt = __import__('importlib.util', fromlist=['util']).module_from_spec(_sp)
_sp.loader.exec_module(_pt)

HELP_HEAD = re.compile(r'^### (\S+) (.+)$')
ROW = re.compile(r'^\s*(\S+)\s{2,}(\S.*?)\s*$')


def read_capture(d):
    """One capture directory -> (provenance, [facts])."""
    cap = os.path.join(d, 'capture.txt')
    st = os.path.join(d, 'status.txt')
    text = open(cap).read() if os.path.exists(cap) else (
        open(st).read() if os.path.exists(st) else '')
    ident = _pt.identify(text)
    if not ident:
        return None, []
    prov = f"{ident['model']} v{ident['ver']} build{ident['build']}"
    facts = []

    # A command's description lives in its PARENT's sub-command listing: asking
    # `get router info bgp ?` prints "neighbors   show BGP neighbors". So read the
    # files once to build that map, then again for the nodes themselves.
    desc = {}
    for f in sorted(glob.glob(os.path.join(d, 'crawl-*.jsonl'))):
        for line in open(f):
            r = json.loads(line)
            for name, dd in r['subs']:
                desc[f"{r['p']} {name}"] = dd

    # the `?` crawl: every node it described, with its arguments
    for f in sorted(glob.glob(os.path.join(d, 'crawl-*.jsonl'))):
        for line in open(f):
            r = json.loads(line)
            words = r['p'].split()
            if len(words) < 2:
                continue
            # Only what the box confirmed is a command: `<Enter>` means complete, and
            # an argument implies it. A node with neither is a namespace branch --
            # `get alertemail` is a path you type through, not a command you run.
            if not (r['complete'] or r['args']):
                continue
            facts.append({'k': words[0], 'p': ' '.join(words[1:]),
                          'complete': r['complete'], 'd': desc.get(r['p'], ''),
                          'x': [{'n': n, 'd': dd} for n, dd in r['args']]})

    # help.txt: `?` asked about commands the bundle ships bare
    hp = os.path.join(d, 'help.txt')
    if os.path.exists(hp):
        cur, body = None, []
        for line in open(hp).read().split('\n') + ['### _ _']:
            m = HELP_HEAD.match(line)
            if m:
                if cur:
                    facts.append(_from_help(cur, body))
                cur, body = m.groups(), []
            elif cur:
                body.append(line)
        facts = [f for f in facts if f]
    return prov, facts


def _from_help(cur, body):
    verb, path = cur
    h = _pt_help('\n'.join(body))
    if not (h['args'] or h['complete']):
        return None
    return {'k': verb, 'p': path, 'complete': h['complete'],
            'x': [{'n': n, 'd': d} for n, d in h['args']]}


def _pt_help(text):
    """`?` output -> complete / args. Mirrors capture_device.help_rows deliberately:
    this must read what that wrote even if the two drift apart in time."""
    complete, args = False, []
    for line in text.split('\n'):
        if line.strip() == '<Enter>':
            complete = True
            continue
        m = ROW.match(line.rstrip())
        if m and (m.group(1).startswith('<') or m.group(1) == 'arg'):
            args.append((m.group(1), m.group(2)))
    return {'complete': complete, 'args': args}


def bundle_for(prov):
    """Which bundle does a capture speak for? Same rule as parse_tree: same platform,
    same major.minor, and never across a minor boundary."""
    ident = _pt.identify(f"Version: {prov.replace(' build', ',build').replace(' v', ' v')}")
    if not ident:
        m = re.match(r'(\S+) v(\d+\.\d+\.\d+) build(\d+)', prov)
        if not m:
            return None
        ident = {'product': _pt.MODELS.get(m.group(1).split('-')[0].lower()),
                 'model': m.group(1), 'ver': m.group(2), 'build': m.group(3)}
    b, _ = _pt.pick_bundle(ident)
    return b


def collect():
    """Every capture directory -> {bundle: {(k,p): fact}} plus the provenance seen."""
    out, provs = {}, {}
    for d in sorted(glob.glob(os.path.join(LIVE, '*'))):
        if not os.path.isdir(d):
            continue
        prov, facts = read_capture(d)
        if not prov:
            continue
        b = bundle_for(prov)
        if not b:
            print(f'  {os.path.basename(d)}: no bundle for {prov} -- skipped')
            continue
        provs.setdefault(b, set()).add(prov)
        dest = out.setdefault(b, {})
        for f in facts:
            key = (f['k'], f['p'])
            old = dest.get(key)
            # prefer the record that actually names arguments
            if not old or (len(f['x']) > len(old['x'])):
                dest[key] = dict(f, src=prov)
    return out, provs


def write_overlay(data, provs):
    doc = {'_comment': [
        'Command facts learned from live devices, for the build to fold into the',
        'bundles. Written by tools/merge_device.py from work/live/, which is gitignored.',
        'Only the facts and a model/build string are here -- never a serial, a hostname',
        'or an address. Regenerate rather than hand-edit.'],
        'devices': {b: sorted(p) for b, p in sorted(provs.items())},
        'facts': {b: [dict(v, k=k[0], p=k[1]) for k, v in sorted(d.items())]
                  for b, d in sorted(data.items())}}
    json.dump(doc, open(OVERLAY, 'w'), ensure_ascii=False, indent=1)
    open(OVERLAY, 'a').write('\n')
    n = sum(len(v) for v in doc['facts'].values())
    print(f'  wrote device-overlay.json: {n} facts across {len(doc["facts"])} bundle(s)')


def report(data, provs):
    for b, d in sorted(data.items()):
        path = os.path.join(ROOT, OUT, f'{b}.json')
        if not os.path.exists(path):
            continue
        bun = json.load(open(path))
        have = {(s['k'], s['p']): s for s in bun['secs']}
        new = [f for k, f in d.items() if k not in have]
        fill = [f for k, f in d.items()
                if k in have and f['x'] and not have[k].get('x')]
        print(f'\n=== {b}   from {", ".join(sorted(provs[b]))}')
        print(f'  facts {len(d)}   commands the bundle lacks {len(new)}'
              f'   bare commands we could fill {len(fill)}')
        kinds = collections.Counter(f['k'] for f in new)
        print(f'  by kind, the new ones: {dict(sorted(kinds.items()))}')
        for f in sorted(new, key=lambda f: (f['k'], f['p']))[:8]:
            a = ' '.join(x['n'] for x in f['x'])
            print(f"      + {f['k']} {f['p']}  {a}")
        for f in sorted(fill, key=lambda f: (f['k'], f['p']))[:6]:
            a = ' '.join(x['n'] for x in f['x'])
            print(f"      > {f['k']} {f['p']}  {a}")


def apply_overlay():
    """Fold the overlay into the bundles. Additive, idempotent, documentation wins.

    A captured argument never replaces a documented one: the PDF carries descriptions,
    defaults and option values the device does not, so the device only fills what is
    empty and adds what is absent. `dvc` marks what came from a box, so the page can
    say "FortiGate-70G-POE v7.6.7 build3704" where it would otherwise cite a page.
    """
    files = sorted(glob.glob(os.path.join(ROOT, '*-overlay.json')))
    if not files:
        print('  no *-overlay.json -- nothing to apply')
        return 0
    merged = {}
    for fn in files:
        doc = json.load(open(fn))
        dev = 'devices' in doc          # a device overlay, as opposed to a document one
        for b, facts in doc.get('facts', {}).items():
            for f in facts:
                merged.setdefault(b, {})[(f['k'], f['p'])] = dict(f, _dev=dev)
        print(f'  {os.path.basename(fn):22s} '
              f'{sum(len(v) for v in doc.get("facts", {}).values()):5d} facts')
    for b, by_key in sorted(merged.items()):
        facts = list(by_key.values())
        path = os.path.join(ROOT, OUT, f'{b}.json')
        if not os.path.exists(path):
            print(f'  {b}: no bundle, skipped')
            continue
        bun = json.load(open(path))
        idx = {(s['k'], s['p']): s for s in bun['secs']}
        added = filled = described = 0
        for f in facts:
            key = (f['k'], f['p'])
            # `k` as well as `n`: the page indexes on p.k, and for a positional
            # argument the key IS the name. Omitting it threw inside the loader and
            # left the page stuck on "loading reference data".
            x = [{'n': a['n'], 'k': a['n'], 'd': a['d']} for a in f.get('x', [])]
            sec = idx.get(key)
            if sec is None:
                sec = {'k': f['k'], 'p': f['p'], 'd': f.get('d') or '', 'pg': '',
                       's': ' '.join([f['k'], f['p']]
                                     + [a['n'] for a in x]).strip(),
                       'x': x, 'osrc': f['src']}
                if f['_dev']:
                    sec['odev'] = 1
                bun['secs'].append(sec)
                added += 1
            elif x and not sec.get('x'):
                sec['x'] = x
                sec['osrc'] = f['src']
                if f['_dev']:
                    sec['odev'] = 1
                # a guide-scraped entry often has neither arguments nor a description;
                # fill the description too rather than leaving it blank next to a
                # perfectly good one the box just gave us
                if f.get('d') and not (sec.get('d') or '').strip():
                    sec['d'] = f['d']
                filled += 1
            elif f.get('d') and not (sec.get('d') or '').strip():
                sec['d'] = f['d']
                sec['osrc'] = f['src']
                if f['_dev']:
                    sec['odev'] = 1
                described += 1
        raw = json.dumps(bun, ensure_ascii=False, separators=(',', ':'))
        open(path, 'w').write(raw)
        print(f'  {b:16s} +{added:5d} commands  {filled:5d} given arguments  '
              f'{described:5d} given a description')
    return 0


def main():
    args = sys.argv[1:]
    if '--apply' in args:
        return apply_overlay()
    if not os.path.isdir(LIVE):
        print(f'  no {os.path.relpath(LIVE, ROOT)} -- run make capture first')
        return 1
    data, provs = collect()
    if not data:
        print('  no usable captures')
        return 1
    report(data, provs)
    if '--report' not in args:
        print()
        write_overlay(data, provs)
    return 0


if __name__ == '__main__':
    sys.exit(main())
