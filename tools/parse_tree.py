#!/usr/bin/env python3
"""Parse a FortiGate `tree` capture into commands, arguments and types.

`tree` prints the box's own command tree. It is the only source that is exact for a
firmware build rather than for whatever version Fortinet last regenerated a PDF from,
and it carries three things the CLI Reference does not:

  * the arguments of diagnose and execute commands -- `diagnose sys session filter src
    <xxx.xxx.xxx.xxx>` is in the tree and is a bare command in the reference;
  * integer ranges and string lengths on every config field, and each table's mkey;
  * the `<Enter> or` marker, which is how the box says an argument is optional.

What it does not carry: descriptions, defaults, option values, sample output -- and the
routing daemon's read tree, so `get router info bgp neighbors` is still missing. The tree
is the skeleton and the PDF is the flesh; they join on the command path.

  python3 tools/parse_tree.py <capture>                 # summary
  python3 tools/parse_tree.py <capture> --json out.json # every node
  python3 tools/parse_tree.py <capture> --diff fortios  # against a shipped bundle
  python3 tools/parse_tree.py --selftest                # against tools/testdata

Format, in case it ever changes under us. Depth is the column of the `|-` / `+-` / `--`
connector, so a deeper column is a deeper node. A line may declare a chain of
descendants with ` -- ` between them, each at its own column -- that is how
`<global> -- language` makes `language` a child. `[x]` is a table you edit into, `*x` its
mkey, `<x>` an object or a command leaf, bare words are fields. A trailing `(35)` is a
string length, `(1,480)` an integer range, `(-1)` a free-form argument.
"""
import json, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.environ.get('OUT', 'site/data')
SAMPLE = os.path.join(ROOT, 'tools/testdata/tree-sample.txt')

# A connector starts a line or follows whitespace. Names never contain a double dash.
CONN = re.compile(r'(?:(?<=\s)|^)(\|-|\+-|--)')
# "  (35)" / "  (1,480)" / "  (-1)" / "  (79 xss)" at the end of a segment.
SUFFIX = re.compile(r'\s+\(([^()]*)\)\s*$')
VERBS = {'diagnose__tree__': 'diagnose', 'execute__tree__': 'execute'}


def segments(line):
    """[(column, name, suffix)] for one line, outermost first."""
    hits = [(m.start(1), m.end(1)) for m in CONN.finditer(line)]
    out = []
    for i, (a, b) in enumerate(hits):
        end = hits[i + 1][0] if i + 1 < len(hits) else len(line)
        text = line[b:end]
        suf = None
        m = SUFFIX.search(text)
        if m:
            suf, text = m.group(1), text[:m.start()]
        name = text.strip()
        if not name:
            continue
        out.append((a, name, suf))
    return out


def typed(name, suf):
    """Split the markers off a node name and read its size or range."""
    n = {'raw': name}
    if name.startswith('*'):
        n['mkey'] = True
        name = name[1:]
    if name.startswith('[') and name.endswith(']'):
        n['kind'], name = 'table', name[1:-1]
    elif name.startswith('<') and name.endswith('>'):
        n['kind'], name = 'object', name[1:-1]
    else:
        n['kind'] = 'field'
    n['name'] = name
    if suf is not None:
        s = suf.strip()
        if s == '-1':
            n['free'] = True                       # free-form argument, no constraint
        elif re.fullmatch(r'\d+', s):
            n['size'] = int(s)
        elif re.fullmatch(r'\d+ xss', s):
            n['size'] = int(s.split()[0])
            n['xss'] = True
        elif re.fullmatch(r'\d+,\d+', s):
            lo, hi = s.split(',')
            n['min'], n['max'] = int(lo), int(hi)
        else:
            n['note'] = s
    return n


def parse(text):
    """Every node, each with its full path. Depth comes from the connector column."""
    nodes, stack = [], []        # stack: [(column, node)]
    for raw in text.split('\n'):
        if not raw.strip():
            continue
        if raw.lstrip().startswith('>'):
            continue             # a terminal wrapped the previous line
        if re.fullmatch(r'\s*\([^()]*\)\s*', raw):
            continue             # a wrapped size suffix, already on its node
        for col, name, suf in segments(raw):
            while stack and stack[-1][0] >= col:
                stack.pop()
            n = typed(name, suf)
            n['path'] = [p['name'] for _, p in stack] + [n['name']]
            n['depth'] = len(stack)
            nodes.append(n)
            stack.append((col, n))
    return nodes


def commands(nodes):
    """Group the nodes into command records: a path, then its positional arguments.

    The discriminator, which is the whole trick: a node with exactly ONE `<angled>` child
    is taking a positional argument, and the chain continues -- that is how the tree
    writes `sniffer packet <interface> <filter> <verbose> ...`, each nested in the last.
    SEVERAL `<angled>` children are alternatives, not arguments: `session-info` offers
    `<list>`, `<full-stat>`, `<ttl>` and each is its own command.

    Under diagnose__tree__ / execute__tree__ every word node is a command. Elsewhere the
    tree is the config tree: a table or an object with real children is a `config` path,
    and an `<angled>` node hanging off it is a `get` endpoint.
    """
    kids = {}
    for n in nodes:
        kids.setdefault(tuple(n['path'][:-1]), []).append(n)

    def chain(node):
        """Follow a descent of single `<angled>` children: the positional arguments."""
        args, cur = [], node
        while True:
            ch = kids.get(tuple(cur['path']), [])
            if len(ch) == 1 and ch[0]['kind'] == 'object':
                args.append(ch[0])
                cur = ch[0]
            else:
                return args

    def arg(c):
        return {'n': f"<{c['name']}>",
                **{k: v for k, v in c.items() if k in ('size', 'min', 'max', 'free')}}

    cmds, consumed = [], set()
    for n in nodes:
        p = tuple(n['path'])
        if p in consumed:
            continue
        verb = VERBS.get(n['path'][0])
        ch = kids.get(p, [])
        args = chain(n)
        for a in args:
            consumed.add(tuple(a['path']))

        if verb:
            if n['depth'] == 0:
                continue                      # the diagnose__tree__ / execute__tree__ root
            cmds.append({'k': verb, 'p': ' '.join(n['path'][1:]), 'x': [arg(a) for a in args]})
        elif n['kind'] == 'object' and not [c for c in ch if c['kind'] != 'object' or len(ch) > 1]:
            # an object whose children are only its argument chain (or none) reads back,
            # so it is a get endpoint; an object with real children is a config object.
            cmds.append({'k': 'get', 'p': ' '.join(n['path']), 'x': [arg(a) for a in args]})
        elif n['kind'] == 'object':
            cmds.append({'k': 'config', 'p': ' '.join(n['path']), 'x': [], 'mkey': None})
        elif n['kind'] == 'table':
            mk = next((c for c in ch if c.get('mkey')), None)
            cmds.append({'k': 'config', 'p': ' '.join(n['path']), 'x': [],
                         'mkey': mk['name'] if mk else None})
    return cmds


def summarise(nodes, cmds):
    import collections
    k = collections.Counter(n['kind'] for n in nodes)
    c = collections.Counter(x['k'] for x in cmds)
    print(f'  nodes {len(nodes)}  {dict(sorted(k.items()))}')
    print(f'  commands {len(cmds)}  {dict(sorted(c.items()))}')
    print(f"  with arguments  {sum(1 for x in cmds if x['x'])}")
    print(f"  tables with an mkey  {sum(1 for x in cmds if x.get('mkey'))}")
    print(f"  fields with a range  {sum(1 for n in nodes if 'min' in n)}"
          f"   with a length  {sum(1 for n in nodes if 'size' in n)}")


def diff(cmds, bundle):
    path = os.path.join(ROOT, OUT, f'{bundle}.json')
    b = json.load(open(path))
    have = {(s['k'], s['p']): s for s in b['secs']}
    print(f'\n=== {bundle}.json vs the device')
    for kind in ('config', 'diagnose', 'execute', 'get'):
        mine = [c for c in cmds if c['k'] == kind]
        if not mine:
            continue
        missing = [c for c in mine if (kind, c['p']) not in have]
        bare = [c for c in mine
                if (kind, c['p']) in have and c['x'] and not have[(kind, c['p'])].get('x')]
        # the device describes more arguments than we ship -- usually a range whose
        # second half the reference omits, e.g. `sys session filter src <ip> <ip>`
        short = [(c, have[(kind, c['p'])]) for c in mine
                 if (kind, c['p']) in have and have[(kind, c['p'])].get('x')
                 and len(c['x']) > len(have[(kind, c['p'])]['x'])]
        print(f'  {kind:9s} device {len(mine):5d}   not in the bundle {len(missing):5d}'
              f'   we ship it bare {len(bare):5d}   we ship fewer args {len(short):5d}')
        for c in bare[:6]:
            print(f"      + {kind} {c['p']}  {[a['n'] for a in c['x']]}")
        for c, s in short[:6]:
            print(f"      > {kind} {c['p']}  {len(s['x'])} -> {len(c['x'])}  "
                  f"{[a['n'] for a in s['x']]} -> {[a['n'] for a in c['x']]}")
        for c in missing[:4]:
            print(f"      ? {kind} {c['p']}")
    only = {(s['k'], s['p']) for s in b['secs'] if not s.get('dv')}
    dev = {(c['k'], c['p']) for c in cmds}
    stale = sorted(p for p in only - dev if p[0] in ('config', 'diagnose', 'execute'))
    print(f'  in the bundle but not on the device: {len(stale)}')
    for k, p in stale[:6]:
        print(f'      - {k} {p}')


def selftest():
    nodes = parse(open(SAMPLE).read())
    cmds = commands(nodes)
    by = {(c['k'], c['p']): c for c in cmds}

    def need(k, p, args=None, mkey=None):
        c = by.get((k, p))
        assert c, f'missing: {k} {p}'
        if args is not None:
            got = [a['n'] for a in c['x']]
            assert got == args, f'{k} {p}: args {got} != {args}'
        if mkey is not None:
            assert c.get('mkey') == mkey, f'{k} {p}: mkey {c.get("mkey")} != {mkey}'

    # the inline `<global> -- language` chain must nest, not flatten
    paths = {' '.join(n['path']) for n in nodes}
    assert 'system global language' in paths, 'inline -- chain did not nest'
    assert 'system global hostname' in paths
    assert 'system interface ipv6 ip6-prefix-list autonomous-flag' in paths

    # ranges, lengths and the xss flag
    g = {' '.join(n['path']): n for n in nodes}
    assert g['system global admintimeout']['min'] == 1
    assert g['system global admintimeout']['max'] == 480
    assert g['system global hostname']['size'] == 35
    assert g['system global admin-host']['xss'] is True

    # diagnose / execute arguments
    need('diagnose', 'sniffer packet',
         ['<interface>', '<filter>', '<verbose>', '<count>', '<tsformat>', '<frame size>'])
    need('diagnose', 'sys session filter src',
         ['<xxx.xxx.xxx.xxx>', '<xxx.xxx.xxx.xxx>'])
    need('diagnose', 'sys session filter clear vd', [])
    need('execute', 'ping', ['<ip>'])
    need('diagnose', 'hardware deviceinfo nic', [])

    # the <Enter> marker survives as an argument name
    c = by[('diagnose', 'sys ha checksum show')]
    assert any('Enter' in a['n'] for a in c['x']), c['x']

    # get endpoints: an object leaf under a config path
    need('get', 'system status')
    need('get', 'system performance status')
    need('get', 'system session-info list')
    need('get', 'system session-info ttl')
    need('get', 'hardware cpu')
    need('get', 'router info')

    paths2 = {' '.join(n['path']) for n in nodes}
    g2 = {' '.join(n['path']): n for n in nodes}

    # config tables keep their mkey
    need('config', 'system interface', mkey='name')
    need('config', 'system accprofile', mkey='name')
    need('config', 'system interface ipv6 ip6-prefix-list', mkey='prefix')

    # `<global>` has children, so it is a config object and NOT a get endpoint
    assert ('get', 'system global') not in by, 'an object with children is not a get'

    # the quirks that actually occur in a real capture
    need('config', 'log custom-field', mkey='id')
    need('config', 'quirks DoS-policy', mkey='policyid')
    need('config', 'quirks DoS-policy anomaly', mkey='name')
    need('config', 'quirks device-upgrade', mkey='serial')     # mkey declared mid-table
    assert 'quirks DoS-policy anomaly threshold(default)' in paths2, 'parens in a name'
    assert g2['quirks DoS-policy anomaly threshold(default)']['max'] == 4294967295
    assert g2['log fortianalyzer setting server']['size'] == 127, 'same-line child after a gap'
    assert 'log setting resolve-ip' in paths2, 'a second <setting> under a different parent'
    # a line the terminal wrapped: the stray "(-1)" must not become a node
    assert not any(n['name'].startswith('(') for n in nodes), 'wrapped suffix became a node'

    print(f'selftest OK  ({len(nodes)} nodes, {len(cmds)} commands from the fixture)')
    return 0


def main():
    args = [a for a in sys.argv[1:]]
    if '--selftest' in args:
        return selftest()
    if not args or args[0].startswith('--'):
        print(__doc__)
        return 2
    text = open(args[0], encoding='utf-8', errors='replace').read()
    nodes = parse(text)
    cmds = commands(nodes)
    print(f'{args[0]}:')
    summarise(nodes, cmds)
    if '--json' in args:
        dest = args[args.index('--json') + 1]
        json.dump({'nodes': nodes, 'commands': cmds}, open(dest, 'w'),
                  ensure_ascii=False, indent=1)
        print(f'  wrote {dest}')
    if '--diff' in args:
        diff(cmds, args[args.index('--diff') + 1])
    return 0


if __name__ == '__main__':
    sys.exit(main())
