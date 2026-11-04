#!/usr/bin/env python3
"""Compare FortiManager's syntax schema with the Finder's parsed FortiOS bundles. Report only.

The sibling repo fortinet-brain holds `fmg-syntax-<train>-device.json`: FortiManager's own
description of every config table (attribute type, default, option list). The Finder's
config parameters are parsed from Fortinet's PDF CLI reference, so each can be checked
against the other. This tool does that and writes nothing but an optional --json file; it
changes no parser, bundle or site file. It exists so that nobody edits a parser on the
strength of a disagreement that is really two vocabularies, or a FortiManager internal.

  python3 tools/diff_schema.py                       # both trains
  python3 tools/diff_schema.py --train 7.6 --table "system sdwan"
  python3 tools/diff_schema.py --json work/schema-diff-7.6.json --train 7.6
  python3 tools/diff_schema.py --selftest            # needs neither the brain nor a bundle

How tables are joined. Tables join on path. A bundle config entry lists every parameter of
its table AND of its nested `config` sub-tables in one flat x[]; a nested parameter carries
`t`, the name of the sub-table it sits in -- the LEAF name only, not the full path. The
schema nests instead (`subobj`). So both sides are flattened to (leaf, parameter name),
leaf None for the table itself. Two sub-tables of one table that share a leaf name (system
sdwan has `sla` under both health-check and service) merge on both sides; where that leaves
more than one candidate for a name on either side the pair is counted as ambiguous and
not compared, rather than guessed at. A bundle parameter equal to the sub-table's edit key
(`edit <id>`) is a key, not a bundle-only parameter: the schema lists keys as `mkey`.

Classes of disagreement:
  schema-excluded  the attribute is FortiManager's own (name begins `_`). Note: the
                   schema's `excluded: true` is NOT used. It sits on 5184 of the 5414
                   attributes that have an option list, equal or not, so it does not mean
                   "FortiManager only"; it is carried in the output as `excl` for whoever
                   works out what it does mean.
  type-vocab       the two vocabularies say the same thing differently: schema uint32 and
                   bundle integer, default 0 and "0", `0.0.0.0 0.0.0.0` and `0.0.0.0`, an
                   encrypted password default the PDF never prints. Counted as agreement
                   and tallied by pair, not listed as a disagreement.
  likely-parser    everything else, each with a `pattern` naming the shape it takes.
"""
import argparse, collections, json, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_BRAIN = os.path.expanduser('~/Development/fortinet-brain')
SCHEMA_REL = 'tools/fgconf/fmg-syntax-{train}-device.json'
TRAINS = {'7.6': 'site/data/fortios.json', '8.0': 'site/data/fortios-8.0.json'}
TOP20 = 20
PER_PATTERN = 4

# ---------------------------------------------------------------- type vocabulary
# Bundle type (what the PDF's {braces} say) -> the schema types that mean the same.
# 'option' is special: it needs the schema attribute to carry an option list (`opts`).
INT_T = {'uint8', 'uint16', 'uint32', 'uint64', 'int8', 'int32', 'seqnum', 'multi_int'}
OPT_T = {'uint8', 'uint16', 'uint32', 'uint64', 'int8', 'int32', 'opt_array'}
VOCAB = {
    'option':               OPT_T,
    'integer':              INT_T | {'datasrc'},         # datasrc: a numeric reference (sdwan service-id)
    'string':               {'string', 'datasrc', 'multi_str', 'hbdev'},
    'var-string':           {'string'},
    'uuid':                 {'string'},
    'ipv4-address':         {'ip4', 'multi_ipv4'},
    'ipv4-address-any':     {'ip4', 'multi_ipv4'},
    'ipv4-address-multicast': {'ip4'},
    'ipv4-classnet':        {'ipv4_mask'},
    'ipv4-classnet-any':    {'ipv4_mask'},
    'ipv4-classnet-host':   {'ipv4_mask'},
    'ipv4-netmask':         {'ip4mask'},
    'ipv4-netmask-any':     {'ip4mask'},
    'ipv6-address':         {'ip6addr', 'multi_ipv6'},
    'ipv6-prefix':          {'ip6prefix'},
    'ipv6-network':         {'ip6prefix'},
    'ipv6-wildcard':        {'ip6wildcard'},
    'mac-address':          {'macaddr', 'multi_str'},
    'datetime':             {'time', 'timedate', 'date_time', 'startend_datetime', 'user'},
    'text':                 {'user', 'string'},
    'ether-type':           {'uint16', 'uint32'},
    'password':             {'password'},
}
# {user} is the PDF's catch-all for "a value with its own syntax": ranges, times, lists,
# masks. It agrees with any schema type except an option list.
USER_ANY = True


def bundle_type(ty):
    """password-2, password-3, 'password_ aes256', 'varlen_ password' are all passwords."""
    ty = (ty or '').strip()
    if ty.startswith('password') or ty.startswith('varlen_ password'):
        return 'password'
    return ty


def type_agrees(bty, stype, has_opts):
    b = bundle_type(bty)
    if b == 'user':
        return not has_opts
    if b == 'option':
        return has_opts and stype in OPT_T
    if has_opts:
        return False
    return stype in VOCAB.get(b, ())


# ---------------------------------------------------------------- flattening
def flat_schema(tab):
    """-> {leaf: {'attrs': {name: [attr,...]}, 'mkeys': set}} ; leaf None is the table."""
    out = {}

    def walk(t, leaf):
        e = out.setdefault(leaf, {'attrs': {}, 'mkeys': set()})
        for a, d in (t.get('attr') or {}).items():
            e['attrs'].setdefault(a, []).append(d)
        if t.get('mkey'):
            e['mkeys'].add(t['mkey'])
        for k, v in (t.get('subobj') or {}).items():
            walk(v, k)
    walk(tab, None)
    return out


def flat_bundle(sec):
    out = {}
    for x in sec.get('x') or ():
        out.setdefault(x.get('t'), {}).setdefault(x['n'], []).append(x)
    return out


# ---------------------------------------------------------------- value comparison
def norm_default(v):
    """A default as comparable text. None stays None; the schema's '' is the empty string."""
    if v is None:
        return None
    if isinstance(v, list):
        return ' '.join(str(i) for i in v)
    s = str(v).strip()
    return '' if s in ("''", '""') else s


def default_verdict(bty, bdf, sdf):
    """-> (state, pattern). state: 'same' | 'vocab' | 'differ'."""
    b, s = norm_default(bdf), norm_default(sdf)
    if b == s:
        return 'same', None
    bt = bundle_type(bty)
    if b is None and s == '':
        return 'vocab', 'empty-string default'
    if b is None and bt == 'password' and s is not None:
        return 'vocab', 'password default is ciphertext'
    if b == '0' and s is None:
        return 'vocab', 'schema leaves a zero default implicit'
    if b is not None and s is not None:
        if bt.startswith('ipv4-classnet') or bt.startswith('ipv4-netmask') or bt == 'ipv6-wildcard':
            if s.split() and s.split()[0] == b.split()[0] and len(s.split()) == 2 and len(b.split()) == 1:
                return 'vocab', 'address default without its mask'
    # genuine differences, named by shape
    if b is not None and (b.endswith('**') or b.endswith(' *')):
        return 'differ', 'footnote marker in default'
    if b is not None and s is not None and b.replace(' ', '') == s.replace(' ', ''):
        return 'differ', 'space inside default (page-break wrap)'
    if b is None:
        return 'differ', 'default missing in bundle'
    if s is None:
        return 'differ', 'default missing in schema'
    return 'differ', 'default value differs'


def option_verdict(x, d):
    """-> (bundle_only, schema_only, pattern) for an option attribute; empty sets if equal."""
    so = set((d.get('opts') or {}).keys())
    has_o = bool(x.get('o'))
    bo = {o[0] for o in (x.get('o') or ())}
    if so == bo:
        return set(), set(), None
    b_only, s_only = bo - so, so - bo
    if not has_o:
        return b_only, s_only, 'option list absent in bundle'
    if b_only and any(any(sx.startswith(b) and sx != b for sx in s_only) for b in b_only):
        return b_only, s_only, 'option name cut at a line wrap'
    if b_only and s_only:
        return b_only, s_only, 'option lists overlap but differ'
    if s_only:
        return b_only, s_only, 'option missing from bundle'
    return b_only, s_only, 'option missing from schema'


# ---------------------------------------------------------------- the comparison
def compare(schema, bundle, only_table=None):
    """schema: {table: {...}}; bundle: parsed bundle dict. -> result dict."""
    secs = {s['p']: s for s in bundle['secs'] if s['k'] == 'config'}
    st, bt = set(schema), set(secs)
    if only_table:
        st, bt = st & {only_table}, bt & {only_table}
    both = sorted(st & bt)
    r = {'tables': {'both': len(both), 'schema_only': sorted(st - bt), 'bundle_only': sorted(bt - st)},
         'subtables': {'both': 0, 'schema_only': 0, 'bundle_only': 0},
         'params': {'both': 0, 'schema_only': 0, 'bundle_only': 0, 'keys': 0, 'ambiguous': 0,
                    'schema_only_internal': 0, 'bundle_only_tables': 0, 'schema_only_tables': 0},
         'type': {'agree': 0, 'vocab': collections.Counter(), 'differ': 0},
         'default': {'agree': 0, 'vocab': collections.Counter(), 'differ': 0},
         'options': {'agree': 0, 'differ': 0},
         'items': []}
    for tp in both:
        sf, bf = flat_schema(schema[tp]), flat_bundle(secs[tp])
        pg = secs[tp].get('pg')
        for leaf in set(sf) | set(bf):
            if leaf not in sf:
                r['subtables']['bundle_only'] += 1
            elif leaf not in bf:
                r['subtables']['schema_only'] += 1
            elif leaf is not None:
                r['subtables']['both'] += 1
        for leaf in sorted(set(sf) & set(bf), key=lambda v: v or ''):
            sa, ba, mk = sf[leaf]['attrs'], bf[leaf], sf[leaf]['mkeys']
            for name in set(sa) | set(ba):
                if name not in ba:
                    r['params']['schema_only'] += 1
                    r['params']['schema_only_internal'] += name.startswith('_')
                    continue
                if name not in sa:
                    if name in mk:
                        r['params']['keys'] += 1
                    else:
                        r['params']['bundle_only'] += 1
                    continue
                r['params']['both'] += 1
                if len(sa[name]) > 1 or len(ba[name]) > 1:
                    r['params']['ambiguous'] += 1
                    continue
                compare_param(r, tp, leaf, name, ba[name][0], sa[name][0], pg)
        # tables present on one side only still have parameters; count them too
    for tp in r['tables']['bundle_only']:
        r['params']['bundle_only_tables'] += len(secs[tp].get('x') or ())
    for tp in r['tables']['schema_only']:
        for leaf, e in flat_schema(schema[tp]).items():
            r['params']['schema_only_tables'] += len(e['attrs'])
    return r


def compare_param(r, tp, leaf, name, x, d, pg):
    has_opts = 'opts' in d
    base = {'table': tp, 'sub': leaf, 'attr': name, 'pg': pg,
            'excl': bool(d.get('excluded'))}
    fmg_only = name.startswith('_')

    def emit(kind, pattern, bundle, schema_v, **more):
        base_cls = 'schema-excluded' if fmg_only else 'likely-parser'
        r['items'].append(dict(base, kind=kind, cls=base_cls, pattern=pattern,
                               bundle=bundle, schema=schema_v, **more))
        r[kind]['differ'] += 1

    # type
    if type_agrees(x.get('ty'), d.get('type'), has_opts):
        r['type']['agree'] += 1
        raw = (x.get('ty') or '').strip()
        if raw == 'option':
            r['type']['vocab'][('option', d.get('type') + ' + opts')] += 1
        elif raw != d.get('type'):
            r['type']['vocab'][(raw, d.get('type'))] += 1
    else:
        emit('type', 'type mismatch', x.get('ty'), d.get('type') + (' + opts' if has_opts else ''))
    # default
    state, pat = default_verdict(x.get('ty'), x.get('df'), d.get('default'))
    if state == 'same':
        r['default']['agree'] += 1
        if isinstance(d.get('default'), int) and x.get('df') is not None:
            r['default']['vocab']['0 vs "0": number in schema, text in bundle'] += 1
    elif state == 'vocab':
        r['default']['agree'] += 1
        r['default']['vocab'][pat] += 1
    else:
        emit('default', pat, x.get('df'), d.get('default'))
    # options
    if has_opts and bundle_type(x.get('ty')) == 'option':
        b_only, s_only, pat = option_verdict(x, d)
        if pat is None:
            r['options']['agree'] += 1
        else:
            emit('options', pat, sorted(b_only), sorted(s_only))
            r['items'][-1]['bundle_has_list'] = bool(x.get('o'))


def trim(s, n=60):
    if s is None:
        return '(none)'
    s = json.dumps(s) if not isinstance(s, str) else s
    return s if len(s) <= n else s[:n - 3] + '...'


# ---------------------------------------------------------------- report
def report(train, r, out=sys.stdout):
    p = lambda *a: print(*a, file=out)
    t, pa = r['tables'], r['params']
    p(f'== FortiOS {train}: FortiManager schema vs bundle ==')
    p(f"tables      in both {t['both']}   schema-only {len(t['schema_only'])}   bundle-only {len(t['bundle_only'])}")
    s = r['subtables']
    p(f"sub-tables  in both {s['both']}   schema-only {s['schema_only']}   bundle-only {s['bundle_only']}"
      '   (inside joined tables)')
    p(f"parameters  in both {pa['both']}   schema-only {pa['schema_only'] + pa['schema_only_tables']}"
      f"   bundle-only {pa['bundle_only'] + pa['bundle_only_tables']}")
    p(f"            schema-only = {pa['schema_only']} in joined tables ({pa['schema_only_internal']} begin `_`)"
      f" + {pa['schema_only_tables']} in schema-only tables")
    p(f"            bundle-only = {pa['bundle_only']} in joined tables + {pa['bundle_only_tables']} in bundle-only tables"
      f"   (+{pa['keys']} edit keys; {pa['ambiguous']} of 'in both' ambiguous, not compared)")
    for k, label in (('type', 'type'), ('default', 'default'), ('options', 'option list')):
        cls = collections.Counter(i['cls'] for i in r['items'] if i['kind'] == k)
        v = sum(r[k]['vocab'].values()) if k != 'options' else 0
        p(f"{label:<12}agree {r[k]['agree']}   differ {r[k]['differ']}"
          + (f"   (of agree, {v} only through the vocabulary)" if k != 'options' else '')
          + (f"   by class: {dict(cls)}" if cls else ''))
    p('')
    pat = collections.Counter((i['kind'], i['pattern']) for i in r['items'] if i['cls'] == 'likely-parser')
    p('likely-parser patterns, most frequent first')
    for (k, pt), n in pat.most_common():
        p(f'  {n:>5}  {k:<8} {pt}')
    p('')
    p(f'top {TOP20} likely-parser examples (at most {PER_PATTERN} per pattern, commonest pattern first)')
    for i in top_examples(r):
        p(f"  {i['table']}{' > ' + i['sub'] if i['sub'] else ''} / {i['attr']}  p.{i['pg']}  [{i['kind']}: {i['pattern']}]")
        p(f"      bundle {trim(i['bundle'])}   schema {trim(i['schema'])}")
    p('')


def top_examples(r):
    items = [i for i in r['items'] if i['cls'] == 'likely-parser']
    pat = collections.Counter((i['kind'], i['pattern']) for i in items)
    seen, out = collections.Counter(), []
    for i in sorted(items, key=lambda i: (-pat[(i['kind'], i['pattern'])], i['table'], i['attr'])):
        k = (i['kind'], i['pattern'])
        if seen[k] < PER_PATTERN:
            seen[k] += 1
            out.append(i)
    return out[:TOP20]


def jsonable(r):
    j = dict(r)
    for k in ('type', 'default'):
        j[k] = dict(r[k], vocab=[[list(a) if isinstance(a, tuple) else a, n] for a, n in r[k]['vocab'].items()])
    return j


# ---------------------------------------------------------------- selftest
def selftest():
    def attr(typ, **kw):
        return dict({'type': typ}, **kw)
    sdwan_sla_h = {'mkey': 'id', 'attr': {'jitter': attr('uint32', default=5)}}
    sdwan_sla_s = {'mkey': 'id', 'attr': {'jitter': attr('uint32', default=7)}}
    schema = {
        'sys a': {'attr': {
            'port':   attr('uint32', default=80),                       # vocab: uint32/integer, 80 vs "80"
            'mode':   attr('uint8', default='auto', opts={'auto': 0, 'erspan-auto': 1}, excluded=True),
            'state':  attr('uint8', default='enable', opts={'enable': 0, 'disable': 1}),
            'subnet': attr('ipv4_mask', default='0.0.0.0 0.0.0.0'),     # vocab: mask appended
            'pw':     attr('password', default='ENC abc'),              # vocab: ciphertext default
            'note':   attr('string', default="''"),                     # vocab: empty string
            'name':   attr('string'),
            'weird':  attr('ip4'),                                      # type mismatch vs bundle integer
            'wrap':   attr('string', default='Fortinet_SSL'),           # default wrapped by the PDF
            'dflt':   attr('uint32', default=9),
            'tail':   attr('uint8', default='a', opts={'a': 0, 'b': 1, 'c': 2}),   # list lost its tail
            'noopt':  attr('uint8', default='a', opts={'a': 0, 'b': 1}),           # no list at all in bundle
            '_fmg':   attr('uint32', default=1),                        # FortiManager's own, and it disagrees
            '_only':  attr('uint32'),                                   # FortiManager's own, schema-only
            'extra':  attr('string'),                                   # schema-only
        }, 'mkey': 'name',
         'subobj': {'sla': {'mkey': 'id', 'attr': {'loss': attr('uint32', default=1)}},
                    'hc': {'mkey': 'name', 'subobj': {'sla': sdwan_sla_h}, 'attr': {}},
                    'svc': {'mkey': 'id', 'subobj': {'sla': sdwan_sla_s}, 'attr': {}}}},
        'sys only': {'attr': {'q': attr('string')}},
    }
    bx = lambda n, ty, **kw: dict({'n': n, 'k': n, 'ty': ty}, **kw)
    bundle = {'secs': [
        {'k': 'config', 'p': 'sys a', 'pg': 42, 'x': [
            bx('port', 'integer', df='80'),
            bx('mode', 'option', df='auto', o=[['auto', ''], ['erspan-', '']]),
            bx('state', 'option', df='enable', o=[['enable', ''], ['disable', '']]),
            bx('subnet', 'ipv4-classnet', df='0.0.0.0'),
            bx('pw', 'password-3'),
            bx('note', 'var-string'),
            bx('name', 'string'),
            bx('weird', 'integer'),
            bx('wrap', 'string', df='Fortinet_ SSL'),
            bx('dflt', 'integer', df='9 **'),
            bx('tail', 'option', df='a', o=[['a', ''], ['b', '']]),
            bx('noopt', 'option', df='a'),
            bx('_fmg', 'integer', df='2'),
            bx('bundleonly', 'string'),
            bx('loss', 'integer', df='1', t='sla'),
            bx('jitter', 'integer', df='5', t='sla'),
            bx('id', 'integer', t='sla'),            # the sub-table's edit key, not a bundle-only parameter
        ]},
        {'k': 'config', 'p': 'bundle only', 'pg': 1, 'x': [bx('z', 'string')]},
        {'k': 'cli', 'p': 'get system status'},
    ]}
    r = compare(schema, bundle)
    cl = lambda kind: {(i['attr'], i['cls'], i['pattern']) for i in r['items'] if i['kind'] == kind}
    # tables and parameters
    assert r['tables']['both'] == 1 and r['tables']['schema_only'] == ['sys only'], r['tables']
    assert r['tables']['bundle_only'] == ['bundle only']
    assert r['params']['keys'] == 1, r['params']
    assert r['params']['schema_only_internal'] == 1, r['params']
    assert r['params']['ambiguous'] == 1 and r['params']['bundle_only'] == 1, r
    assert r['params']['bundle_only_tables'] == 1 and r['params']['schema_only_tables'] == 1, r['params']
    # nested join: loss and jitter joined by leaf 'sla'; jitter is ambiguous on the schema side (two sla), not compared
    assert not any(i['attr'] == 'loss' for i in r['items'])
    assert not any(i['attr'] == 'jitter' for i in r['items'])
    # type vocabulary applied: uint32/integer, option/uint8+opts, ip mask, password, string
    v = r['type']['vocab']
    assert v[('integer', 'uint32')] >= 2 and v[('option', 'uint8 + opts')] == 4, dict(v)
    assert v[('ipv4-classnet', 'ipv4_mask')] == 1 and v[('password-3', 'password')] == 1, dict(v)
    # ... and only the real mismatch is reported
    assert cl('type') == {('weird', 'likely-parser', 'type mismatch')}, cl('type')
    # defaults: vocab ones agree and are tallied; the rest classified
    dv = r['default']['vocab']
    assert dv['address default without its mask'] == 1 and dv['empty-string default'] == 1, dict(dv)
    assert type_agrees('datetime', 'user', False) and default_verdict('integer', '0', None)[0] == 'vocab'
    assert dv['password default is ciphertext'] == 1, dict(dv)
    assert cl('default') == {
        ('wrap', 'likely-parser', 'space inside default (page-break wrap)'),
        ('dflt', 'likely-parser', 'footnote marker in default'),
        ('_fmg', 'schema-excluded', 'default value differs'),
    } | {i for i in cl('default') if i[0] in ('noopt',)}, cl('default')
    # options: schema `excluded: true` must NOT change the class; wrap and truncation detected
    o = cl('options')
    assert ('mode', 'likely-parser', 'option name cut at a line wrap') in o, o
    assert ('tail', 'likely-parser', 'option missing from bundle') in o, o
    assert ('noopt', 'likely-parser', 'option list absent in bundle') in o, o
    assert not any(i[0] == 'state' for i in o), o
    # the pg of the bundle entry rides on every item, and the JSON form serialises
    assert all(i['pg'] == 42 for i in r['items'])
    json.dumps(jsonable(r))
    # top examples: likely-parser only, capped per pattern
    assert all(i['cls'] == 'likely-parser' for i in top_examples(r))
    # --table narrows
    assert compare(schema, bundle, 'sys a')['tables']['bundle_only'] == []
    # type_agrees: {user} agrees with anything but an option list
    assert type_agrees('user', 'multi_int', False) and not type_agrees('user', 'uint8', True)
    assert not type_agrees('string', 'uint32', False) and not type_agrees('integer', 'uint32', True)
    print('diff_schema selftest: ok')


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--brain', default=DEFAULT_BRAIN, help='fortinet-brain checkout (read only)')
    ap.add_argument('--train', default='all', choices=['7.6', '8.0', 'all'])
    ap.add_argument('--table', help='one table path, e.g. "system sdwan"')
    ap.add_argument('--json', metavar='FILE', help='write the full disagreement list here')
    ap.add_argument('--selftest', action='store_true')
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    trains = list(TRAINS) if a.train == 'all' else [a.train]
    if a.json and len(trains) > 1:
        sys.exit('--json takes one --train; make schema-diff runs each train in turn')
    for tr in trains:
        sp = os.path.join(a.brain, SCHEMA_REL.format(train=tr))
        bp = os.path.join(ROOT, TRAINS[tr])
        for pth in (sp, bp):
            if not os.path.exists(pth):
                sys.exit(f'missing {pth}' + ('  (use --brain PATH)' if pth == sp else ''))
        with open(sp) as f:
            schema = json.load(f)
        with open(bp) as f:
            bundle = json.load(f)
        r = compare(schema, bundle, a.table)
        report(tr, r)
        if a.json:
            os.makedirs(os.path.dirname(os.path.abspath(a.json)), exist_ok=True)
            with open(a.json, 'w') as f:
                json.dump(jsonable(r), f, indent=1, sort_keys=True)
            print(f'wrote {a.json}: {len(r["items"])} disagreements')


if __name__ == '__main__':
    main()
