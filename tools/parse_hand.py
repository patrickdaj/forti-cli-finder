#!/usr/bin/env python3
"""Parse hand-written Fortinet CLI references (FortiSwitchOS, FortiAnalyzer, FortiManager) from
pdftotext -layout output into the same section format as parse_fos.py.

Layout: unindented heading; indented prose; 'Syntax' then an indented command block (possibly several);
'Variable  Description [Default]' table; optional 'Example' blocks.
"""
import re, sys, json

src, out, product = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(src, encoding='utf-8', errors='replace').read().replace('\f', '')
lines = text.split('\n')
FOOT = re.compile(r'^\S.*CLI Reference\s+(\d+)\s*$')

clean = []
page = 0
i, n = 0, len(lines)
while i < n:
    l = lines[i]
    m = FOOT.match(l)
    if m:
        page = int(m.group(1)); i += 1
        if i < n and lines[i].startswith('Fortinet Inc.'):
            i += 1
            j = i
            while j < n and lines[j].strip() == '':
                j += 1
            if j < n and lines[j] and not lines[j].startswith(' ') and len(lines[j].split()) <= 5:
                i = j + 1
        continue
    clean.append((page + 1 if page else 0, l))
    i += 1

VERB = re.compile(r'^(config|execute|diagnose|get|show|set|unset|end|next|edit|exec|diag)\b')
TBL = re.compile(r'^(\s*)Variable\s+Description(\s+Default)?\s*$')
SYN = re.compile(r'^\s*Syntax\s*$')
EXA = re.compile(r'^\s*Example[s]?( output)?\s*$')
SKIPHEAD = re.compile(r'^(https?://|Change log|Introduction|What|Using the Command|Appendix|Administrative Domains|Table of Contents|Contents)')

def col_slices(header):
    return [(m.group(0), m.start()) for m in re.finditer(r'\S+', header)]

def slice_cols(line, cols):
    vals = []
    for k, (name, start) in enumerate(cols):
        end = cols[k + 1][1] if k + 1 < len(cols) else None
        vals.append(line[start:end].strip() if end else line[start:].strip())
    return vals

def unclosed(s):
    return s.endswith('-') or s.count('<') > s.count('>') or s.count('{') > s.count('}') or s.count('[') > s.count(']')

sections = []
cur = None
mode = None   # None | 'prose' | 'syntax' | 'table' | 'example'
cols = None
row = None
N = len(clean)
idx = 0
# Skip front matter: start at the first 'Syntax' heading's section; simpler: skip until the first line after the TOC.
# TOC lines contain '....' or end with a page number after many spaces; headings in TOC are indented. Our headings are
# unindented, so front matter only contributes junk headings which we filter below.
while idx < N:
    page, l = clean[idx]
    if l and not l.startswith(' ') and not SKIPHEAD.match(l):
        head = l.strip()
        while idx + 1 < N and clean[idx+1][1] and not clean[idx+1][1].startswith(' ') and not SKIPHEAD.match(clean[idx+1][1]) and head.endswith('-'):
            idx += 1; head = head + clean[idx][1].strip()
        cur = {'kind': '', 'path': '', 'head': head, 'desc': '', 'page': page, 'syntax': [], 'params': [], 'notes': [], 'examples': [], 'product': product}
        sections.append(cur)
        mode = 'prose'; row = None
        idx += 1
        continue
    if cur is None:
        idx += 1
        continue
    if SYN.match(l):
        mode = 'syntax'; idx += 1
        if cur['syntax']:
            cur['syntax'].append('')
        continue
    if EXA.match(l):
        mode = 'example'; cur['examples'].append([]); idx += 1
        continue
    mt = TBL.match(l)
    if mt:
        mode = 'table'; cols = col_slices(l); row = None; idx += 1
        continue
    if mode == 'prose':
        if l.strip():
            cur['desc'] += (' ' if cur['desc'] else '') + l.strip()
    elif mode == 'syntax':
        if l.strip() == '':
            # keep a single blank only inside a block; drop runs
            if cur['syntax'] and cur['syntax'][-1] != '':
                cur['syntax'].append('')
        else:
            cur['syntax'].append(l.rstrip())
    elif mode == 'example':
        cur['examples'][-1].append(l.rstrip())
    elif mode == 'table':
        if l.strip() == '':
            idx += 1; continue
        pstart, dstart = cols[0][1], cols[1][1]
        first = l[pstart:dstart].strip() if len(l) > pstart else ''
        lead = len(l) - len(l.lstrip())
        vals = slice_cols(l, cols)
        prev_blank = clean[idx - 1][1].strip() == ''
        cont = row is not None and (row['_wrap'] or ('|' in first and '{' not in first) or (not prev_blank and (first[:1] in '{[' or (first[:1] == '<' and not re.search(r'[<{\[]', row['name'])))))
        if first and lead <= pstart + 1 and not cont:
            row = {'table': '', 'name': first, 'desc': vals[1], 'default': vals[2] if len(vals) > 2 else '', '_wrap': unclosed(first)}
            cur['params'].append(row)
        elif row is not None:
            if first:
                row['name'] = (row['name'] + ('' if row['name'].endswith('-') else ' ') + first).strip()
                row['_wrap'] = unclosed(row['name'])
            if vals[1]:
                v = re.sub(r'^l\s+(?=\S)', '\u2022 ', vals[1])
                row['desc'] = (row['desc'] + (' ' if not v.startswith('\u2022') else ' ') + v).strip()
            if len(vals) > 2 and vals[2]:
                row['default'] = (row['default'] + ' ' + vals[2]).strip()
    idx += 1

final = []
for s in sections:
    syn = [x for x in s['syntax']]
    while syn and syn[-1] == '':
        syn.pop()
    while syn and syn[0] == '':
        syn.pop(0)
    if syn:
        ind = min(len(x) - len(x.lstrip()) for x in syn if x.strip())
        syn = [x[ind:] if x.strip() else '' for x in syn]
    s['syntax'] = syn
    # path and kind from the first syntax line, else from the heading
    first = next((x.strip() for x in syn if x.strip()), '')
    m = VERB.match(first)
    if m and m.group(1) in ('config', 'execute', 'diagnose', 'get', 'show'):
        s['kind'] = m.group(1)
        s['path'] = re.sub(r'\s+', ' ', first[len(m.group(1)):]).strip()
    else:
        hm = VERB.match(s['head'])
        if hm and hm.group(1) in ('config', 'execute', 'diagnose', 'get', 'show'):
            s['kind'] = hm.group(1); s['path'] = s['head'][len(hm.group(1)):].strip()
        else:
            continue  # chapter intro or junk heading
    if not syn and not s['params']:
        continue
    ex = []
    for e in s['examples']:
        e = [x for x in e]
        while e and not e[-1].strip(): e.pop()
        while e and not e[0].strip(): e.pop(0)
        if not e: continue
        ind = min(len(x) - len(x.lstrip()) for x in e if x.strip())
        ex.append('\n'.join(x[ind:] if x.strip() else '' for x in e))
    s['examples'] = ex
    # A "config <name>" row in the variable table opens a sub-table: it is a heading for
    # the parameters under it, not a parameter called "config". Turn it into their table.
    kept, table = [], ''
    for p in s['params']:
        m = re.match(r'^config\s+(\S.*)$', p['name'].strip())
        if m and len(m.group(1).split()) <= 4:
            table = m.group(1).strip().rstrip('.')
            continue
        p['table'] = p.get('table') or table
        kept.append(p)
    s['params'] = kept
    for p in s['params']:
        p.pop('_wrap', None)
        p['key'] = re.split(r'[\s(<{\[]', p['name'], maxsplit=1)[0] or p['name']
        p['type'] = ''; p['size'] = ''; p['options'] = []
        # options embedded in the name: foo {a | b}
        mo = re.search(r'\{([^}]*)\}', p['name'])
        if mo and '|' in mo.group(1):
            p['options'] = [{'v': v.strip(), 'desc': ''} for v in mo.group(1).split('|')]
            p['type'] = 'option'
    s.pop('head', None)
    final.append(s)

json.dump(final, open(out, 'w'), ensure_ascii=False)
kinds = {}
for s in final:
    kinds[s['kind']] = kinds.get(s['kind'], 0) + 1
print(len(final), 'sections', kinds, sum(len(s['params']) for s in final), 'params', sum(len(s['examples']) for s in final), 'examples')
