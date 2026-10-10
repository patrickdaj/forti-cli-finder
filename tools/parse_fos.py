#!/usr/bin/env python3
"""Parse the FortiOS CLI Reference (pdftotext -layout output) into a command tree.

Output: list of sections
 {kind: config|execute|diagnose, path: 'system ha', desc, page, syntax: [lines],
  params: [{table, name, desc, type, size, default, options:[{v,desc}], note}]}
"""
import re, sys, json

src, out, product = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(src, encoding='utf-8', errors='replace').read()
lines = text.replace('\f', '').split('\n')

FOOT = re.compile(r'^\S.*CLI Reference\s+(\d+)\s*$')
# ---- pass 1: strip footers / running heads, keep page numbers per line
clean = []  # (page, line)
page = 0
i = 0
n = len(lines)
while i < n:
    l = lines[i]
    m = FOOT.match(l)
    if m:
        page = int(m.group(1))
        i += 1
        if i < n and lines[i].startswith('Fortinet Inc.'):
            i += 1
        # running head: a short unindented line like 'CLI diagnose commands', 'system', 'config'
        # followed by blank lines; it is not a section heading if it has no verb prefix
        j = i
        while j < n and lines[j].strip() == '':
            j += 1
        if j < n and lines[j] and not lines[j].startswith(' '):
            head = lines[j].strip()
            if not re.match(r'^(config|execute|diagnose|get)\s', head):
                i = j + 1
        continue
    clean.append((page + 1 if page else 0, l))
    i += 1

HEAD = re.compile(r'^(config|execute|diagnose|get) (\S.*)$')
TBL = re.compile(r'^(\s*)Parameter\s+Description(\s+Type)?(\s+Size)?(\s+Default)?\s*$')
OPTH = re.compile(r'^(\s*)Option\s+Description\s*$')
SUBT = re.compile(r'^   config (\S.*)$')
NOTE = re.compile(r'^\s*\*{1,2} (This parameter|Values|This|The) ')

sections = []
cur = None

def new_section(kind, path, page):
    s = {'kind': kind, 'path': path.strip(), 'desc': '', 'page': page, 'syntax': [], 'params': [], 'notes': []}
    sections.append(s)
    return s

def unclosed(name):
    return name.endswith('-') or (name.count('<') > name.count('>')) or (name.count('[') > name.count(']')) or (name.count('{') > name.count('}'))

def strip_flag(name):
    m = re.match(r'^(.*?)\s*(\*{1,2})$', name)
    if m:
        return m.group(1), m.group(2)
    return name, ''

def col_slices(header):
    """Return list of (name, start) from a table header line."""
    cols = []
    for m in re.finditer(r'\S+', header):
        cols.append((m.group(0), m.start()))
    return cols

def slice_cols(line, cols):
    vals = []
    for k, (name, start) in enumerate(cols):
        end = cols[k + 1][1] if k + 1 < len(cols) else None
        vals.append(line[start:end].strip() if end else line[start:].strip())
    return vals

idx = 0
N = len(clean)
while idx < N:
    page, l = clean[idx]
    m = HEAD.match(l)
    if m and not l.startswith(' '):
        kind, path = m.group(1), m.group(2)
        # Skip index-style headings ("diagnose alertconsole" topic pages list sub-commands)
        idx += 1
        # heading wrapped onto a second unindented line
        while idx < N and clean[idx][1] and not clean[idx][1].startswith(' ') and not HEAD.match(clean[idx][1]) and not FOOT.match(clean[idx][1]):
            path = path + ('' if path.endswith('-') else ' ') + clean[idx][1].strip()
            idx += 1
        cur = new_section(kind, path, page)
        # description: following indented lines until blank
        while idx < N and clean[idx][1].strip() == '':
            idx += 1
        desc = []
        while idx < N and clean[idx][1].startswith('   ') and clean[idx][1].strip():
            t = clean[idx][1].strip()
            if t.startswith('This topic includes the following commands'):
                cur['index'] = True
            desc.append(t)
            idx += 1
        cur['desc'] = ' '.join(desc)
        # syntax block: indented >= 5 lines until a blank line followed by table header / another heading / 'Parameter'
        while idx < N and clean[idx][1].strip() == '':
            idx += 1
        syn = []
        while idx < N:
            p2, l2 = clean[idx]
            if HEAD.match(l2) and not l2.startswith(' '):
                break
            if TBL.match(l2) or SUBT.match(l2) or NOTE.match(l2):
                break
            if l2.strip() == '':
                # end syntax if the next non-blank is a table header / subtable / heading / note
                j = idx
                while j < N and clean[j][1].strip() == '':
                    j += 1
                if j >= N or TBL.match(clean[j][1]) or SUBT.match(clean[j][1]) or (HEAD.match(clean[j][1]) and not clean[j][1].startswith(' ')) or NOTE.match(clean[j][1]):
                    idx = j
                    break
                syn.append('')
                idx += 1
                continue
            syn.append(l2.rstrip())
            idx += 1
        # normalise syntax indentation: remove common leading spaces
        syn = [s for s in syn]
        while syn and syn[-1] == '':
            syn.pop()
        if syn:
            ind = min(len(s) - len(s.lstrip()) for s in syn if s.strip())
            syn = [s[ind:] if s.strip() else '' for s in syn]
        # "This topic includes the following commands:" marks a contents page, not a
        # command. It usually sits in the description, but when the description is a bare
        # repeat of the heading it lands here instead.
        if syn and re.match(r'^This topic includes', syn[0].strip()):
            cur['index'] = True
        cur['syntax'] = syn
        continue

    if l and not l.startswith(' ') and not HEAD.match(l):
        cur = None   # category page ('azure', 'system') or stray line ends the section
    if cur is None:
        idx += 1
        continue

    # sub-table marker
    ms = SUBT.match(l)
    if ms:
        cur['_table'] = ms.group(1).strip()
        idx += 1
        continue
    # notes
    if NOTE.match(l):
        cur['notes'].append(l.strip())
        idx += 1
        continue

    mt = TBL.match(l)
    if mt and cur.get('index'):
        idx += 1
        continue
    if mt:
        cols = col_slices(l)
        table = cur.get('_table', '')
        idx += 1
        # parse rows until next heading / subtable / table header / note
        row = None
        in_opts = False
        optcols = None
        while idx < N:
            p2, l2 = clean[idx]
            if (HEAD.match(l2) and not l2.startswith(' ')) or SUBT.match(l2) or TBL.match(l2) or NOTE.match(l2):
                break
            if (l2 and not l2.startswith(' ')) or re.match(r'^\s*l\s{2,}\S', l2) or 'includes syntax for the following' in l2 or 'includes the following commands' in l2:
                break
            if l2.strip() == '':
                idx += 1
                continue
            mo = OPTH.match(l2)
            if mo:
                in_opts = True
                optcols = col_slices(l2)
                idx += 1
                continue
            pstart = cols[0][1]
            dstart = cols[1][1]
            first = l2[pstart:dstart].strip() if len(l2) > pstart else ''
            lead = len(l2) - len(l2.lstrip())
            if in_opts and lead >= optcols[0][1] - 1 and row is not None and lead > pstart:
                v = slice_cols(l2, optcols)
                if v[0]:
                    row['options'].append({'v': v[0], 'desc': v[1]})
                elif row['options'] and v[1]:
                    row['options'][-1]['desc'] += ' ' + v[1]
                idx += 1
                continue
            vals = slice_cols(l2, cols)
            if first and lead <= pstart + 1 and strip_flag(first)[0] == '' and row is not None:
                row['flag'] = row.get('flag') or strip_flag(first)[1]
                vals = slice_cols(l2, cols)
                for k, (name, _) in enumerate(cols[1:], 1):
                    if vals[k]:
                        key = name.lower()
                        row[key] = (row[key] + ' ' + vals[k]).strip()
                idx += 1
                continue
            if first and lead <= pstart + 1:
                # new row, unless previous row name wrapped (previous row's desc empty so far and no blank line between)
                prev_blank = clean[idx - 1][1].strip() == ''
                if row is not None and not prev_blank and row['_wrap']:
                    first, flag = strip_flag(first)
                    row['name'] += first
                    row['flag'] = row.get('flag') or flag
                    row['_wrap'] = unclosed(row['name'])
                    for k, (name, _) in enumerate(cols[1:], 1):
                        if vals[k]:
                            key = name.lower()
                            row[key] = (row[key] + ' ' + vals[k]).strip()
                    idx += 1
                    continue
                in_opts = False
                first, flag = strip_flag(first)
                row = {'table': table, 'name': first, 'description': '', 'type': '', 'size': '', 'default': '', 'options': [], 'flag': flag, '_wrap': unclosed(first)}
                for k, (name, _) in enumerate(cols[1:], 1):
                    row[name.lower()] = vals[k]
                cur['params'].append(row)
                idx += 1
                continue
            # continuation of the current row
            if row is not None:
                for k, (name, _) in enumerate(cols[1:], 1):
                    if vals[k]:
                        key = name.lower()
                        row[key] = (row[key] + ' ' + vals[k]).strip()
                if first:
                    first, flag = strip_flag(first)
                    row['name'] += first
                    row['flag'] = row.get('flag') or flag
            idx += 1
        continue
    idx += 1

ELEM = re.compile(r'^<[^<>]*>$')
def fold_elements(sections):
    """Fold an element row back into the parameter above it.

    A multi-value parameter is printed over two table rows: the name on the first,
    a bare placeholder on the second, and the Description and Size cells wrap across
    both -- so `application / <id>` is one list-of-IDs parameter, not two, and its
    size really reads 'Minimum value: 0 Maximum value: 4294967295'.

    Only for config. In execute and diagnose a <...> row is a genuine argument
    ('execute vpn ipsec tunnel down <phase2>'), so those are left alone.
    """
    n = 0
    merged = re.compile(r'^(\S+)\s+(<[^<>]*>)$')
    for s in sections:
        if s['kind'] != 'config':
            continue
        out = []
        for p in s['params']:
            # The element sometimes lands in the Parameter cell itself ("srcaddr <name>")
            # when the table indents it far enough to read as a continuation of the row.
            # Same thing, caught one step later.
            m = merged.match(p['name'].strip())
            if m:
                p['name'], p['elem'] = m.group(1), m.group(2)
                p['key'] = m.group(1)
                n += 1
            prev = out[-1] if out else None
            if prev is not None and ELEM.match(p['name'].strip()) and prev.get('table', '') == p.get('table', ''):
                prev['elem'] = p['name'].strip()          # the parameter takes a list of these
                if p['size']:
                    prev['size'] = (prev['size'] + ' ' + p['size']).strip()
                for f in ('type', 'default'):
                    if p[f] and not prev[f]:
                        prev[f] = p[f]
                if p['description']:
                    prev['description'] = (prev['description'] + ' ' + p['description']).strip()
                prev['options'].extend(p['options'])
                n += 1
                continue
            out.append(p)
        s['params'] = out
    return n

folded = fold_elements(sections)

# 124 sections have no description at all -- just "This command is available for
# model(s):" and 133 model names, ~2500 characters of it. Left in `desc` it is what the
# listing shows for the command and it is taller than the viewport when selected. Pull it
# out; build_bundles.py interns the handful of distinct lists.
MODELS = re.compile(r'^This command is available for model\(s\):\s*(.+)$', re.S)
for s in sections:
    m = MODELS.match((s.get('desc') or '').strip())
    if m:
        s['models'] = [x.strip() for x in re.sub(r'\s+', ' ', m.group(1)).split(',') if x.strip()]
        s['desc'] = ''

for s in sections:
    s.pop('_table', None)
    for p in s['params']:
        p.pop('_wrap', None)
        p['desc'] = p.pop('description', '')
        # normalise size like 'Minimum value: 0 Maximum value: 1023'
        p['size'] = re.sub(r'\s+', ' ', p['size'])
        p['type'] = re.sub(r'-\s+', '-', p['type'])
        if not p.get('flag'): p.pop('flag', None)
        p['key'] = re.split(r'[\s(]', p['name'], maxsplit=1)[0]
        # default may repeat on wrapped lines ("0.0.0.0 0.0.0.0")
        d = p['default'].split()
        if len(d) == 2 and d[0] == d[1]:
            p['default'] = d[0]
    s['product'] = product

json.dump(sections, open(out, 'w'), ensure_ascii=False)
kinds = {}
for s in sections:
    kinds[s['kind']] = kinds.get(s['kind'], 0) + 1
print(len(sections), 'sections', kinds, sum(len(s['params']) for s in sections), 'params')
