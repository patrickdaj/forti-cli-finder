#!/usr/bin/env python3
"""Pull `config ... end` examples out of a guide.

extract_outputs.py deliberately skips these -- a block of config commands is not sample
output -- but they are worth having for their own sake. Two reasons:

  1. The CLI Reference ships no examples for FortiOS at all.
  2. They are the only evidence of which fields actually get set. Nothing in the reference
     marks a field required, and FortiOS only complains at `end`; but across 346 of
     Fortinet's own `config firewall policy` examples, srcintf/dstintf/action/srcaddr/
     schedule/dstaddr/service appear in over 90%, which is the list every admin knows.

Fields are counted at the top level of the block only, so a `set name` inside a nested
`config` sub-table is not credited to the parent.

Output: [{t: table, x: [lines], pg: page, f: [fields set at the top level]}]
"""
import re, sys, json
from collections import Counter

src, out = sys.argv[1], sys.argv[2]
lines = open(src, encoding='utf-8', errors='replace').read().replace('\f', '').split('\n')


def learn_footer(ls):
    cand = re.compile(r'^\s*(Forti[A-Za-z]* [\d.]+ \S.*?)\s{2,}(\d+)\s*$')
    seen = Counter()
    for l in ls:
        m = cand.match(l)
        if m:
            seen[m.group(1).strip()] += 1
    if not seen:
        return None
    title, n = seen.most_common(1)[0]
    return re.compile(r'^\s*' + re.escape(title) + r'\s+(\d+)\s*$') if n >= 5 else None


FOOT = learn_footer(lines) or re.compile(r'(?!)')
clean, page = [], 0
for l in lines:
    m = FOOT.match(l)
    if m:
        page = int(m.group(1))
        continue
    if l.strip() == 'Fortinet Inc.':
        continue
    clean.append((page + 1, l))

CMD = re.compile(r'^(config|edit|set|unset|next|end|append|select|move|delete|purge|clone|rename|unselect)\b')
SET = re.compile(r'^set\s+(\S+)')

out_rows = []
i, N = 0, len(clean)
while i < N:
    pg, l = clean[i]
    if not l.strip() or (len(l) - len(l.lstrip())) < 5 or not l.strip().startswith('config '):
        i += 1
        continue
    # take the indented run and keep it only if every line is a config command
    block, j = [], i
    while j < N:
        p2, l2 = clean[j]
        if not l2.strip():
            k = j
            while k < N and not clean[k][1].strip():
                k += 1
            if k < N and (len(clean[k][1]) - len(clean[k][1].lstrip())) >= 5 and k - j <= 1:
                j = k
                continue
            break
        if (len(l2) - len(l2.lstrip())) < 5:
            break
        block.append(l2.strip())
        j += 1
    i = max(j, i + 1)
    if len(block) < 2 or not all(CMD.match(x) for x in block):
        continue
    # fields set at the top level of this table, not inside a nested config
    depth, fields = 0, []
    for x in block:
        if x.startswith('config '):
            depth += 1
        elif x == 'end':
            depth -= 1
        elif depth == 1:
            m = SET.match(x)
            if m:
                fields.append(m.group(1))
    if depth != 0:                      # unbalanced: the block ran off the page
        continue
    out_rows.append({'t': block[0][len('config '):].strip(), 'x': block, 'pg': pg,
                     'f': sorted(set(fields))})

json.dump(out_rows, open(out, 'w'), ensure_ascii=False, indent=0)
c = Counter(r['t'] for r in out_rows)
print(f'{len(out_rows)} config examples, {len(c)} tables; most: {c.most_common(3)}')
