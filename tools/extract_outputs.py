#!/usr/bin/env python3
"""Extract CLI command + output samples from the FortiOS Administration Guide (pdftotext -layout).

A sample = a prompt line ('# diagnose ...', 'FGT (root) # get ...') inside an indented code block,
followed by its output lines up to the next prompt or the end of the block.
Output: list of {cmd, out, cap, pg, sect}
"""
import re, sys, json
from collections import Counter

src, out = sys.argv[1], sys.argv[2]
lines = open(src, encoding='utf-8', errors='replace').read().replace('\f', '').split('\n')

# Page footers are "<Product> <version> <Guide title>   <page>" but the title differs per
# document, so learn it instead of hard-coding one: the prefix that repeats most often on
# lines ending in a page number is the footer.
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
    if n < 5:            # not a running footer, just a stray table row
        return None
    return re.compile(r'^\s*' + re.escape(title) + r'\s+(\d+)\s*$')

FOOT = learn_footer(lines)
if FOOT is None:
    sys.stderr.write('  no repeating page footer found in %s; page numbers will be 0\n' % src)
    FOOT = re.compile(r'(?!)')   # never matches

# strip footers + running heads; remember the page of each kept line
clean = []
page = 0
i, n = 0, len(lines)
while i < n:
    l = lines[i]
    m = FOOT.match(l)
    if m:
        page = int(m.group(1)); i += 1
        if i < n and lines[i].strip() == 'Fortinet Inc.':
            i += 1
            j = i
            while j < n and lines[j].strip() == '':
                j += 1
            if j < n and lines[j] and not lines[j].startswith(' ') and len(lines[j].split()) <= 6:
                i = j + 1   # running head (chapter name)
        continue
    clean.append((page + 1, l))
    i += 1

VERBS = r'(get|show|diagnose|diag|execute|exec|fnsysctl)'
PROMPT = re.compile(r'^\s*(?:[A-Za-z0-9_.\-]+(?:\s*\([A-Za-z0-9_.\- ]+\))*\s*)?#\s*' + VERBS + r'\b(.*)$')
HEAD = re.compile(r'^[A-Z][^\s].*$')  # unindented heading

def indent(l):
    return len(l) - len(l.lstrip())

samples = []
cur_sect = ''
last_prose = []   # recent prose lines (indent <= 4)
k = 0
N = len(clean)
while k < N:
    pg, l = clean[k]
    if l.strip() == '':
        k += 1; continue
    ind = indent(l)
    if ind == 0 and HEAD.match(l):
        cur_sect = l.strip(); last_prose = []; k += 1; continue
    if ind <= 4:
        last_prose.append(l.strip()); last_prose = last_prose[-10:]; k += 1; continue
    # code block: collect lines with indent >= 5, allowing single blank lines inside
    block = []
    while k < N:
        pg2, l2 = clean[k]
        if l2.strip() == '':
            # look ahead: block continues if the next non-blank line is still indented >= 5 within 2 blanks
            j = k; blanks = 0
            while j < N and clean[j][1].strip() == '':
                j += 1; blanks += 1
            if j < N and indent(clean[j][1]) >= 5 and blanks <= 2:
                block.append((pg2, ''))
                k += 1; continue
            break
        if indent(l2) < 5:
            break
        block.append((pg2, l2))
        k += 1
    # split the block on prompt lines
    seg = None
    # join wrapped prose into sentences, then pick the best caption
    sents = []
    for lp in last_prose:
        if sents and not re.match(r'^(\d+\.|l\s|To\s|[A-Z])', lp) :
            sents[-1] += ' ' + lp
        else:
            sents.append(re.sub(r'^(\d+\.|l)\s+', '', lp))
    colon = [x for x in sents if x.rstrip().endswith(':')]
    to = [x for x in colon if re.match(r'^(To|Verify|Check|View|Display)\b', x)]
    generic = lambda x: re.match(r'^(In the CLI|Run|Enter|Use|Type|For example|The output|Output|Sample output|Example)\b', x, re.I)
    cap = ''
    if colon:
        cap = colon[-1]
        if generic(cap) and to: cap = to[-1] + ' ' + cap if False else to[-1]
    elif sents:
        cap = sents[-1]
    cap = cap.strip()[:220]
    base = min((indent(b) for _, b in block if b.strip()), default=5)
    for pgb, b in block:
        mp = PROMPT.match(b)
        if mp:
            if seg: samples.append(seg)
            verb = mp.group(1)
            verb = {'diag': 'diagnose', 'exec': 'execute'}.get(verb, verb)
            seg = {'cmd': (verb + ' ' + mp.group(2).strip()).strip(), 'out': [], 'cap': cap, 'pg': pgb, 'sect': cur_sect, '_ind': indent(b), '_done': False}
            continue
        if seg is not None and not seg['_done'] and b.strip() and (indent(b) < seg['_ind'] - 1 or re.match(r'^\s*l\s{2,}\S', b) or re.match(r'^\s*\d+\.\s+[A-Z]', b)):
            seg['_done'] = True   # prose list item, not output
        if seg is not None and not seg['_done']:
            # a following command typed without output after a prompt-less line (e.g. 'config ...') ends the segment
            seg['out'].append(b[base:] if len(b) >= base else b.strip())
    if seg: samples.append(seg)
    last_prose = []

# keep samples with real output
kept = []
for s in samples:
    o = s['out']
    while o and not o[-1].strip(): o.pop()
    while o and not o[0].strip(): o.pop(0)
    body = [x for x in o if x.strip() and x.strip() != '...']
    if len(body) < 1:
        continue
    # output that is only more config commands is not output
    if all(re.match(r'^\s*(config|edit|set|unset|next|end|append|select)\b', x) for x in body):
        continue
    mi = min((len(x)-len(x.lstrip()) for x in o if x.strip()), default=0)
    o = [x[mi:] if x.strip() else '' for x in o]
    s['out'] = '\n'.join(o); s.pop('_ind', None); s.pop('_done', None)
    kept.append(s)

json.dump(kept, open(out, 'w'), ensure_ascii=False, indent=0)
from collections import Counter
c = Counter(s['cmd'].split()[0] for s in kept)
print(len(samples), 'prompt segments;', len(kept), 'with output;', dict(c))
print('distinct commands', len(set(s['cmd'] for s in kept)))
