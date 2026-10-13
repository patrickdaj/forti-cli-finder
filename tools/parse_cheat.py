#!/usr/bin/env python3
"""Mine Fortinet's CLI troubleshooting cheat sheets into an overlay.

Six pages per sheet, two columns of `command | description`, and between them they carry
two things the generated CLI Reference does not: arguments for commands it prints bare
(`diagnose sys top {s} {n} {i}`) and a handful of commands it never lists at all.

Two things make this harder than it looks.

A naive `pdftotext -layout` interleaves the two columns into nonsense. Cropping each
column separately fixes it completely:  -x 0 -W 306  and  -x 306 -W 306.

And the rows are EXAMPLES, not syntax. `diagnose sys kill 11 <pid>` has a literal signal
number where the reference would write `<signal>`; `diagnose debug duration 0` has a
literal 0. Taking those as command paths would invent commands that do not exist, so a
path containing a bare number is never treated as one -- the row still contributes its
description to the command it is an example of.

  python3 tools/parse_cheat.py            # report, then write cheat-overlay.json
  python3 tools/parse_cheat.py --report    # report only

Output is the same shape as device-overlay.json, so the same applier folds it in.
"""
import json, os, re, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.environ.get('OUT', 'site/data')
WORK = os.environ.get('WORK', 'work')
OVERLAY = os.path.join(ROOT, 'cheat-overlay.json')

ROW = re.compile(r'^\s*(diagnose|diag|execute|exec|get|config|show)\s+(\S.*?)\s{2,}(\S.*)$')
CONT = re.compile(r'^\s{20,}(\S.*)$')          # a description wrapping to the next line
PLACEHOLDER = re.compile(r'^[<{].*[>}]$')
# a bare number, negative included: `diagnose debug application authd -1`
# has a debug LEVEL where syntax would have a placeholder
LITERAL = re.compile(r'^-?\d+$')
# A command cut off at the column edge: the 306pt crop turns `link-monitor` into
# `link-`, so a path token ending in a hyphen is truncated, not a real command.
TRUNCATED = re.compile(r'-$')
VERB = {'diag': 'diagnose', 'exec': 'execute'}


def columns(pdf, dest):
    """Crop each column separately; -layout alone interleaves them into nonsense."""
    parts = []
    for x in (0, 306):
        out = f'{dest}.{x}.txt'
        subprocess.run(['pdftotext', '-layout', '-x', str(x), '-y', '40',
                        '-W', '306', '-H', '720', pdf, out], check=True)
        parts.append(open(out, encoding='utf-8', errors='replace').read())
    return '\n'.join(parts)


def rows(text):
    """(verb, command, description), with wrapped descriptions joined."""
    out = []
    for line in text.split('\n'):
        m = ROW.match(line.rstrip())
        if m:
            out.append([VERB.get(m.group(1), m.group(1)), m.group(2).strip(),
                        m.group(3).strip()])
            continue
        c = CONT.match(line.rstrip())
        if c and out:
            out[-1][2] = (out[-1][2] + ' ' + c.group(1).strip()).strip()
    return out


def facts(text, src):
    """Rows -> facts, skipping the ones that are examples rather than syntax."""
    out, skipped = {}, []
    for verb, cmd, desc in rows(text):
        toks = cmd.split()
        path = [t for t in toks if not PLACEHOLDER.match(t)]
        args = [t for t in toks if PLACEHOLDER.match(t)]
        if any(LITERAL.match(t) for t in path) or any(TRUNCATED.search(t) for t in path):
            # an example with a literal value where syntax would have a placeholder,
            # or a command the column crop cut in half
            skipped.append(f'{verb} {cmd}')
            continue
        if not path:
            continue
        key = (verb, ' '.join(path))
        old = out.get(key)
        if not old or len(args) > len(old['x']):
            out[key] = {'k': verb, 'p': key[1], 'd': desc, 'src': src,
                        'x': [{'n': a, 'k': a, 'd': ''} for a in args]}
    return out, skipped


def collect():
    cfg = json.load(open(os.path.join(ROOT, 'sources.json')))
    lock = json.load(open(os.path.join(ROOT, 'sources.lock.json')))['documents']
    per_bundle, skipped = {}, []
    for e in cfg.get('cheat', []):
        pdf = os.path.join(ROOT, 'sources', e['key'] + '.pdf')
        if not os.path.exists(pdf):
            print(f"  {e['key']}: not downloaded -- run make fetch")
            continue
        d = os.path.join(ROOT, WORK, e['key'])
        os.makedirs(d, exist_ok=True)
        text = columns(pdf, os.path.join(d, 'text'))
        f, sk = facts(text, e['title'])
        skipped += sk
        print(f"  {e['key']:10s} {len(rows(text)):4d} rows -> {len(f):4d} commands"
              f"   ({len(sk)} skipped as examples)")
        for b in e['target']:
            dest = per_bundle.setdefault(b, {})
            for k, v in f.items():
                if k not in dest or len(v['x']) > len(dest[k]['x']):
                    dest[k] = v
    return per_bundle, skipped


def only_known(per_bundle):
    """Keep facts whose command the bundle already documents.

    The sheets are reliable for arguments and descriptions on commands we know, and
    unreliable for naming commands nothing else lists: the column crop truncates long
    paths, and the rows use abbreviations (`diagnose debug app`) where the reference
    writes them out. Filling is safe; inventing is not, so by default we only fill.
    """
    kept = {}
    for b, d in per_bundle.items():
        path = os.path.join(ROOT, OUT, f'{b}.json')
        if not os.path.exists(path):
            continue
        have = {(s['k'], s['p']) for s in json.load(open(path))['secs']}
        kept[b] = {k: v for k, v in d.items() if k in have}
    return kept


def report(per_bundle):
    for b, d in sorted(per_bundle.items()):
        path = os.path.join(ROOT, OUT, f'{b}.json')
        if not os.path.exists(path):
            continue
        bun = json.load(open(path))
        have = {(s['k'], s['p']): s for s in bun['secs']}
        new = [f for k, f in d.items() if k not in have]
        fill = [f for k, f in d.items()
                if k in have and f['x'] and not have[k].get('x')]
        desc = [f for k, f in d.items()
                if k in have and f['d'] and not (have[k].get('d') or '').strip()]
        print(f'\n=== {b}')
        print(f'  commands the bundle lacks {len(new)}   bare commands we could fill '
              f'{len(fill)}   descriptions we could add {len(desc)}')
        for f in sorted(fill, key=lambda f: f['p'])[:6]:
            print(f"      > {f['k']} {f['p']}  {' '.join(x['n'] for x in f['x'])}")
        for f in sorted(new, key=lambda f: f['p'])[:6]:
            print(f"      + {f['k']} {f['p']}  {' '.join(x['n'] for x in f['x'])}")


def main():
    per_bundle, skipped = collect()
    if not per_bundle:
        return 1
    if '--add-new' not in sys.argv:
        before = sum(len(v) for v in per_bundle.values())
        per_bundle = only_known(per_bundle)
        after = sum(len(v) for v in per_bundle.values())
        print(f'  keeping {after} of {before} facts: commands the bundle already '
              f'documents (pass --add-new to let the sheets name commands too)')
    report(per_bundle)
    if '--report' in sys.argv:
        return 0
    doc = {'_comment': [
        'Commands and arguments mined from the CLI troubleshooting cheat sheets.',
        'Written by tools/parse_cheat.py. Regenerate rather than hand-edit.',
        'Rows on those sheets are examples, not syntax, so any whose path carried a',
        'literal value was skipped rather than invented into a command.'],
        'skipped_as_examples': sorted(set(skipped)),
        'facts': {b: [dict(v) for _, v in sorted(d.items())]
                  for b, d in sorted(per_bundle.items())}}
    json.dump(doc, open(OVERLAY, 'w'), ensure_ascii=False, indent=1)
    open(OVERLAY, 'a').write('\n')
    print(f'\n  wrote cheat-overlay.json: '
          f'{sum(len(v) for v in doc["facts"].values())} facts, '
          f'{len(doc["skipped_as_examples"])} skipped as examples')
    return 0


if __name__ == '__main__':
    sys.exit(main())
