#!/usr/bin/env python3
"""Parse hand-written Fortinet CLI references (FortiSwitchOS, FortiAnalyzer, FortiManager) from
pdftotext -layout output into the same section format as parse_fos.py.

Layout: unindented heading; indented prose; 'Syntax' then an indented command block (possibly several);
'Variable  Description [Default]' table; optional 'Example' blocks.
"""
import collections, re, sys, json

VERB = re.compile(r'^(config|execute|diagnose|get|show|set|unset|end|next|edit|exec|diag)\b')
# "Variables" as well as "Variable": 25 tables across FortiManager and FortiAnalyzer use
# the plural, and missing them dropped both their parameters and -- because the header
# then leaked into the syntax block and defeated its de-indent -- their commands.
TBL = re.compile(r'^(\s*)Variables?\s+Description(\s+Default)?\s*$')
SYN = re.compile(r'^\s*Syntax\s*$')
EXA = re.compile(r'^\s*Example[s]?( output)?\s*$')
SKIPHEAD = re.compile(r'^(https?://|Change log|Introduction|What|Using the Command|Appendix|Administrative Domains|Table of Contents|Contents)')



# ---------------------------------------------------------------- syntax -> path + args
#
# The single biggest defect in these three references was that we stored the whole first
# syntax line as the command path: `execute backup config flash <comment>` was the
# "command", so the page could neither name it nor offer `<comment>` as an argument.
# 401 of 1086 sections were in that state. The path is the leading run of LITERAL
# tokens; everything from the first notation token on is an argument, in order -- which
# is what the inspector already wanted, since it emits arguments positionally.

PAIRS = {'<': '>', '{': '}', '[': ']', '(': ')'}
NOTATION = re.compile(r'[<>{}\[\]|()]')


def tokens(s):
    """Whitespace split, but `{a | b}` and `<x y>` stay single tokens."""
    out, buf, stack = [], '', []
    for ch in s:
        if ch in PAIRS:
            stack.append(PAIRS[ch]); buf += ch
        elif stack and ch == stack[-1]:
            stack.pop(); buf += ch
        elif ch.isspace() and not stack:
            if buf:
                out.append(buf); buf = ''
        else:
            buf += ch
    if buf:
        out.append(buf)
    return out


def alternatives(tok):
    """The literal alternatives of `{a | b | c}`, or [] if it is not one.

    Only pure literals count: `{<address_ipv6> | <host-name_str>}` is one argument that
    takes either shape, not two commands.
    """
    if len(tok) < 3 or tok[0] not in '{[(' or tok[-1] != PAIRS[tok[0]]:
        return []
    inner = tok[1:-1]
    if '|' not in inner:
        return []
    alts = [a.strip() for a in inner.split('|')]
    if all(a and ' ' not in a and not NOTATION.search(a) for a in alts):
        return alts
    return []


def join_syntax(lines):
    """Rejoin a syntax statement that wrapped across lines.

    A long line wraps wherever it must, and a group left open at the end of one line
    continues on the next -- the real FortiAnalyzer line is

        config system locallog [disk | memory | fortianalyzer | syslogd
              | syslogd2 | syslogd3] filter

    which, read one line at a time, has an unterminated group and so lost both its
    choice and its trailing `filter`.
    """
    out = []
    for raw in lines:
        if not raw.strip():
            continue
        if out and _open_group(out[-1]):
            out[-1] = out[-1].rstrip() + ' ' + raw.strip()
        else:
            out.append(raw.rstrip())    # indent kept: it says nested vs sibling
    return out


def _open_group(s):
    """Is a bracket group still open at the end of this line?"""
    stack = []
    for ch in s:
        if ch in PAIRS:
            stack.append(PAIRS[ch])
        elif stack and ch == stack[-1]:
            stack.pop()
    return bool(stack)


def split_syntax(kind, rest):
    """A syntax line (minus its verb) -> [{path, args}], one per real command.

    Usually one. A MANDATORY choice followed by more literal tokens is the exception:
    `config log {syslogd | syslogd2 | syslogd3} filter` is three tables, and the path
    without the choice (`config log filter`) is not a command at all, so there is
    nothing to truncate it to. A choice at the end stays an argument -- `execute cli
    status-msg-only {enable | disable}` is one command taking a value, not two
    commands. An OPTIONAL group is never expanded: dropping `[ftp|scp|sftp]` would
    lose the fact that it may be left out entirely.
    """
    tk = tokens(rest)
    base = []
    for i, t in enumerate(tk):
        if not NOTATION.search(t):
            base.append(t)
            continue
        alts = alternatives(t)
        after = tk[i + 1:]
        if alts and after and not NOTATION.search(after[0]):
            # A choice with a literal token after it names real, separate commands,
            # and there is nothing to truncate the path to: `config log filter` is not
            # a table. An OPTIONAL choice also has the form with nothing chosen --
            # that is what the brackets mean -- so it yields one more.
            picks = list(alts) + ([''] if t[0] == '[' else [])
            out = []
            for a in picks:
                mid = base + ([a] if a else []) + after
                for sub in split_syntax(kind, ' '.join(mid)):
                    sub['exp'] = 1      # derived from a choice, not quoted verbatim
                    if sub not in out:
                        out.append(sub)
            return out
        return [{'path': ' '.join(base), 'args': tk[i:], 'exp': 0}]
    return [{'path': ' '.join(base), 'args': [], 'exp': 0}]


def merge_args(args, params):
    """Positional arguments first, in the order the syntax prints them.

    The Variable table is where the descriptions live, but its order is the order
    someone wrote the table in: across the three references it agreed with the syntax
    line for only 28 of 369 multi-argument commands. The inspector emits arguments
    positionally, so taking the table's order meant emitting `execute ping <count>
    <host>` -- right words, wrong command. Order comes from the syntax; the table is
    matched into it by name for the description, default and size it carries.
    """
    out, taken = [], set()
    for a in params_from_args(args):
        t = next((q for q in params
                  if q['key'] == a['key'] and id(q) not in taken), None)
        if t:
            taken.add(id(t))
            a = dict(t, name=a['name'], pos=1,
                     options=a['options'] or t.get('options') or [],
                     type=a['type'] or t.get('type') or '')
        out.append(a)
    # Rows the syntax line never mentioned are still documentation; they keep their
    # own order behind the positional ones.
    out += [q for q in params if id(q) not in taken]
    return out


def split_block(kind, syn, params, desc):
    """A syntax block -> one entry per command it actually documents.

    Two shapes, told apart by indentation. A non-config block lists SIBLINGS at the
    left margin -- the FortiManager block under "debug application" is 73 of them --
    and each has its own row in the Variable table, keyed by the token that
    distinguishes it. A config block's indented lines are the fields of the command
    above them, so they are never commands: splitting them would invent `config set
    router-id`.

    A sibling's description comes from its own row, which beats the family prose it
    used to share: "Set the debug level of the archd daemon" rather than "Use this
    command to view or set the debug levels for the FortiManager applications".
    """
    lines = join_syntax(syn)
    # Siblings sit at the FIRST statement's indentation, which is not always column
    # zero: one stray unindented line in the block defeats its de-indent, and then
    # every real command in it is indented.
    base = next((len(x) - len(x.lstrip()) for x in lines
                 if x.split()[:1] == [kind]), 0)
    stmts = [x.strip() for x in lines
             if x.split()[:1] == [kind] and len(x) - len(x.lstrip()) == base]
    if not stmts:
        return []
    # One statement cannot be a family. (Config is handled below regardless: its
    # siblings are tables whose fields the document does not attribute separately.)
    family = len(stmts) > 1
    out = []
    for st in stmts:
        rest = st[len(kind):].strip()
        if not rest:
            continue
        for v in split_syntax(kind, rest):
            if not v['path']:
                continue
            if kind == 'config':
                # fields, not arguments: every sibling table keeps the whole list,
                # since nothing in the document says which field belongs to which
                out.append(dict(v, desc=desc, params=params))
            elif not family:
                out.append(dict(v, desc=desc, params=merge_args(v['args'], params)))
            else:
                words = v['path'].split()
                own, mine = [], ''
                argkeys = {q['key'] for q in params_from_args(v['args'])}
                for q in params:
                    if q['key'] == words[-1]:
                        mine = q['desc']    # the row describes the command itself
                    elif q['key'] in argkeys:
                        own.append(q)       # the row describes one of its arguments
                out.append(dict(v, desc=mine or desc,
                                params=merge_args(v['args'], own)))
    return out


def dedupe(final):
    """One entry per command, keeping what each duplicate knew.

    Duplicates arise two ways. An optional choice expands to the form with nothing
    chosen, and the document sometimes gives that form its own section too -- there
    the document's own section is the better one, so a quoted entry beats a derived
    one. And some commands simply appear twice: FortiManager documents `config
    fmupdate fds-setting` in five places, with different fields in each, which is why
    this merges the fields instead of picking a winner and dropping four.
    """
    out, at = [], {}
    for s in final:
        key = (s['kind'], s['path'])
        if key not in at:
            at[key] = s
            out.append(s)
            continue
        keep = at[key]
        # a quoted command outranks one derived from a choice
        if keep.get('exp') and not s.get('exp'):
            out[out.index(keep)] = s
            s['params'] = _union(s['params'], keep['params'])
            s['examples'] = s['examples'] or keep['examples']
            s['desc'] = s['desc'] or keep['desc']
            at[key] = s
            continue
        keep['params'] = _union(keep['params'], s['params'])
        keep['examples'] = keep['examples'] or s['examples']
        keep['desc'] = keep['desc'] or s['desc']
    return out


def _union(a, b):
    """a, then whatever b adds that a does not already name."""
    seen = {q['key'] for q in a}
    return a + [q for q in b if q['key'] not in seen]


def nesting(syn):
    """field key -> the sub-table it sits in, once per occurrence, in syntax order.

    A config block states its nesting by indentation:

        config system csf
           set certificate <string>          <- the root table's
           config trusted-list
               edit <name>
                  set certificate <string>   <- a different field, same name

    The Variable table is supposed to say the same thing with a row named `config
    trusted-list`, and FortiManager and FortiAnalyzer frequently do not print one --
    so both fields landed in the root with different descriptions and nothing to tell
    them apart. The block always knows, so ask the block.

    One list per field name, because the whole point is the names that repeat: the Nth
    row with that name in the table is the Nth occurrence in the syntax.
    """
    out = collections.defaultdict(list)
    stack = []                      # [(indent, sub-table name)]
    for raw in syn:
        if not raw.strip():
            continue
        ind = len(raw) - len(raw.lstrip())
        w = raw.split()
        while stack and ind <= stack[-1][0]:
            stack.pop()
        if w[0] == 'config' and len(w) > 1:
            # the outermost config IS the command, so its fields have no sub-table
            stack.append((ind, '' if not stack else ' '.join(w[1:])))
        elif w[0] in ('set', 'unset', 'edit') and len(w) > 1:
            # `edit <id>` names the table's key, and a root table and a sub-table often
            # both have one -- so it needs attributing just as a field does
            out[keyof(w[1])].append(stack[-1][1] if stack else '')
    return out


def keyof(name):
    """The name a parameter is indexed by, computed the same way everywhere.

    A table row and a syntax argument are often the same thing written the same way --
    `{primary | secondary}` -- and when the two compute different keys they both
    survive the merge and the page lists the parameter twice.
    """
    n = (name or '').strip()
    if n[:1] in '<{[(':
        inner = re.sub(r'^[<{\[(]+|[>}\])]+$', '', n).strip()
        return re.split(r'[\s|]', inner, maxsplit=1)[0] or n
    return re.split(r'[\s(<{\[]', n, maxsplit=1)[0] or n


def params_from_args(args):
    """Positional arguments -> parameter rows, in the order the syntax prints them.

    `<parameter> .. <parameter>` is ONE argument you may repeat. Taken literally it
    became three, the middle one called `..`, which is not a thing you can type.
    """
    # collapse a repeat marker and the duplicate it sits between
    flat, i = [], 0
    while i < len(args):
        a = args[i]
        if a.strip(' .\u2026') == '' and flat:
            nxt = args[i + 1] if i + 1 < len(args) else None
            if nxt == flat[-1]:
                i += 2              # `<x> .. <x>` -> the one `<x>` already kept
            else:
                i += 1              # a stray marker: drop it, keep what follows
            flat[-1] = (flat[-1], True)
            continue
        flat.append(a)
        i += 1
    out = []
    for a in flat:
        a, rep = a if isinstance(a, tuple) else (a, False)
        key = keyof(a)
        row = {'table': '', 'name': a, 'desc': '', 'default': '', 'key': key,
               'type': '', 'size': '', 'options': [], 'pos': 1}
        if rep:
            row['elem'] = a        # build_bundles turns this into a list argument
        alts = alternatives(a)
        if alts:
            row['options'] = [{'v': v, 'desc': ''} for v in alts]
            row['type'] = 'option'
            row['key'] = key if not NOTATION.search(key) else alts[0]
        out.append(row)
    return out



# ---------------------------------------------------------------- selftest
def _selftest():
    """Real syntax lines from the three hand-written references."""
    cases = [
        # the common case: arguments baked into what we were storing as a path
        ('execute', 'backup config flash <comment>',
         [('backup config flash', ['<comment>'])]),
        ('execute', 'alias configure get <alias_name> <table-entry-id-if-needed>',
         [('alias configure get', ['<alias_name>', '<table-entry-id-if-needed>'])]),
        ('get', 'router info bfd neighbor [<BFD_local_IPv4_address>] [<BFD_peer_interface>]',
         [('router info bfd neighbor',
           ['[<BFD_local_IPv4_address>]', '[<BFD_peer_interface>]'])]),
        ('execute', 'batch [<cmd_cue>]', [('batch', ['[<cmd_cue>]'])]),
        # a mandatory choice is an argument, not a set of commands
        ('execute', 'cli status-msg-only {enable | disable}',
         [('cli status-msg-only', ['{enable | disable}'])]),
        ('get', 'switch qos (dot1p-map | ip-dscp-map | qos-policy)',
         [('switch qos', ['(dot1p-map | ip-dscp-map | qos-policy)'])]),
        ('execute', 'ping6 {<address_ipv6> | <host-name_str>}',
         [('ping6', ['{<address_ipv6> | <host-name_str>}'])]),
        # ... but a choice with literal tokens AFTER it names real, separate tables:
        # `config log syslogd filter` is a table and `config log filter` is not
        ('config', 'log {syslogd | syslogd2 | syslogd3} filter',
         [('log syslogd filter', []), ('log syslogd2 filter', []),
          ('log syslogd3 filter', [])]),
        ('config', 'system locallog {fortianalyzer | fortianalyzer2} setting',
         [('system locallog fortianalyzer setting', []),
          ('system locallog fortianalyzer2 setting', [])]),
        # optional alternatives are not expanded: dropping the brackets would lose the
        # fact that you may leave the whole thing out
        ('execute', 'fmpolicy upload-print-log [ftp|scp|sftp] <server> <port>',
         [('fmpolicy upload-print-log', ['[ftp|scp|sftp]', '<server>', '<port>'])]),
        # An OPTIONAL choice with a literal after it is every form, the omitted one
        # included. `config system locallog [disk | ... ] filter` is the real line, and
        # `config system locallog filter` is a real command -- the brackets say so.
        # Leaving it unexpanded would strand the literal `filter` in the argument list,
        # where the inspector would emit `config log disk` and stop.
        ('config', 'log [disk | memory] setting',
         [('log disk setting', []), ('log memory setting', []),
          ('log setting', [])]),
        # nothing to do
        ('get', 'system status', [('system status', [])]),
        ('execute', 'reboot', [('reboot', [])]),
    ]
    fails = []
    for kind, rest, want in cases:
        got = [(x['path'], x['args']) for x in split_syntax(kind, rest)]
        if got != want:
            fails.append(f'  {kind} {rest!r}\n      got  {got}\n      want {want}')
    # A syntax block often holds a whole FAMILY of commands, not one. The real
    # FortiManager block under the heading "debug application" lists 73 siblings, each
    # with its own row in the Variable table -- and we were shipping the first one and
    # hanging the other 72 rows off it as if they were its arguments.
    def row(key, name, desc):
        # keyed the way the parser keys a real table row, so the test exercises the
        # same path rather than a convenient fiction
        return {'table': '', 'name': name, 'desc': desc, 'default': '',
                'key': keyof(name), 'type': '', 'size': '', 'options': []}
    block = ['diagnose debug application alertmail <integer>',
             'diagnose debug application archd <integer>']
    rows = [row('alertmail', 'alertmail <integer>', 'Set the alert mail debug level'),
            row('archd', 'archd <integer>', 'Set the archd debug level')]
    got = split_block('diagnose', block, rows, 'family prose')
    want = [('debug application alertmail', 'Set the alert mail debug level',
             ['<integer>']),
            ('debug application archd', 'Set the archd debug level', ['<integer>'])]
    if [(g['path'], g['desc'], [q['name'] for q in g['params']]) for g in got] != want:
        fails.append('  family block not split per command:\n      got  '
                     + repr([(g['path'], g['desc'], [q['name'] for q in g['params']])
                             for g in got]) + f'\n      want {want}')

    # These documents write the table header both ways, and 25 tables across
    # FortiManager and FortiAnalyzer say "Variables". Missing them did not just lose a
    # heading: the header leaked into the syntax block, which defeated the block's
    # de-indent, which left every command in it indented -- and an indented command
    # reads as a nested field, so the whole section was dropped.
    for head in ('Variable          Description',
                 'Variables         Description',
                 '   Variable       Description       Default'):
        if not TBL.match(head):
            fails.append(f'  table header not recognised: {head!r}')

    # A block whose own indentation survived must still split: siblings are the
    # statements at the FIRST statement's indent, not at column zero.
    got3 = split_block('diagnose',
                       ['  diagnose debug application alertmail <integer>',
                        '  diagnose debug application archd <integer>'],
                       [], 'prose')
    if [g['path'] for g in got3] != ['debug application alertmail',
                                     'debug application archd']:
        fails.append(f'  indented block not split: {[g["path"] for g in got3]}')
    got4 = split_block('config', ['  config fmupdate service',
                                  '     set avips {enable | disable}'], [], 'prose')
    if [g['path'] for g in got4] != ['fmupdate service']:
        fails.append(f'  indented config block lost: {[g["path"] for g in got4]}')

    # Synthetic: no document in the corpus puts two sibling tables in one block, but
    # if one does, both are real tables and each keeps the fields -- dropping the
    # second would lose a command outright.
    got5 = split_block('config', ['config log syslogd', 'config log syslogd2',
                                  '   set status {enable | disable}'],
                       [row('status', 'status', 'enable it')], 'prose')
    if [(g['path'], [q['key'] for q in g['params']]) for g in got5] != [
            ('log syslogd', ['status']), ('log syslogd2', ['status'])]:
        fails.append(f'  sibling config tables: {[g["path"] for g in got5]}')

    # A config block is the opposite shape: one command, and the indented lines are its
    # fields. Splitting those into commands would invent `config set router-id`.
    cfg = ['config router ospf', '   set router-id <router_ipv4>',
           '   config area', '      set id <id>']
    got2 = split_block('config', cfg, [row('router-id', 'router-id', 'the id')],
                       'ospf prose')
    if [g['path'] for g in got2] != ['router ospf']:
        fails.append(f'  config block should stay one command: {[g["path"] for g in got2]}')

    # A syntax line wraps when it is long, and the real FortiAnalyzer line below put
    # half its alternatives on the next line -- which left the group unterminated, so
    # the path was truncated to `config system locallog` and the choice was lost.
    joined = join_syntax([
        'config system locallog [disk | memory | fortianalyzer | syslogd',
        '      | syslogd2 | syslogd3] filter',
        'set controller {enable | disable}'])
    if joined != ['config system locallog [disk | memory | fortianalyzer | syslogd '
                  '| syslogd2 | syslogd3] filter', 'set controller {enable | disable}']:
        fails.append(f'  wrapped syntax not joined: {joined}')

    # `<parameter> .. <parameter>` is one argument you may repeat, not three arguments
    # the middle of which is called `..`. The schema already has a list argument, so
    # say it that way.
    rep = params_from_args(['<parameter>', '..', '<parameter>'])
    if [q['name'] for q in rep] != ['<parameter>'] or not rep[0].get('elem'):
        fails.append(f'  a repeated argument should collapse to one list: '
                     f'{[(q["name"], q.get("elem")) for q in rep]}')

    # A nested table's fields must not land beside the root's. The syntax block states
    # the nesting by indentation; the FortiManager and FortiAnalyzer Variable tables
    # often omit the `config <name>` row that would say it, which is why `config system
    # csf` listed `certificate <string>` twice with different descriptions and no way
    # to tell them apart.
    csf = ['config system csf',
           '   set accept-auth-by-cert {enable | disable}',
           '   set certificate <string>',
           '   config trusted-list',
           '       edit <name>',
           '          set action {accept | deny}',
           '          set certificate <string>']
    nest = nesting(csf)
    if nest.get('certificate') != ['', 'trusted-list']:
        fails.append(f'  nesting wrong for a field in both tables: '
                     f'{nest.get("certificate")}')
    if nest.get('accept-auth-by-cert') != ['']:
        fails.append(f'  a root field should have no sub-table: '
                     f'{nest.get("accept-auth-by-cert")}')
    if nest.get('action') != ['trusted-list']:
        fails.append(f'  a nested-only field: {nest.get("action")}')

    if nesting(csf + ['   config sub', '       edit <id>']).get('id') != ['sub']:
        fails.append('  an edit mkey is not attributed to its table: '
                     + repr(nesting(csf + ['   config sub', '       edit <id>'])))

    # A table row and a syntax argument written identically must merge into ONE
    # parameter. `execute bootimage {primary | secondary}` has the choice in its syntax
    # AND as a row in its table; keying them differently listed it twice on the page.
    one = merge_args(['{primary | secondary}'],
                     [row('{primary | secondary}', '{primary | secondary}',
                          'Select the partition to boot from.')])
    if len(one) != 1 or one[0]['desc'] != 'Select the partition to boot from.':
        fails.append(f'  identical row and argument not merged: '
                     f'{[(q["name"], q["desc"]) for q in one]}')

    # One command, documented twice: an optional choice expands to the form with
    # nothing chosen, and sometimes the document also gives that form its own section.
    # And FortiManager's `config fmupdate fds-setting` has five sections under one
    # path, carrying different fields between them -- we were shipping five identical
    # looking entries, and keeping just one would have dropped the others' fields.
    def sec(path, params, exp=0, page=1, desc='', ex=None):
        return {'kind': 'config', 'path': path, 'params': params, 'exp': exp,
                'page': page, 'desc': desc, 'examples': ex or [], 'syntax': [],
                'notes': [], 'product': 'x'}
    merged = dedupe([
        sec('fmupdate fds-setting', [row('a', 'a', 'A')], page=5, desc='first'),
        sec('fmupdate fds-setting', [row('b', 'b', 'B')], page=9, desc=''),
        sec('system locallog setting', [row('c', 'c', 'C')], exp=1),
        sec('system locallog setting', [row('c', 'c', 'C')], exp=0, desc='quoted'),
    ])
    if len(merged) != 2:
        fails.append(f'  duplicates not merged: {[m["path"] for m in merged]}')
    else:
        f1 = next(m for m in merged if m['path'] == 'fmupdate fds-setting')
        if [q['key'] for q in f1['params']] != ['a', 'b']:
            fails.append(f'  fields lost when merging: {[q["key"] for q in f1["params"]]}')
        if f1['desc'] != 'first':
            fails.append(f'  description lost when merging: {f1["desc"]!r}')
        f2 = next(m for m in merged if m['path'] == 'system locallog setting')
        if f2['exp'] or f2['desc'] != 'quoted':
            fails.append('  a quoted command should win over a derived duplicate')

    # options come off a choice argument so the inspector can offer them
    p = params_from_args(['{enable | disable}'])[0]
    if [o['v'] for o in p['options']] != ['enable', 'disable']:
        fails.append(f'  options not read off a choice: {p}')
    if p['type'] != 'option':
        fails.append(f'  a choice should be type option, got {p["type"]!r}')
    q = params_from_args(['<comment>'])[0]
    if q['key'] != 'comment' or q['name'] != '<comment>':
        fails.append(f'  placeholder key/name wrong: {q}')
    if fails:
        print('FAIL\n' + '\n'.join(fails))
        return 1
    print(f'selftest OK  ({len(cases)} syntax lines)')
    return 0


if '--selftest' in sys.argv:
    sys.exit(_selftest())


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
    elif mode == 'note':
        # prose that followed a table: about the command, but not its description
        if l.strip():
            if cur['notes'] and not unclosed(cur['notes'][-1]) \
                    and cur['notes'][-1][-1:] not in '.:':
                cur['notes'][-1] += ' ' + l.strip()     # a sentence that wrapped
            else:
                cur['notes'].append(l.strip())
    elif mode == 'table':
        if l.strip() == '':
            idx += 1; continue
        pstart, dstart = cols[0][1], cols[1][1]
        if len(l) - len(l.lstrip()) < pstart:
            # Indented LESS than the table's own name column, so it cannot be a row:
            # the table ended and prose resumed. Slicing it at the name column anyway
            # is how `If you do not specify primary or secondary...` became a parameter
            # called `f you do not specify primary or sec` -- junk, and missing its
            # first letter. It is a note about the command, so keep it as one.
            mode = 'note'
            cur['notes'].append(l.strip())
            idx += 1
            continue
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
    # path and kind from the first syntax STATEMENT, else from the heading. A statement,
    # not a line: a long one wraps, and reading only the first line truncates the
    # command at whatever column the PDF broke it on.
    stmts = join_syntax(syn)
    # stripped: the block's de-indent only removes the indent COMMON to every line, so
    # one stray shallow line leaves every command indented -- and VERB is anchored, so
    # an indented `config ...` matched nothing and the whole section was discarded.
    first = stmts[0].strip() if stmts else ''
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
    s['_rest'] = s['path']      # the full line; split into path + arguments below
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
        if p['name'].strip(' .\u2026') == '':
            continue        # a literal `...` row: the table saying "and so on"

        m = re.match(r'^config\s+(\S.*)$', p['name'].strip())
        if m and len(m.group(1).split()) <= 4:
            table = m.group(1).strip().rstrip('.')
            continue
        p['table'] = p.get('table') or table
        kept.append(p)
    s['params'] = kept
    # The `config <name>` rows above gave us what the table says; the syntax block says
    # it more reliably, so let it correct the attribution where it knows the field.
    nest = nesting(s['syntax'])
    seen_key = collections.Counter()
    for p in s['params']:
        occ = nest.get(keyof(p['name']))
        if occ:
            i = seen_key[keyof(p['name'])]
            if i < len(occ):
                p['table'] = occ[i]
            seen_key[keyof(p['name'])] += 1
    for p in s['params']:
        p.pop('_wrap', None)
        p['key'] = keyof(p['name'])
        p['type'] = ''; p['size'] = ''; p['options'] = []
        # options embedded in the name: foo {a | b}
        mo = re.search(r'\{([^}]*)\}', p['name'])
        if mo and '|' in mo.group(1):
            p['options'] = [{'v': v.strip(), 'desc': ''} for v in mo.group(1).split('|')]
            p['type'] = 'option'
    s.pop('head', None)
    rest = s.pop('_rest', s['path'])
    entries = split_block(s['kind'], s['syntax'], s['params'], s['desc'])
    if not entries:
        # no usable syntax block: fall back to the path the heading gave us
        entries = [dict(v, desc=s['desc'],
                        params=s['params'] if s['kind'] == 'config'
                        else merge_args(v['args'], s['params']))
                   for v in split_syntax(s['kind'], rest)]
    for ix, v in enumerate(entries):
        if not v['path']:
            continue        # nothing literal to name it by -- drop rather than invent
        # The examples were written under the family heading, so they illustrate the
        # family. Repeating them on all 73 siblings would claim each was written for
        # that command; they stay with the first.
        final.append(dict(s, path=v['path'], desc=v['desc'], params=v['params'],
                          exp=v.get('exp', 0),
                          examples=s['examples'] if ix == 0 else []))

final = dedupe(final)

# Every command must be IN the document. The only commands we are entitled to derive
# are the alternatives of a documented choice -- `config log {syslogd | syslogd2}
# filter` really is two tables -- and those are marked. Anything else that is not
# quoted verbatim is a parser bug inventing commands, which is the one failure this
# reference must not have.
flat = re.sub(r'\s+', ' ', text)
invented = [f"{x['kind']} {x['path']}" for x in final if not x.get('exp')
            if not re.search(re.escape(re.sub(r'\s+', ' ',
                                              f"{x['kind']} {x['path']}").strip())
                             + r'(?=[\s<{\[(]|$)', flat)]
derived = sum(1 for x in final if x.get('exp'))
if invented:
    print(f'FAIL {len(invented)} commands are in neither the document nor a documented '
          f'choice -- the parser invented them:', file=sys.stderr)
    for x in invented[:15]:
        print(f'   {x}', file=sys.stderr)
    sys.exit(1)

json.dump(final, open(out, 'w'), ensure_ascii=False)
kinds = {}
for s in final:
    kinds[s['kind']] = kinds.get(s['kind'], 0) + 1
print(len(final), 'sections', kinds, sum(len(s['params']) for s in final), 'params',
      sum(len(s['examples']) for s in final), 'examples;',
      len(final) - derived, 'quoted verbatim,', derived,
      'derived from a documented choice')

