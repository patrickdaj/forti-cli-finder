#!/usr/bin/env python3
"""Capture a Fortinet device's own command tree and `?` help, over SSH.

The PDFs give prose, defaults and sample output; a device gives the things no document
has -- the arguments of the 3104 commands the reference prints bare, the `get` tree the
reference omits entirely, and whether each argument is optional. This collects the
second half. tools/parse_tree.py reads what it writes.

    cp .env.devices.example .env.devices     # then edit it; it is gitignored
    chmod 600 .env.devices
    python3 tools/capture_device.py                  # every device in the file
    python3 tools/capture_device.py fgt1             # just one
    python3 tools/capture_device.py fgt1 --probe-all # ? every bare command, not a sample
    python3 tools/capture_device.py fgt1 --config-walk  # also field help (enters config)
    python3 tools/capture_device.py fgt1 --crawl get    # walk ? down the get tree (long)

What it runs: `get system status`, `tree`, and `<command> ?` for commands we ship with no
arguments. All reads. It never enters `config` mode, so it works against an account with
`cli-config disable` -- which is the point: the device enforces read-only, not this
script. Field-level help for config tables would need config mode and is deliberately
not here.

What it writes: work/live/<product>-<ver>-<build>/ -- gitignored, because a status banner
carries a serial number and a hostname. Only model, firmware and build are ever recorded,
by `parse_tree.py --record` into captures.json.

Credentials: .env.devices, which must not be group- or world-readable. Prefer a key --
set <NAME>_KEY to a private key path, or leave both unset to use your ssh-agent. A
password in <NAME>_PASS is supported because labs are labs; it is passed to the device's
own prompt over the pty and never appears in a file, a log or an argument list.
"""
import os, pty, re, select, sys, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV = os.path.join(ROOT, '.env.devices')
LIVE = os.path.join(ROOT, 'work/live')

# Reads only. `tree` prints the command tree; the rest identify the build.
# `tree` exists on FortiOS only -- FortiSwitch answers "Unknown action 0" and
# FortiManager/FortiAnalyzer return a one-line stub. The `?` crawl works on all of them,
# which is why it, not the tree, is the general mechanism.
SAFE = {
    'fgt': ['get system status', 'tree'],
    'fsw': ['get system status'],
    'faz': ['get system status'],
    'fmg': ['get system status'],
}
KIND_PRODUCT = {'fgt': 'fortios', 'fsw': 'fortiswitch',
                'faz': 'fortianalyzer', 'fmg': 'fortimanager'}

PROMPT = re.compile(rb'(?:^|\r?\n)[\w.\-]+(?:\s+\([\w.\-]+\))?\s*[#$]\s*$')
PAGER = re.compile(rb'--More--|\(END\)', re.I)
PASSWD = re.compile(rb"password:\s*$", re.I)
import importlib.util as _il
_sp = _il.spec_from_file_location('parse_tree', os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'parse_tree.py'))
_pt = _il.module_from_spec(_sp)
_sp.loader.exec_module(_pt)
identify = _pt.identify       # this writes what parse_tree.py reads; one definition only
BAD = re.compile(r'command parse error|unknown action|Command fail|Unknown action', re.I)


# ---------------------------------------------------------------- the device file

def load_env(path=ENV):
    """Parse .env.devices into {name: {host, kind, user, pass, key}}.

    Plain dotenv so a shell can source it too:  DEVICES=fgt1,fsw1  then FGT1_HOST=...
    """
    if not os.path.exists(path):
        raise SystemExit(f'no {os.path.relpath(path, ROOT)} -- copy .env.devices.example '
                         f'to it and fill it in (it is gitignored)')
    mode = os.stat(path).st_mode & 0o077
    if mode:
        raise SystemExit(f'{os.path.relpath(path, ROOT)} is readable by others '
                         f'(mode {oct(os.stat(path).st_mode & 0o777)}). '
                         f'chmod 600 it before this will run.')
    env = {}
    for line in open(path):
        line = line.split('#', 1)[0].strip()
        if '=' in line:
            k, v = line.split('=', 1)
            env[k.strip().upper()] = v.strip().strip('"\'')

    names = [n.strip() for n in env.get('DEVICES', '').split(',') if n.strip()]
    if not names:
        raise SystemExit('set DEVICES=<name>[,<name>...] in .env.devices')
    out = {}
    for n in names:
        p = n.upper()
        d = {'name': n, 'host': env.get(f'{p}_HOST'), 'kind': (env.get(f'{p}_KIND') or 'fgt').lower(),
             'user': env.get(f'{p}_USER') or 'admin',
             'pass': env.get(f'{p}_PASS'), 'key': env.get(f'{p}_KEY')}
        if not d['host']:
            raise SystemExit(f'{n}: set {p}_HOST')
        if d['kind'] not in SAFE:
            raise SystemExit(f'{n}: {p}_KIND must be one of {", ".join(SAFE)}')
        out[n] = d
    return out


# ---------------------------------------------------------------- the session

class Session:
    """An ssh session on a pty.

    A pty, not a pipe: FortiOS acts on `?` the moment it is typed, with no newline, and
    only does so for a terminal. The system ssh binary does the protocol -- adding
    paramiko would be this project's first runtime dependency and it does not need one.
    """

    def __init__(self, dev, verbose=False):
        self.dev, self.verbose, self.buf = dev, verbose, b''
        self.method = None      # the `?` spelling this device answered to
        argv = ['ssh', '-tt', '-o', 'StrictHostKeyChecking=accept-new',
                '-o', 'NumberOfPasswordPrompts=1',
                # FortiOS ships older kex/cipher/key sets on some builds; a modern
                # OpenSSH refuses the handshake outright without these.
                '-o', 'KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1',
                '-o', 'HostKeyAlgorithms=+ssh-rsa',
                '-o', 'PubkeyAcceptedAlgorithms=+ssh-rsa',
                '-o', 'Ciphers=+aes128-cbc,aes256-cbc']
        if dev.get('key'):
            argv += ['-o', 'IdentitiesOnly=yes', '-i', os.path.expanduser(dev['key'])]
        argv.append(f"{dev['user']}@{dev['host']}")
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.execvp('ssh', argv)
            os._exit(1)

    def read(self, idle=0.6, timeout=40.0, until=None):
        start = last = time.time()
        while time.time() - start < timeout:
            r, _, _ = select.select([self.fd], [], [], 0.1)
            if r:
                try:
                    chunk = os.read(self.fd, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                self.buf += chunk
                last = time.time()
                if self.verbose:
                    sys.stdout.write(chunk.decode('utf-8', 'replace'))
                    sys.stdout.flush()
                if PASSWD.search(self.buf.replace(b'\r', b'')[-40:]):
                    if not self.dev.get('pass'):
                        raise SystemExit(f"{self.dev['name']}: the device asked for a "
                                         f"password; set {self.dev['name'].upper()}_PASS "
                                         f"or {self.dev['name'].upper()}_KEY")
                    # straight to the device's own prompt: never logged, never an argv
                    os.write(self.fd, self.dev['pass'].encode() + b'\r')
                    self.buf = b''
                    continue
                if PAGER.search(chunk):
                    os.write(self.fd, b' ')
                    continue
                if until and until.search(self.buf):
                    return self.buf
            elif time.time() - last > idle:
                return self.buf
        return self.buf

    def run(self, cmd, idle=1.0, timeout=180.0):
        self.buf = b''
        os.write(self.fd, cmd.encode() + b'\r')
        return clean(self.read(idle=idle, timeout=timeout).decode('utf-8', 'replace'), cmd)

    def ask(self, cmd):
        """`<cmd> ?` -- help without running anything. Returns (method, text).

        FortiOS answers `?` on the keystroke, so nothing is executed. Whether that
        survives an ssh pty is the one thing about this script that cannot be known
        without a device, so it tries both spellings and reports which answered.
        """
        tries = (('space-q', cmd + ' ?'), ('bare-q', cmd + '?'))
        if self.method:                 # it answered once; stop paying for the other
            tries = [t for t in tries if t[0] == self.method]
        for method, payload in tries:
            self.buf = b''
            os.write(self.fd, payload.encode())
            time.sleep(0.35)
            out = clean(self.read(idle=0.7, timeout=20).decode('utf-8', 'replace'), payload)
            os.write(self.fd, b'\x15')          # ctrl-U: clear the line, run nothing
            self.read(idle=0.25, timeout=3)
            if useful(out):
                self.method = method
                return method, out
        return None, ''

    def close(self):
        for fn in (lambda: os.write(self.fd, b'exit\r'), lambda: os.close(self.fd)):
            try:
                fn()
            except OSError:
                pass


def clean(raw, cmd):
    raw = re.sub(r'\x1b\[[0-9;?]*[a-zA-Z]', '', raw)
    raw = re.sub(r'\x1b[()][AB012]', '', raw)
    raw = raw.replace('\r\n', '\n').replace('\r', '\n')
    raw = re.sub(r'--More--\s*', '', raw)
    raw = re.sub(r'\x08+ *', '', raw)
    lines = raw.split('\n')
    if lines and cmd.strip() and cmd.strip() in lines[0]:
        lines = lines[1:]
    # after a ctrl-U the device redraws "host # <the command>"; drop that tail
    while lines and (PROMPT.search(lines[-1].encode())
                     or re.match(r'^[\w.\-]+\s*(\([\w.\-]+\))?\s*[#$]\s', lines[-1])):
        lines = lines[:-1]
    return '\n'.join(lines).strip('\n')


def useful(out):
    """Did `?` produce a help listing rather than an error or an empty redraw?"""
    if not out or len(out) < 12 or BAD.search(out):
        return False
    return bool(re.search(r'^\s*\S+\s{2,}\S', out, re.M) or re.search(r'[<{][^>}]+[>}]', out))


# ---------------------------------------------------------------- what to ask about

def bare_commands(product, ver=None, limit=None):
    """Commands we ship with no arguments -- the ones a device can describe and the
    documentation cannot. This is the walk's whole point, so it is driven by the gap
    rather than a hand-written list.

    Against the bundle for the device's OWN firmware: asking a 7.6 box about commands
    only 8.0 documents wastes the walk and muddles the result.
    """
    import json
    cfg = json.load(open(os.path.join(ROOT, 'sources.json')))
    cands = [e for e in cfg['cli'] if e['product'] == product]
    if ver:
        want = '.'.join(ver.split('.')[:2])
        cands = [e for e in cands
                 if '.'.join(e.get('ver', '').split('.')[:2]) == want] or cands
    if not cands:
        return []
    name = cands[0].get('bundle') or cands[0]['product']
    path = os.path.join(ROOT, os.environ.get('OUT', 'site/data'), f'{name}.json')
    if not os.path.exists(path):
        return []
    out = []
    for sec in json.load(open(path))['secs']:
        if sec['k'] not in ('diagnose', 'execute', 'get') or sec.get('dv') or sec.get('x'):
            continue
        # parse_hand leaves argument syntax in some paths ("diagnose debug cdbcheck
        # {enable | disable}"); asking the box about those would be nonsense.
        if re.search(r'[<>\[\]{}|]', sec['p']):
            continue
        out.append(f"{sec['k']} {sec['p']}")
    return sorted(out)[:limit] if limit else sorted(out)


# ---------------------------------------------------------------- the ? crawl

# "  neighbors    show BGP neighbors"  /  "  <A.B.C.D>    neighbor IP"
HELP_ROW = re.compile(r'^\s*(\S+)\s{2,}(\S.*?)\s*$')


def help_rows(text):
    """Parse `?` output into (name, description), plus what kind of answer it was.

    FortiOS answers `?` three ways and they mean different things:
      <Enter>            this path is already a complete command
      <placeholder> ...  the NEXT positional argument, one at a time
      word  word  word   sub-commands, which is the tree we cannot get from a PDF
    """
    rows, complete, args, subs = [], False, [], []
    for line in text.split('\n'):
        line = line.rstrip()
        if not line.strip() or line.strip().startswith('###'):
            continue
        if line.strip() == '<Enter>':
            complete = True
            continue
        m = HELP_ROW.match(line)
        if not m:
            continue
        name, desc = m.group(1), m.group(2)
        if name.startswith('<') or name == 'arg':
            args.append((name, desc))
        else:
            subs.append((name, desc))
        rows.append((name, desc))
    return {'complete': complete, 'args': args, 'subs': subs, 'rows': rows}


def crawl(s, root, out, max_nodes=40000, max_depth=10):
    """Walk `?` down from a command prefix, breadth first.

    This is the only way to reach `get router info bgp neighbors` and its family: the
    routing daemon answers `?` even though `tree` does not expand it. Nothing is ever
    executed -- `?` is answered on the keystroke and the line is cleared with ctrl-U.
    """
    import json
    seen, queue, found, asked = set(), [root], [], 0
    dest = os.path.join(out, 'crawl-' + re.sub(r'\W+', '_', root) + '.jsonl')
    with open(dest, 'w') as fh:
        while queue and asked < max_nodes:
            path = queue.pop(0)
            if path in seen or len(path.split()) - len(root.split()) > max_depth:
                continue
            seen.add(path)
            method, body = s.ask(path)
            asked += 1
            if not method:
                continue
            h = help_rows(body)
            if not (h['subs'] or h['args'] or h['complete']):
                continue
            rec = {'p': path, 'complete': h['complete'],
                   'args': h['args'], 'subs': h['subs']}
            fh.write(json.dumps(rec) + '\n')
            fh.flush()
            found.append(rec)
            for name, _ in h['subs']:
                queue.append(f'{path} {name}')
            if asked % 25 == 0:
                print(f'    asked {asked}, described {len(found)}, queue {len(queue)}',
                      flush=True)
    print(f'    asked {asked}, described {len(found)} -> {os.path.relpath(dest, ROOT)}')
    return found


# ---------------------------------------------------------------- the config walk

def config_targets(product, ver=None, limit=None):
    """Top-level `config` paths, and each one's edit key if it has one.

    From the bundle rather than the tree: the bundle's config sections are exactly the
    valid top-level `config` commands, and its syntax block already says `edit <key>`
    for the ones that are tables.
    """
    import json
    cfg = json.load(open(os.path.join(ROOT, 'sources.json')))
    cands = [e for e in cfg['cli'] if e['product'] == product]
    if ver:
        want = '.'.join(ver.split('.')[:2])
        cands = [e for e in cands
                 if '.'.join(e.get('ver', '').split('.')[:2]) == want] or cands
    if not cands:
        return []
    name = cands[0].get('bundle') or cands[0]['product']
    path = os.path.join(ROOT, os.environ.get('OUT', 'site/data'), f'{name}.json')
    if not os.path.exists(path):
        return []
    edit = re.compile(r'^\s*edit\s+(<[^>]+>)', re.M)
    out = []
    for sec in json.load(open(path))['secs']:
        if sec['k'] != 'config' or sec.get('dv'):
            continue
        if re.search(r'[<>\[\]{}|]', sec['p']):
            continue
        m = edit.search(sec.get('s') or '')
        out.append((sec['p'], m.group(1) if m else None))
    out.sort(key=lambda t: t[0])
    return out[:limit] if limit else out


def probe_key(mkey):
    """A key to `edit` so `set ?` has a context. Discarded by `abort`, never committed.

    Distinctive on purpose: if one ever survives a crashed session, it is obvious where
    it came from and trivial to find.
    """
    return '99999999' if re.search(r'id|num|seq|policyid', mkey or '', re.I) else 'zz-cli-finder-probe'


def checksum(s):
    """The device's own config checksum -- how we prove the walk changed nothing.

    Better than diffing `show full-configuration`, which would mean writing the whole
    configuration, secrets included, to our disk in order to check it was not touched.
    """
    return s.run('diagnose sys ha checksum show', idle=1.2, timeout=60)


def config_walk(s, targets, out):
    """`config <path>` -> `set ?` -> abort, for each table. Never `end`.

    `abort` leaves the config block discarding everything done inside it, which is why
    editing a probe key is safe; the checksum either side is what proves it.
    """
    got = 0
    with open(os.path.join(out, 'config-help.txt'), 'w') as fh:
        for i, (path, mkey) in enumerate(targets, 1):
            try:
                r = s.run(f'config {path}', idle=0.5, timeout=20)
                if BAD.search(r or ''):
                    continue
                if mkey:
                    s.run(f'edit {probe_key(mkey)}', idle=0.5, timeout=20)
                _, body = s.ask('set')
                if body and useful(body):
                    fh.write(f'### config {path}\n{body}\n\n')
                    got += 1
            finally:
                # always, even if the above raised: never leave a config block open
                s.run('abort', idle=0.4, timeout=20)
            if i % 50 == 0 or i == len(targets):
                print(f'    {i}/{len(targets)}  field help for {got}', flush=True)
    return got


# ---------------------------------------------------------------- one device

def capture(dev, probe_limit, verbose, do_config=False):
    print(f"\n=== {dev['name']}  {dev['user']}@{dev['host']}  ({dev['kind']})")
    s = Session(dev, verbose)
    s.read(idle=1.5, timeout=90, until=PROMPT)

    status = s.run('get system status', idle=1.0, timeout=60)
    ident = identify(status)
    if not ident:
        # keep it so an unrecognised banner is debuggable rather than just a refusal
        os.makedirs(LIVE, exist_ok=True)
        write(LIVE, f"unidentified-{dev['name']}.txt", status)
        s.close()
        print(f"  no version banner -- saved what it said to "
              f"work/live/unidentified-{dev['name']}.txt")
        return None
    model, ver, build = ident['model'], ident['ver'], ident['build']
    product = KIND_PRODUCT[dev['kind']]
    print(f'  {model} v{ver} build{build}')

    out = os.path.join(LIVE, f'{product}-{ver}-{build}')
    os.makedirs(out, exist_ok=True)
    write(out, 'status.txt', status)

    parts = [f'Version: {model} v{ver},build{build}']   # normalised for parse_tree
    for cmd in SAFE[dev['kind']][1:]:
        body = s.run(cmd, idle=1.5, timeout=300)
        write(out, re.sub(r'\W+', '_', cmd) + '.txt', body)
        print(f'  {cmd:22s} {len(body.splitlines()):6d} lines')
        if cmd == 'tree':
            parts.append(body)
    write(out, 'capture.txt', '\n'.join(parts))     # what parse_tree.py reads

    todo = bare_commands(product, ver, probe_limit)
    methods, answered = {}, 0
    if todo:
        print(f'  asking ? about {len(todo)} commands the reference prints bare')
        with open(os.path.join(out, 'help.txt'), 'w') as fh:
            for i, cmd in enumerate(todo, 1):
                method, body = s.ask(cmd)
                if method:
                    answered += 1
                    methods[method] = methods.get(method, 0) + 1
                    fh.write(f'### {cmd}\n{body}\n\n')
                if i % 100 == 0 or i == len(todo):
                    print(f'    {i}/{len(todo)}  answered {answered}', flush=True)
                if i == 20 and not answered:
                    print('    nothing answered in the first 20: `?` is not surviving '
                          'this ssh pty on this build. Stopping the walk; the tree is '
                          'still captured.')
                    break
    if do_config:
        print('  config walk: backing up to flash first')
        bk = s.run('execute backup config flash "cli-finder pre-walk"', idle=1.5, timeout=90)
        write(out, 'backup.txt', bk)
        before = checksum(s)
        write(out, 'checksum-before.txt', before)
        targets = config_targets(product, ver, None if probe_all else 40)
        print(f'  asking ? about {len(targets)} config tables (abort after each, never end)')
        got = config_walk(s, targets, out)
        after = checksum(s)
        write(out, 'checksum-after.txt', after)
        if before.strip() and before.strip() == after.strip():
            print(f'  config checksum unchanged -- the walk wrote nothing. '
                  f'({got} tables described)')
        elif not before.strip():
            print('  WARNING: no checksum before the walk, so nothing was verified. '
                  'Compare a revision by hand: execute revision list config')
        else:
            print('  *** CONFIG CHECKSUM CHANGED -- the walk altered something. ***')
            print('      restore:  execute revision list config')
            print('                execute restore config flash <revision>')
            print(f'      the two checksums are in {os.path.relpath(out, ROOT)}/')

    s.close()

    print(f'  -> {os.path.relpath(out, ROOT)}/   ({answered} help texts)')
    for m_, n in sorted(methods.items()):
        print(f'     `?` answered via {m_} for {n}')
    return out


def write(d, name, text):
    with open(os.path.join(d, name), 'w') as f:
        f.write(text.rstrip('\n') + '\n')


def main():
    args = sys.argv[1:]
    verbose = '--verbose' in args
    probe_all = '--probe-all' in args
    config_walk_on = '--config-walk' in args
    crawl_roots = []
    if '--crawl' in args:
        i = args.index('--crawl')
        crawl_roots = [r.strip() for r in args[i + 1].split(',') if r.strip()]
        args = args[:i] + args[i + 2:]
    want = [a for a in args if not a.startswith('--')]
    devices = load_env()
    if want:
        missing = [w for w in want if w not in devices]
        if missing:
            raise SystemExit(f'not in .env.devices: {missing} (have {list(devices)})')
        devices = {k: v for k, v in devices.items() if k in want}

    print(f'{len(devices)} device(s): {", ".join(devices)}')
    if crawl_roots:
        # Crawl only: walk `?` down from each root on each device. This is the long one,
        # and the only way to reach the get tree -- the reference documents none of it and
        # the device's own `tree` cannot expand the routing daemon's subtree.
        for dev in devices.values():
            try:
                print(f"\n=== {dev['name']}  crawl {crawl_roots}")
                s = Session(dev, verbose)
                s.read(idle=1.5, timeout=90, until=PROMPT)
                status = s.run('get system status', idle=1.0, timeout=60)
                ident = identify(status)
                if not ident:
                    print('  no version banner -- skipped')
                    s.close()
                    continue
                out = os.path.join(LIVE, f"{KIND_PRODUCT[dev['kind']]}-"
                                         f"{ident['ver']}-{ident['build']}")
                os.makedirs(out, exist_ok=True)
                write(out, 'status.txt', status)
                write(out, 'capture.txt',
                      f"Version: {ident['model']} v{ident['ver']},build{ident['build']}")
                for root in crawl_roots:
                    print(f'  crawling {root!r}', flush=True)
                    crawl(s, root, out)
                s.close()
                print(f'  -> {os.path.relpath(out, ROOT)}/')
            except Exception as e:
                print(f"  {dev['name']}: {type(e).__name__}: {e}")
        return 0

    done = []
    for dev in devices.values():
        try:
            d = capture(dev, None if probe_all else 60, verbose, config_walk_on)
            if d:
                done.append(d)
        except SystemExit as e:
            print(f"  {dev['name']}: {e}")
        except Exception as e:                       # one bad box must not stop the rest
            print(f"  {dev['name']}: {type(e).__name__}: {e}")

    if done:
        print('\nnext:')
        for d in done:
            rel = os.path.relpath(os.path.join(d, 'capture.txt'), ROOT)
            print(f'  make tree FILE={rel}')
            print(f'  python3 tools/parse_tree.py {rel} --record')
    return 0 if done else 1


if __name__ == '__main__':
    sys.exit(main())
