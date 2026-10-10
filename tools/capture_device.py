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
SAFE = {
    'fgt': ['get system status', 'tree'],
    'fsw': ['get system status', 'tree'],
    'faz': ['get system status', 'tree'],
    'fmg': ['get system status', 'tree'],
}
KIND_PRODUCT = {'fgt': 'fortios', 'fsw': 'fortiswitch',
                'faz': 'fortianalyzer', 'fmg': 'fortimanager'}

PROMPT = re.compile(rb'(?:^|\r?\n)[\w.\-]+(?:\s+\([\w.\-]+\))?\s*[#$]\s*$')
PAGER = re.compile(rb'--More--|\(END\)', re.I)
PASSWD = re.compile(rb"password:\s*$", re.I)
BANNER = re.compile(r'^Version:\s*(\S+?)\s+v(\d+\.\d+\.\d+)\s*,\s*build(\d+)', re.M)
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
        for method, payload in (('space-q', cmd + ' ?'), ('bare-q', cmd + '?')):
            self.buf = b''
            os.write(self.fd, payload.encode())
            time.sleep(0.35)
            out = clean(self.read(idle=0.7, timeout=20).decode('utf-8', 'replace'), payload)
            os.write(self.fd, b'\x15')          # ctrl-U: clear the line, run nothing
            self.read(idle=0.25, timeout=3)
            if useful(out):
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
    while lines and PROMPT.search(lines[-1].encode()):
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


# ---------------------------------------------------------------- one device

def capture(dev, probe_limit, verbose):
    print(f"\n=== {dev['name']}  {dev['user']}@{dev['host']}  ({dev['kind']})")
    s = Session(dev, verbose)
    s.read(idle=1.5, timeout=90, until=PROMPT)

    status = s.run('get system status', idle=1.0, timeout=60)
    m = BANNER.search(status)
    if not m:
        s.close()
        print('  no "Version:" banner -- is this a Fortinet CLI? Leaving it alone.')
        return None
    model, ver, build = m.group(1), m.group(2), m.group(3)
    product = KIND_PRODUCT[dev['kind']]
    print(f'  {model} v{ver} build{build}')

    out = os.path.join(LIVE, f'{product}-{ver}-{build}')
    os.makedirs(out, exist_ok=True)
    write(out, 'status.txt', status)

    parts = [f'Version: {model} v{ver},build{build}']
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
    want = [a for a in args if not a.startswith('--')]
    devices = load_env()
    if want:
        missing = [w for w in want if w not in devices]
        if missing:
            raise SystemExit(f'not in .env.devices: {missing} (have {list(devices)})')
        devices = {k: v for k, v in devices.items() if k in want}

    print(f'{len(devices)} device(s): {", ".join(devices)}')
    done = []
    for dev in devices.values():
        try:
            d = capture(dev, None if probe_all else 60, verbose)
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
