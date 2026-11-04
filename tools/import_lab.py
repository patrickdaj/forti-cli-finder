#!/usr/bin/env python3
"""Turn the lab's logged device output into an anonymised overlay of sample output.

The guides contain little output, so the Finder's sample column is thin. The owner's lab
(a separate repository) logs every masked read it makes of a device: thousands of real
`get system status`, `diagnose vpn tunnel list`, `show full-configuration ...`. This reads
those logs and distils one sample per (platform, train, command) into lab-overlay.json,
which is committed. A later step (not this one) attaches the samples to the bundles.

  python3 tools/import_lab.py                 # read the lab, write lab-overlay.json
  python3 tools/import_lab.py --report        # counts only; writes nothing
  python3 tools/import_lab.py --lab PATH      # a lab checkout other than ~/Development/fortinet-lab
  python3 tools/import_lab.py --selftest      # inline fixtures; needs no lab (make check)

Input is `investigations/<id>/lab.log` and `investigations/_lab/<date>.log` under the lab,
nothing else there. A record is

    === 2026-11-03T07:04:58 fgt-edge1 exit=0
    $ get system status
    fgt-edge1-76 $ Version: FortiGate-VM64-KVM v7.6.7,build3704,260601 (GA.M)

THIS REPOSITORY IS PUBLIC and the overlay is committed, so anonymisation is the point and
not a courtesy. Every kept sample, scratch or company, has:

  * prompts and hostnames made generic per platform (`FGT $`, `FMG $`, `FAZ $`, `FSW $`);
  * serials cut to their last four characters (`FGVMxxxx1234`);
  * company names and the abbreviations in the lab's device names replaced;
  * everything the lab's own masker masks, masked again, and `ENC <masked>` collapsed to
    `<masked>` so no stored-secret marker survives at all;
  * public IPv4 addresses replaced by RFC 5737 ones, the same address every time;
  * the last three octets of MAC addresses replaced.

Then a final scan runs over what is about to be written. A secret, serial or company name
still there means this REFUSES TO WRITE (exit 1, naming the record) -- a leak into a public
repository is worse than a missing sample.

Selection (rulings, not tuning): exit=0 reads only -- `get`, `show`, `diagnose`/`diag`,
`execute ping`, `execute traceroute`. Records of the policy hook, plan runner and
containers are not device reads. Piped or compound commands are dropped: `show ... | grep x`
is one line of a sample, not the sample. Output that is an error message is dropped.
"""
import collections, datetime, hashlib, importlib.util, ipaddress, json, os, re, sys, tomllib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OVERLAY = os.path.join(ROOT, 'lab-overlay.json')
DEFAULT_LAB = os.path.expanduser('~/Development/fortinet-lab')
BUNDLES = os.path.join(ROOT, 'site', 'data')
CAP_LINES = 60
PLAN_WINDOW = 600          # seconds: a dated-log record belongs to a plan this recent

GENERIC = {'fortios': 'FGT', 'fortimanager': 'FMG', 'fortianalyzer': 'FAZ', 'fortiswitch': 'FSW'}
PLATFORM_OF = (('FortiGate', 'fortios'), ('FortiWiFi', 'fortios'), ('FortiManager', 'fortimanager'),
               ('FortiAnalyzer', 'fortianalyzer'), ('FortiSwitch', 'fortiswitch'))

# ---- secrets: lab/mask.py, copied -----------------------------------------------------
# Copied from fortinet-lab lab/mask.py at commit 76aeea7 (stdlib-only there too), so that
# --selftest needs no lab. When the lab is present, its own mask.py is applied as well
# (load_lab_mask), so a pattern added there later is honoured here before this copy catches up.
MASK = '<masked>'
_SA_KEY = re.compile(r"(\bkey=\d+\s+)([0-9A-Fa-f]{8,})")
_IKE_SK = re.compile(r"(\b(?:SK_[a-z]{1,2}|SKEYSEED)\b:?[ \t]+(?:\d+:)?)([0-9A-Fa-f]{4,}(?:-[0-9A-Fa-f]+)*)")
_IKE_DUMP = re.compile(r"(\bike [^\n]*?: (?:enc|dec) )([0-9A-Fa-f]{16,})")
_ENC = re.compile(r"(\bENC[ \t]+)([A-Za-z0-9+/=]{8,})")
_FIELD = (r"(?:psksecret(?:-remote)?|ppk-secret|password\d?|passwd\d?|secret|key|private-key|api-key"
          r"|auth-pwd|authpasswd|[\w-]+-(?:password|passwd|secret|psk|pwd|key|token))")
_SET_SECRET = re.compile(
    r'(\bset[ \t]+' + _FIELD + r'[ \t]+)(?!ENC[ \t]|<masked>|@secret:)("(?:\\.|[^"\\])*"|[^\s"]+)',
    re.IGNORECASE)
MASK_PATTERNS = (_SA_KEY, _IKE_SK, _IKE_DUMP, _ENC, _SET_SECRET)
# Not the lab's (a public key is no secret) but it names its owner: key blob and trailing comment.
SSH_KEY = re.compile(r'\b(ssh-(?:ed25519|rsa|dss)|ecdsa-sha2-nistp\d+)[ \t]+[A-Za-z0-9+/=]{20,}(?:[ \t]+[^\s"\\]+)?')
# A wider net than the masker's, for the final scan only: these must not survive anywhere.
SCAN_EXTRA = (re.compile(r'\bpsksecret\b[ \t]+(?!<masked>|ENC\b|@secret:)\S', re.I),
              re.compile(r'\bENC[ \t]'),
              SSH_KEY,)
_LAB_MASK = None


def load_lab_mask(lab):
    """The lab's own lab/mask.py, if there and importable; its mask_count is applied too."""
    global _LAB_MASK
    path = os.path.join(lab, 'lab', 'mask.py')
    _LAB_MASK = None
    if os.path.isfile(path):
        try:
            spec = importlib.util.spec_from_file_location('lab_mask', path)
            mod = importlib.util.module_from_spec(spec)
            sys.modules['lab_mask'] = mod       # dataclass-style modules want this
            spec.loader.exec_module(mod)
            _LAB_MASK = mod
        except Exception as e:                  # copied patterns still apply
            print(f'note: could not load {path}: {e}', file=sys.stderr)


def mask(text):
    for p in MASK_PATTERNS:
        text = p.sub(lambda m: m.group(1) + MASK, text)
    if _LAB_MASK is not None:
        text = _LAB_MASK.mask(text)
    text = SSH_KEY.sub(lambda m: m.group(1) + ' ' + MASK, text)
    return re.sub(r'\bENC[ \t]+' + re.escape(MASK), MASK, text)


# ---- the anonymiser -------------------------------------------------------------------
# Both come from the lab at run time (derive_names); nothing about a real customer is written here.
COMPANY_NAMES = ()
COMPANY_ABBR = ()
# `fips-cc` is Common Criteria, not a company; the others are listed when the abbreviation
# is also a word in Fortinet's own output.
ABBR_KEEP = re.compile(r'fips-cc|cc-mode', re.I)

SERIAL = re.compile(r'(?<![A-Za-z0-9])F[A-Z][A-Z0-9-]{8,24}(?![A-Za-z0-9])')
SERIAL_LINE = re.compile(r'(Serial[- ]Number[ \t]*:[ \t]*)(\S+)', re.I)
IPV4 = re.compile(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])')
# six octets, standing alone: not the head of a 20-octet fingerprint, but fine after `Hwaddr:`
MAC = re.compile(r'(?<![0-9A-Fa-f])(?<![0-9A-Fa-f]:)((?:[0-9A-Fa-f]{2}:){2}[0-9A-Fa-f]{2}):'
                 r'(?:[0-9A-Fa-f]{2}:){2}[0-9A-Fa-f]{2}(?![0-9A-Fa-f])(?!:[0-9A-Fa-f])')
PROMPT = re.compile(r'^(?P<host>[A-Za-z0-9][\w.-]*)(?P<ha>\([^)\s]*\))?(?P<vd> \([^)]*\))? '
                    r'(?P<sym>[$#])(?: (?P<rest>.*))?$')
RFC5737 = [ipaddress.ip_network(n) for n in ('192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24')]
KEEP_NETS = [ipaddress.ip_network(n) for n in (
    '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10', '169.254.0.0/16',
    '127.0.0.0/8', '224.0.0.0/4', '0.0.0.0/8', '240.0.0.0/4', *[str(n) for n in RFC5737])]


def mask_serial(s):
    return s if 'xxxx' in s else s[:4] + 'xxxx' + s[-4:]


def serial_tail(s):
    """A serial on a Serial-Number line: F-prefixed ones keep their model prefix, any other is
    reduced to `xxxx` and its last four characters."""
    if 'xxxx' in s:
        return s
    return mask_serial(s) if re.match(r'F[A-Z]', s) else 'xxxx' + s[-4:]


def serial_hit(m_text):
    """Serial-shaped tokens in text: F + capital, 10-25 characters, at least four digits."""
    return [m.group(0) for m in SERIAL.finditer(m_text) if sum(c.isdigit() for c in m.group(0)) >= 4]


def public_ip_map(ip):
    """A public address -> an RFC 5737 one, the same one every time (hash, not order)."""
    h = int(hashlib.sha256(ip.encode()).hexdigest(), 16)
    net = RFC5737[h % 3]
    return str(net.network_address + 1 + (h // 3) % 254)


class Anonymiser:
    """hosts: {hostname: platform}. Everything else is fixed or derived from the lab."""

    def __init__(self, hosts=None, names=None, abbrs=None):
        names = COMPANY_NAMES if names is None else names
        abbrs = COMPANY_ABBR if abbrs is None else abbrs
        self.hosts = dict(hosts or {})
        self.names = sorted({n.lower() for n in names})
        self.abbrs = sorted({a.lower() for a in abbrs})
        self._name_re = re.compile('(?<![A-Za-z0-9])(' + '|'.join(map(re.escape, self.names)) + ')',
                                   re.I) if self.names else None
        # not beside a colon: `78:CC:A5:...` is a fingerprint, and cc is a hex byte
        self._abbr_re = re.compile(r'(?<![A-Za-z0-9:])(' + '|'.join(
            f'{re.escape(a)}|{re.escape(a.upper())}' for a in self.abbrs) + r')(?![A-Za-z0-9:])') if self.abbrs else None
        hs = sorted(self.hosts, key=lambda h: (-len(h), h))
        self._host_re = re.compile('(?<![A-Za-z0-9])(' + '|'.join(map(re.escape, hs)) + ')(?![A-Za-z0-9])',
                                   re.I) if hs else None

    # -- pieces, each testable and (for the leak test) overridable
    def prompt_line(self, line, platform, first=False, last=False):
        """Rewrite a prompt line generically; the (host, rest) it carried, or None if not one."""
        m = PROMPT.match(line)
        if not m:
            return None
        host = m.group('host')
        if not (first or last or host.lower() in {h.lower() for h in self.hosts}):
            return None
        return (f"{GENERIC[platform]}{m.group('vd') or ''} {m.group('sym')}", m.group('rest') or '')

    def hostnames(self, s, platform):
        if not self._host_re:
            return s
        lower = {h.lower(): p for h, p in self.hosts.items()}
        return self._host_re.sub(lambda m: GENERIC[lower.get(m.group(1).lower(), platform)], s)

    def serials(self, s):
        s = SERIAL_LINE.sub(lambda m: m.group(1) + (serial_tail(m.group(2))
                            if len(m.group(2)) >= 8 and any(c.isdigit() for c in m.group(2)) else m.group(2)), s)
        return SERIAL.sub(lambda m: mask_serial(m.group(0)) if serial_hit(m.group(0)) else m.group(0), s)

    def company(self, s):
        if self._name_re:
            s = self._name_re.sub('corp', s)
        if self._abbr_re:
            def rep(m):
                ctx = s[max(0, m.start() - 5):m.end() + 5]
                return m.group(0) if ABBR_KEEP.search(ctx) else 'site'
            s = self._abbr_re.sub(rep, s)
        return s

    @staticmethod
    def addresses(s):
        def ip(m):
            t = m.group(0)
            try:
                a = ipaddress.ip_address(t)
            except ValueError:
                return t
            if any(a in n for n in KEEP_NETS):
                return t
            return public_ip_map(t)
        s = IPV4.sub(ip, s)
        return MAC.sub(lambda m: m.group(1) + ':xx:xx:xx', s)

    def text(self, s, platform):
        """Everything but prompts, which are line-structural and handled by the caller."""
        s = mask(s)
        s = self.hostnames(s, platform)
        s = self.serials(s)
        s = self.company(s)
        return self.addresses(s)

    def problems(self, s):
        """What must not be in text about to be written; [] if clean."""
        out = []
        for p in MASK_PATTERNS:
            if p.search(s):
                out.append('secret pattern')
        if any(p.search(s) for p in SCAN_EXTRA):
            out.append('stored-secret marker')
        if serial_hit(s):
            out.append('serial')
        if self._name_re and self._name_re.search(s):
            out.append('company name')
        if self._host_re and self._host_re.search(s):
            out.append('hostname')
        return sorted(set(out))


class Refuse(Exception):
    pass


# ---- records ----------------------------------------------------------------------------
HDR = re.compile(r'^=== (\d{4}-\d\d-\d\d)T(\d\d:\d\d:\d\d) (\S+) exit=(\S+)\s*$')
ANSI = re.compile(r'\x1b\[[0-9;?]*[A-Za-z]|[\x00-\x08\x0b-\x1f\x7f]')


def split_records(text):
    """[{ts, date, dev, exit, cmds, body}]. Leading `$ ` lines are the commands; the rest is output."""
    recs, cur = [], None
    for line in text.replace('\r\n', '\n').split('\n'):
        m = HDR.match(line)
        if m:
            cur = {'date': m.group(1), 'ts': f'{m.group(1)}T{m.group(2)}', 'dev': m.group(3),
                   'exit': m.group(4), 'cmds': [], 'body': [], 'head': True}
            recs.append(cur)
        elif cur is not None:
            if cur['head'] and line.startswith('$ '):
                cur['cmds'].append(line[2:].strip())
            else:
                cur['head'] = False
                cur['body'].append(ANSI.sub('', line).rstrip())
    for r in recs:
        del r['head']
        while r['body'] and not r['body'][-1]:
            r['body'].pop()
    return recs


def when(ts):
    return datetime.datetime.fromisoformat(ts)


EXCLUDED_DEVS = ('policy', 'plan')
READ_VERBS = {'get': 'get', 'show': 'show', 'diagnose': 'diagnose', 'diag': 'diagnose'}
DEBUG_BOOKKEEPING = re.compile(r'^(?:diagnose|diag) debug (?:enable|disable|reset|console)\b')
COMPOUND = re.compile(r'[|;&<>`]|\$\(')
ERROR_OUT = re.compile(r'Unknown action|Command fail|parse error|Unknown command|ssh failed|'
                       r'No permission|Permission denied|node_check_object fail', re.I)
BANNER = re.compile(r'WARNING: File System Check|It is strongly recommended|Please run \'execute disk|'
                    r'Note: The device will reboot|^\*\* |Warning: Permanently added', re.I)


def classify(cmd):
    """(k, p) for a read command we keep, else a reason string."""
    c = ' '.join(cmd.split())
    parts = c.split(' ')
    verb = parts[0]
    if verb == 'execute':
        if len(parts) < 2 or parts[1] not in ('ping', 'traceroute'):
            return 'not a read command'
        k = 'execute'
    elif verb in READ_VERBS:
        k = READ_VERBS[verb]
    else:
        return 'not a read command'
    if DEBUG_BOOKKEEPING.match(c):
        return 'debug bookkeeping'
    if COMPOUND.search(c):
        return 'piped or compound'
    return (k, ' '.join(parts[1:]))


# ---- builds -----------------------------------------------------------------------------
_FGT_VER = re.compile(r'\bVersion\s*:\s*(Forti\S+)\s+v(\d+\.\d+\.\d+)[,-]\s*build(\d+)')
_FMG_NAME = re.compile(r'Platform Full Name\s*:\s*(\S+)')
_FMG_VER = re.compile(r'\bVersion\s*:\s*v(\d+\.\d+\.\d+)-build(\d+)')


def parse_status(body):
    """(model, version, build) from `get system status` output, else None."""
    text = '\n'.join(body)
    m = _FGT_VER.search(text)
    if m:
        return m.group(1), m.group(2), m.group(3)
    n, v = _FMG_NAME.search(text), _FMG_VER.search(text)
    if n and v:
        return n.group(1), v.group(1), v.group(2)
    return None


def platform_of(model):
    for prefix, plat in PLATFORM_OF:
        if model.startswith(prefix):
            return plat
    return None


def fallback_build(vmid):
    if vmid is None:
        return None
    if 5081 <= vmid <= 5085:
        return ('FortiGate-VM64-KVM', '7.6.7', '3704')
    if 5091 <= vmid <= 5095:
        return ('FortiGate-VM64-KVM', '8.0.2', '0251')
    return None


def build_string(b):
    return f'{b[0]} v{b[1]} build{b[2]}'


def train_of(b):
    return '.'.join(b[1].split('.')[:2])


# ---- output of one command --------------------------------------------------------------
def segments(rec, anon):
    """[(cmd, body_lines)] for a record, or None when a multi-command output cannot be attributed."""
    cmds, body = rec['cmds'], rec['body']
    if len(cmds) == 1:
        return [(cmds[0], body)]
    first = next((PROMPT.match(l) for l in body if l.strip()), None)
    if not first:
        return None
    starts = []
    for i, l in enumerate(body):
        m = PROMPT.match(l)
        if m and m.group('host') == first.group('host'):
            starts.append(i)
    # a lone prompt as the last non-blank line closes the session; it starts nothing
    if starts and starts[-1] == len(body) - 1 and not PROMPT.match(body[-1]).group('rest'):
        starts.pop()
    if len(starts) != len(cmds):
        return None
    ends = starts[1:] + [len(body)]
    return [(c, body[s:e]) for c, s, e in zip(cmds, starts, ends)]


def clean_output(lines, anon, platform):
    """Drop banner and prompt scaffolding, make remaining prompts generic. Returns the text."""
    lines, kept, skip_blank = list(lines), [], False
    for l in lines:                     # pager residue: `--More--` and the blank line after it
        if l.strip() == '--More--':
            skip_blank = True
            continue
        if skip_blank and not l.strip():
            skip_blank = False
            continue
        skip_blank = False
        kept.append(l)
    lines = kept
    # leading: banner lines up to the first prompt, then the prompt itself
    for i, l in enumerate(lines[:12]):
        if PROMPT.match(l) and anon.prompt_line(l, platform, first=True):
            if all(BANNER.search(x) or not x.strip() for x in lines[:i]):
                lines = lines[i:]
            break
    out = []
    for i, l in enumerate(lines):
        p = anon.prompt_line(l, platform, first=(i == 0), last=(i == len(lines) - 1))
        if p is None:
            out.append(l)
        elif i == 0:
            if p[1]:
                out.append(p[1])        # `host $ Version: ...` -> `Version: ...`
        else:
            out.append(f'{p[0]} {p[1]}'.rstrip() if p[1] else p[0] + ' ')
    while out and (not out[-1].strip() or out[-1].rstrip() in tuple(f'{g} {s}' for g in GENERIC.values()
                                                                     for s in '$#')):
        out.pop()
    return '\n'.join(out)


def cap(text):
    lines = text.split('\n')
    if len(lines) > CAP_LINES:
        lines = lines[:CAP_LINES] + ['...']
    return '\n'.join(lines)


# ---- the whole run ----------------------------------------------------------------------
def run(sources, vmids=None, anon_factory=Anonymiser, names=None, abbrs=None):
    """sources: [(kind, name, text)], kind 'inv' (name = investigation folder) or 'dated' (name = date).

    Returns (samples, stats). Raises Refuse if anything that must not ship is still there.
    """
    vmids = vmids or {}
    stats = collections.Counter()
    recs = []
    for si, (kind, name, text) in enumerate(sources):
        plans = []
        for r in split_records(text):
            r['kind'], r['name'], r['seq'] = kind, name, (si, len(recs))
            if r['dev'] == 'plan':
                for l in r['body']:
                    m = re.match(r'plan=(\S+)', l)
                    if m:
                        plans.append((when(r['ts']), m.group(1)))
                        break
            r['plan'] = None
            for t, pid in reversed(plans):
                if t <= when(r['ts']) and (when(r['ts']) - t).total_seconds() <= PLAN_WINDOW:
                    r['plan'] = pid
                    break
            recs.append(r)
    stats['records read'] = len(recs)
    recs.sort(key=lambda r: (r['ts'], r['seq']))

    # Hostnames: prompts at the head or tail of an output, `Hostname` lines, and the device
    # names the lab logs under. Anything else that merely looks like a prompt is not trusted.
    status = {}                       # dev -> most recent build
    hosts = {}
    plat_of_dev = {}
    for r in recs:
        dev = r['dev']
        if dev in EXCLUDED_DEVS or dev.startswith('ct:'):
            continue
        st = None
        if r['cmds'] and ' '.join(r['cmds'][0].split()) == 'get system status' and r['exit'] == '0':
            st = parse_status(r['body'])
        if st:
            status[dev] = st
            plat_of_dev[dev] = platform_of(st[0])
        r['_build'] = status.get(dev)
    for r in recs:
        dev = r['dev']
        if dev in EXCLUDED_DEVS or dev.startswith('ct:'):
            continue
        plat = platform_of(r['_build'][0]) if r['_build'] else plat_of_dev.get(dev)
        if plat is None:
            b = fallback_build(vmids.get(dev))
            plat = platform_of(b[0]) if b else None
        if plat is None:
            continue
        if any(isinstance(classify(c), tuple) for c in r['cmds']):
            hosts.setdefault(dev, plat)
        body = r['body']
        for idx in ((0, len(body) - 1) if body else ()):
            m = PROMPT.match(body[idx])
            if m and not m.group('host').startswith('Forti'):
                hosts.setdefault(m.group('host'), plat)
        for l in body:
            m = re.match(r'\s*Hostname\s*:\s*(\S+)\s*$', l)
            if m and not m.group(1).startswith('Forti'):
                hosts.setdefault(m.group(1), plat)
    hosts = {h: p for h, p in hosts.items() if len(h) >= 3}
    anon = anon_factory(hosts, names, abbrs)

    cands = {}
    kept_records = set()
    for r in recs:
        dev = r['dev']
        if dev in EXCLUDED_DEVS or dev.startswith('ct:'):
            stats['dropped: policy, plan or container record'] += 1
            continue
        if r['exit'] != '0':
            stats['dropped: exit != 0'] += 1
            continue
        if not r['cmds']:
            stats['dropped: no command'] += 1
            continue
        segs = segments(r, anon)
        if segs is None:
            stats['dropped: session output cannot be attributed to commands'] += 1
            continue
        build = r['_build'] or fallback_build(vmids.get(dev))
        for cmd, lines in segs:
            c = classify(cmd)
            if isinstance(c, str):
                stats['dropped: ' + c] += 1
                continue
            if not build:
                stats['dropped: no known build'] += 1
                continue
            plat = platform_of(build[0])
            if plat is None:
                stats['dropped: unrecognised model'] += 1
                continue
            raw = '\n'.join(lines)
            if ERROR_OUT.search(raw):
                stats['dropped: error output'] += 1
                continue
            body = clean_output(lines, anon, plat)
            if not body.strip():
                stats['dropped: empty output'] += 1
                continue
            body = cap(anon.text(body, plat))
            command = anon.text(' '.join(cmd.split()), plat)
            k, p = c
            p = anon.text(p, plat)
            if r['kind'] == 'inv':
                capt = r['name']
            else:
                capt = r['plan'] or f"lab session {r['date']}"
            capt = anon.text(capt, plat)
            for what, val in (('output', body), ('command', command), ('caption', capt)):
                bad = anon.problems(val)
                if bad:
                    raise Refuse(f"{r['ts']} {r['dev']} `{cmd[:60]}`: {what} still has {', '.join(bad)}")
            kept_records.add(r['seq'])
            key = (plat, train_of(build), k, ' '.join(p.split()))
            if k == 'diagnose' and not command.startswith('diagnose'):
                command = 'diagnose' + command[len(command.split()[0]):]
            cand = {'k': k, 'p': ' '.join(p.split()), 'c': command, 't': body, 'cap': capt,
                    'build': build_string(build), 'train': train_of(build), 'date': r['date']}
            rank = (r['date'], min(body.count('\n') + 1, CAP_LINES + 1), not capt.startswith('lab session'),
                    r['ts'], capt, body)
            if key not in cands or rank > cands[key][0]:
                cands[key] = (rank, cand, plat)
    stats['records kept'] = len(kept_records)
    samples = collections.defaultdict(list)
    for key, (_, cand, plat) in cands.items():
        samples[plat].append(cand)
    for plat in samples:
        samples[plat].sort(key=lambda s: (s['train'], s['k'], s['p'], s['c']))
    stats['hostnames anonymised'] = len(hosts)
    return dict(sorted(samples.items())), stats


def overlay(samples):
    builds = sorted({s['build'] for lst in samples.values() for s in lst})
    return {
        '_comment': [
            'Sample output from the owner\'s lab, for the build to attach to commands.',
            'Written by tools/import_lab.py from the lab\'s own logged, masked device reads.',
            'Regenerate rather than hand-edit.',
            'Anonymised before it gets here: prompts and hostnames made generic (FGT, FMG, FAZ,',
            'FSW), serials cut to their last four characters, company names and the',
            'abbreviations in device names replaced, secrets masked, public IPv4 addresses',
            'swapped for RFC 5737 ones, MAC suffixes blanked. The tool refuses to write if a',
            'secret, serial or company name survives its own final scan.',
        ],
        'builds': builds,
        'samples': samples,
    }


def dump(samples):
    return json.dumps(overlay(samples), indent=1, ensure_ascii=False) + '\n'


# ---- reading the lab --------------------------------------------------------------------
def read_lab(lab):
    inv = os.path.join(lab, 'investigations')
    sources = []
    if not os.path.isdir(inv):
        raise SystemExit(f'{inv} is not a directory; pass --lab PATH')
    for d in sorted(os.listdir(inv)):
        p = os.path.join(inv, d, 'lab.log')
        if d != '_lab' and os.path.isfile(p):
            sources.append(('inv', d, open(p, encoding='utf-8', errors='replace').read()))
    dated = os.path.join(inv, '_lab')
    if os.path.isdir(dated):
        for f in sorted(os.listdir(dated)):
            if f.endswith('.log'):
                sources.append(('dated', f[:-4], open(os.path.join(dated, f), encoding='utf-8',
                                                      errors='replace').read()))
    vmids, raw = {}, ''
    t = os.path.join(lab, 'lab.toml')
    if os.path.isfile(t):
        raw = open(t, encoding='utf-8').read()
        for name, dev in tomllib.loads(raw).get('devices', {}).items():
            if 'vmid' in dev:
                vmids[name] = dev['vmid']
    return sources, vmids, raw


def derive_names(raw, lab=None):
    """Company names and device-name abbreviations the lab's own config uses (lab.toml sets, and
    the company files under the lab's docs/companies/)."""
    names, abbrs = set(COMPANY_NAMES), set(COMPANY_ABBR)
    cdir = os.path.join(lab, 'docs', 'companies') if lab else ''
    if cdir and os.path.isdir(cdir):
        names |= {f[:-3].lower() for f in os.listdir(cdir) if f.endswith('.md') and f.lower() != 'readme.md'}
    if raw:
        for m in re.finditer(r'^\[sets\.([a-z0-9_-]+)\]\s*\ntier\s*=\s*"company"', raw, re.M):
            names.add(m.group(1))
        abbrs |= set(re.findall(r'\bf(?:gt|mg|az|sw)-([a-z]{2,3})-[a-z0-9]', raw))
    return sorted(names), sorted(abbrs)


# ---- the report -------------------------------------------------------------------------
def guide_index():
    """{bundle: {k: [(tokens, has_sample)]}} from the committed bundles, for the report only."""
    idx = {}
    for b in ('fortios', 'fortios-8.0', 'fortimanager', 'fortianalyzer', 'fortiswitch'):
        f = os.path.join(BUNDLES, b + '.json')
        if not os.path.isfile(f):
            continue
        d = collections.defaultdict(list)
        for s in json.load(open(f))['secs']:
            if s['k'] in ('get', 'show', 'diagnose', 'execute'):
                d[s['k']].append((s['p'].split(), bool(s.get('o'))))
        idx[b] = d
    return idx


def bundle_for(plat, train):
    return 'fortios-8.0' if (plat, train) == ('fortios', '8.0') else plat


def guide_match(idx, plat, train, k, p):
    """True / False if the longest matching bundle command has / lacks a guide sample; None if none matches."""
    ents = idx.get(bundle_for(plat, train), {}).get(k)
    if not ents:
        return None
    t, best = p.split(), None
    for toks, has in ents:
        if len(toks) <= len(t) and all(a.startswith(b) or a[:1] in '<{[' for a, b in zip(toks, t)):
            if best is None or len(toks) > best[0]:
                best = (len(toks), has)
    return None if best is None else best[1]


def report(samples, stats):
    print('records read:', stats['records read'])
    print('records kept:', stats['records kept'])
    print('dropped by reason:')
    for k in sorted(k for k in stats if k.startswith('dropped')):
        print(f'  {stats[k]:6d}  {k[9:]}')
    print('hostnames anonymised:', stats['hostnames anonymised'])
    print('samples (one per platform, train, command):')
    n = 0
    for plat, lst in samples.items():
        for tr, c in sorted(collections.Counter(s['train'] for s in lst).items()):
            print(f'  {plat:14s} {tr:4s} {c:5d}')
        n += len(lst)
    print(f'  total {n}')
    idx = guide_index()
    if not idx:
        print('guide comparison: no bundles in site/data/')
        return
    tally = collections.Counter()
    for plat, lst in samples.items():
        for s in lst:
            g = guide_match(idx, plat, s['train'], s['k'], s['p'])
            tally['has a guide sample' if g else 'matches a command with no guide sample' if g is False
                  else 'matches no bundle command'] += 1
    print('against the committed bundles (longest matching command, abbreviations allowed):')
    for k in ('has a guide sample', 'matches a command with no guide sample', 'matches no bundle command'):
        print(f'  {tally[k]:6d}  {k}')
    print(f"  would be new: {tally['matches a command with no guide sample'] + tally['matches no bundle command']}"
          f" of {n}")


# ---- selftest ---------------------------------------------------------------------------
FGT_STATUS = """=== 2026-11-03T07:04:58 fgt-ac-hub1 exit=0
$ get system status
WARNING: File System Check Recommended! An unsafe reboot may have caused an inconsistency in the disk drive.
Note: The device will reboot and scan the disk during startup. This may take up to an hour.
fgt-ac-hub1(Primary) $ Version: FortiGate-VM64-KVM v7.6.7,build3704,260601 (GA.M)
Serial-Number: FGVMELTM00001234
Hostname: fgt-ac-hub1
Log hard disk: Not available

fgt-ac-hub1(Primary) $ 
"""
FMG_STATUS = """=== 2026-11-03T08:00:00 fmg-core exit=0
$ get system status
fmg-core $ Platform Type                   : FMG-VM64-KVM
Platform Full Name              : FortiManager-VM64-KVM
Version                         : v7.6.7-build3737 260601 (GA.M)
Serial Number                   : FMVMELTM00005678
Hostname                        : fmg-core

fmg-core $ 
"""
PLAN = """=== 2026-11-03T07:00:00 plan exit=0
$ make x
plan=demo-plan sha=0a39e2be414e step 1/2
"""


def selftest():
    global COMPANY_NAMES, COMPANY_ABBR
    COMPANY_NAMES, COMPANY_ABBR = ('acme', 'bluebird', 'kestrel'), ('ac', 'bl')   # invented customers
    # --- record splitting
    recs = split_records(FGT_STATUS + "=== 2026-11-03T07:05:00 policy exit=-\n$ ls\npass\n")
    assert [r['dev'] for r in recs] == ['fgt-ac-hub1', 'policy'], recs
    assert recs[0]['cmds'] == ['get system status'] and recs[0]['exit'] == '0'
    assert recs[0]['date'] == '2026-11-03' and recs[0]['ts'] == '2026-11-03T07:04:58'
    assert recs[0]['body'][-1].startswith('fgt-ac-hub1(Primary) $'), recs[0]['body']

    # --- selection filters
    assert classify('get router info bgp summary') == ('get', 'router info bgp summary')
    assert classify('diag  sys   ha status') == ('diagnose', 'sys ha status')
    assert classify('execute ping 10.1.1.1') == ('execute', 'ping 10.1.1.1')
    assert classify('execute traceroute 10.1.1.1') == ('execute', 'traceroute 10.1.1.1')
    assert classify('execute reboot') == 'not a read command'
    assert classify('config system global') == 'not a read command'
    assert classify('diagnose debug enable') == 'debug bookkeeping'
    assert classify('diag debug reset') == 'debug bookkeeping'
    assert classify('diagnose debug application ike -1') == ('diagnose', 'debug application ike -1')
    assert classify('show system global | grep alias') == 'piped or compound'
    assert classify('get a; get b') == 'piped or compound'

    # --- builds, captions, selection, in one scripted log
    dated = FGT_STATUS + PLAN + """=== 2026-11-03T07:05:10 fgt-ac-hub1 exit=0
$ get router info bgp summary
fgt-ac-hub1(Primary) $ BGP router identifier 10.1.1.1, local AS number 65001
Neighbor  8.8.8.8  4 65002  bluebird uplink at Acme, ac-hub1 SN FGVMELTM00001234

fgt-ac-hub1(Primary) $ 
=== 2026-11-03T07:05:11 fgt-ac-hub1 exit=3
$ get system performance status
fgt-ac-hub1 $ Unknown action 0
=== 2026-11-03T07:05:12 fgt-ac-hub1 exit=0
$ diagnose debug enable
fgt-ac-hub1 $ 
=== 2026-11-03T07:05:13 fgt-ac-hub1 exit=0
$ show system global | grep alias
fgt-ac-hub1 $     set alias "x"
=== 2026-11-03T07:05:14 fgt-ac-hub1 exit=0
$ config system global
fgt-ac-hub1 $ whatever
=== 2026-11-03T07:05:15 ct:7110 exit=0
$ get system status
ct7110 $ Version: FortiGate-VM64-KVM v7.6.7,build3704,260601 (GA.M)
=== 2026-11-03T07:05:16 fgt-ac-hub1 exit=0
$ get vpn ipsec tunnel summary
fgt-ac-hub1 $ 'T1' 203.0.113.9:0  selectors(total,up): 1/1  rx(pkt,err): 5/0
enc: spi=1 esp=aes key=16 00112233445566778899aabbccddeeff
    set psksecret hunter2hunter2
    set password ENC SH2abcdefghijklmnop==
    mac 00:09:0f:aa:bb:cc

fgt-ac-hub1 $ 
=== 2026-11-03T09:30:00 fgt-ac-hub1 exit=0
$ get router info bgp summary
fgt-ac-hub1 $ short
=== 2026-11-03T09:30:01 fgt-ac-hub1 exit=0
$ get system ha status
fgt-ac-hub1 $ HA Health Status: OK
=== 2026-11-03T09:31:00 fgt-ac-hub1 exit=0
$ get sys ha status
fgt-ac-hub1 $ HA Health Status: OK
=== 2026-11-03T09:32:00 fgt-edge2 exit=0
$ get system global
fgt-edge2 # admin-sport: 443
fgt-edge2 # 
=== 2026-11-03T09:33:00 mystery exit=0
$ get system global
mystery $ admin-sport: 443
""" + FMG_STATUS + """=== 2026-11-03T08:01:00 fmg-core exit=0
$ get system performance
fmg-core $ CPU: 3%
Long: """ + ' 8.8.8.8' + """

fmg-core $ 
=== 2026-11-03T08:02:00 fgt-ac-hub1 exit=0
$ get system a
$ get system b
fgt-ac-hub1 $ alpha
fgt-ac-hub1 $ beta
fgt-ac-hub1 $ 
=== 2026-11-03T08:03:00 fgt-ac-hub1 exit=0
$ get system c
$ get system d
fgt-ac-hub1 $ only one block

fgt-ac-hub1 $ 
"""
    old = """=== 2026-11-02T07:00:00 fgt-edge2 exit=0
$ get system global
fgt-edge2 $ older and much longer
line two
line three
=== 2026-11-02T07:00:01 fgt-ac-hub1 exit=0
$ get system status
fgt-ac-hub1 $ no version line here
"""
    inv = FGT_STATUS.replace('2026-11-03T07', '2026-11-04T07') + """=== 2026-11-04T07:10:00 fgt-ac-hub1 exit=0
$ get system interface physical
fgt-ac-hub1 $ port1 up
"""
    sources = [('dated', '2026-11-02', old), ('dated', '2026-11-03', dated),
               ('inv', 'ac-bgp-test', inv)]
    samples, stats = run(sources, vmids={'fgt-edge2': 5082, 'mystery': 7000})
    by = {(p, s['train'], s['k'], s['p']): s for p, l in samples.items() for s in l}

    # build from status: model, version, build; platform and train from the model
    s = by[('fortios', '7.6', 'get', 'router info bgp summary')]
    assert s['build'] == 'FortiGate-VM64-KVM v7.6.7 build3704' and s['train'] == '7.6'
    assert by[('fortimanager', '7.6', 'get', 'system performance')]['build'] == 'FortiManager-VM64-KVM v7.6.7 build3737'
    # build from the VMID pool when no status was logged; none known -> dropped and counted
    assert by[('fortios', '7.6', 'get', 'system global')]['build'] == 'FortiGate-VM64-KVM v7.6.7 build3704'
    assert stats['dropped: no known build'] == 2, stats   # `mystery`, and a hub read before any status
    assert fallback_build(5093) == ('FortiGate-VM64-KVM', '8.0.2', '0251') and fallback_build(5510) is None
    # newest day wins over an older, longer one; shorter record of a day loses within the day
    assert s['date'] == '2026-11-03', s
    # (the 09:30 `short` is one line; the 07:05 one is longer, so it stays)
    assert 'BGP router identifier' in s['t']
    # selection: failures, bookkeeping, pipes, config, containers, plan/policy all gone
    for gone in ('system performance status',):
        assert ('fortios', '7.6', 'get', gone) not in by
    assert stats['dropped: exit != 0'] == 1 and stats['dropped: debug bookkeeping'] == 1
    assert stats['dropped: piped or compound'] == 1 and stats['dropped: not a read command'] == 1
    assert stats['dropped: policy, plan or container record'] == 2, stats
    # abbreviated verbs and commands share a key: `get sys ha status` and `get system ha status` are two
    # commands as typed, so both stay (nothing is guessed about abbreviations)
    assert ('fortios', '7.6', 'get', 'sys ha status') in by
    # sessions: split at the prompts when attributable, skipped otherwise
    assert by[('fortios', '7.6', 'get', 'system a')]['t'] == 'alpha'
    assert by[('fortios', '7.6', 'get', 'system b')]['t'] == 'beta'
    assert ('fortios', '7.6', 'get', 'system c') not in by
    assert stats['dropped: session output cannot be attributed to commands'] == 1
    # captions: investigation folder; plan within 10 minutes; else lab session; anonymised
    assert by[('fortios', '7.6', 'get', 'system interface physical')]['cap'] == 'site-bgp-test'
    assert s['cap'] == 'demo-plan'
    assert by[('fortios', '7.6', 'get', 'system ha status')]['cap'] == 'lab session 2026-11-03'

    # --- anonymisation: prompts, hostnames, serials, companies, secrets, addresses
    assert s['t'].splitlines()[0].startswith('BGP router identifier 10.1.1.1')   # private stays
    assert '8.8.8.8' not in s['t'] and re.search(r'192\.0\.2\.|198\.51\.100\.|203\.0\.113\.', s['t'])
    assert 'FGVMxxxx1234' in s['t'] and 'FGVMELTM' not in s['t']
    assert 'orp uplink' in s['t'] and 'luebird' not in s['t'] and 'cme' not in s['t']
    assert 'corp uplink at corp, site-hub1 SN' in s['t'], s['t']      # hostname -> site-hub1 only via abbr
    st = by[('fortios', '7.6', 'get', 'vpn ipsec tunnel summary')]['t']
    assert '203.0.113.9' in st, st                                     # RFC 5737 stays
    assert '00112233445566778899' not in st and 'hunter2' not in st and 'ENC' not in st, st
    assert 'set password <masked>' in st and 'key=16 <masked>' in st, st
    assert '00:09:0f:xx:xx:xx' in st and 'aa:bb:cc' not in st, st
    assert st.splitlines()[-1] != '' and 'fgt-ac' not in st
    st2 = json.dumps(samples)
    assert 'fgt-ac-hub1' not in st2 and 'Hostname: FGT' in st2
    gs = by[('fortios', '7.6', 'get', 'system global')]['t']
    assert gs == 'admin-sport: 443', gs                                # `#` prompts, both ends
    an = Anonymiser({'fgt-a': 'fortios', 'fmg-b': 'fortimanager'})
    assert an.prompt_line('fgt-a (root) #', 'fortios', first=True) == ('FGT (root) #', '')
    assert an.prompt_line('fmg-b $ x', 'fortimanager', last=True) == ('FMG $', 'x')
    assert an.prompt_line('Total # of things', 'fortios') is None      # not a prompt mid-output
    assert an.hostnames('on fgt-a and fmg-b, not fgt-ab', 'fortios') == 'on FGT and FMG, not fgt-ab'
    assert an.serials('FMG-VM0123456789 FS1E48T123456789 FG70GPT22000123') \
        == 'FMG-xxxx6789 FS1Exxxx6789 FG70xxxx0123'
    assert an.serials('Serial-Number: FGVMELTM00001234') == 'Serial-Number: FGVMxxxx1234'
    assert an.serials('Serial Number : ABC12345678') == 'Serial Number : xxxx5678'
    assert an.serials('Serial: ') == 'Serial: ' and an.serials('FortiGate-VM64-KVM FGVMxxxx1234') \
        == 'FortiGate-VM64-KVM FGVMxxxx1234'
    assert an.company('Kestrel, Bluebird and Acme; fips-cc; bl-1 AC_x') == 'corp, corp and corp; fips-cc; site-1 site_x'
    ips = Anonymiser.addresses
    for keep in ('10.1.2.3', '172.16.0.1', '192.168.1.1', '192.0.2.5', '198.51.100.7', '203.0.113.7',
                 '100.64.0.1', '169.254.1.1', '127.0.0.1', '224.0.0.5', '255.255.255.0', '0.0.0.0'):
        assert ips(keep) == keep, keep
    a1, a2 = ips('8.8.8.8'), ips('x 8.8.8.8 y 1.1.1.1')
    assert a1 != '8.8.8.8' and a1 in a2 and ips('7.6.7.1234') == '7.6.7.1234'
    assert ips('8.8.8.8') == a1 and ips('1.1.1.1') != a1
    # mask: idempotent, ENC marker gone
    m1 = mask('set psksecret abc\nset password ENC AAAABBBBCCCC==\nkey=32 0011223344556677')
    assert mask(m1) == m1 and 'ENC' not in m1 and 'abc' not in m1, m1
    assert mask('set ssh-public-key1 "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKnvPQ0IDopaAM0 me@host"') \
        == 'set ssh-public-key1 "ssh-ed25519 <masked>"'
    assert 'fips-cc' in an.company('set fips-cc enable')
    assert Anonymiser(abbrs=('cc',)).company('78:CC:A5 cc-x') == '78:CC:A5 site-x'
    assert ips('Permanent Hwaddr:bc:24:11:97:46:7d') == 'Permanent Hwaddr:bc:24:11:xx:xx:xx'
    fp = '50:00:00:00:03:92:a1:85:79:f5:e7:13:5a:00'
    assert ips(fp) == fp

    # --- refuse to write: a leak that survives the pipeline stops the run, naming the record
    class Leaky(Anonymiser):
        def company(self, s):
            return s
    try:
        run([('dated', '2026-11-03', dated)], anon_factory=Leaky)
    except Refuse as e:
        assert '2026-11-03T07:05:10' in str(e) and 'company name' in str(e), e
    else:
        raise AssertionError('a surviving company name must refuse')
    assert Anonymiser({'h-1': 'fortios'}).problems('Acme FGVMELTM00001234 key=16 00112233445566778899') \
        == ['company name', 'secret pattern', 'serial']

    # --- determinism: same input, same bytes, whatever the source order
    one = dump(run(sources, vmids={'fgt-edge2': 5082})[0])
    two = dump(run(list(reversed(sources)), vmids={'fgt-edge2': 5082})[0])
    assert one == two, 'output depends on source order'
    d = json.loads(one)
    assert list(d) == ['_comment', 'builds', 'samples'] and d['builds'] == sorted(d['builds'])
    assert set(d['builds']) == {'FortiGate-VM64-KVM v7.6.7 build3704', 'FortiManager-VM64-KVM v7.6.7 build3737'}
    assert list(d['samples']['fortios'][0]) == ['k', 'p', 'c', 't', 'cap', 'build', 'train', 'date']
    # a cap: more than 60 lines is cut with a `...` line
    long = "=== 2026-11-03T07:06:00 fgt-ac-hub1 exit=0\n$ get big\nfgt-ac-hub1 $ " + '\n'.join(
        f'line {i}' for i in range(100)) + "\n\nfgt-ac-hub1 $ \n"
    ls, _ = run([('dated', '2026-11-03', FGT_STATUS + long)])
    t = [s for s in ls['fortios'] if s['p'] == 'big'][0]['t'].split('\n')
    assert len(t) == CAP_LINES + 1 and t[-1] == '...' and t[0] == 'line 0'
    # derive the abbreviations and companies the lab config uses
    n, a = derive_names('[sets.zeta]\ntier = "company"\n# fgt-zz-hq, fgt-ac-x\n')
    assert 'zeta' in n and 'zz' in a and 'ac' in a and 'bl' in a and 'acme' in n
    assert clean_output(['a', '--More--', '', 'b', '', 'c'], Anonymiser(), 'fortios') == 'a\nb\n\nc'
    print('import_lab selftest: ok')


# ---- main -------------------------------------------------------------------------------
def main(argv):
    if '--selftest' in argv:
        selftest()
        return 0
    lab = DEFAULT_LAB
    if '--lab' in argv:
        if argv.index('--lab') + 1 >= len(argv):
            print('usage: import_lab.py [--lab PATH] [--report | --selftest]', file=sys.stderr)
            return 2
        lab = os.path.expanduser(argv[argv.index('--lab') + 1])
    sources, vmids, raw = read_lab(lab)
    load_lab_mask(lab)
    names, abbrs = derive_names(raw, lab)
    try:
        samples, stats = run(sources, vmids, names=names, abbrs=abbrs)
    except Refuse as e:
        print(f'REFUSING to write {os.path.basename(OVERLAY)}: {e}', file=sys.stderr)
        return 1
    if '--report' in argv:
        report(samples, stats)
        return 0
    with open(OVERLAY, 'w') as f:
        f.write(dump(samples))
    report(samples, stats)
    print('wrote', os.path.relpath(OVERLAY, ROOT))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
