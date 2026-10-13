# The pipeline

Where every byte in `site/data/*.json` comes from, and how to rebuild all of it from an
empty directory. If you can follow this to a working site, you can add FortiOS 8.1 the
day it ships — that is the test this document exists to pass.

- [From scratch](#from-scratch)
- [Where the data comes from](#where-the-data-comes-from)
- [Adding a firmware version](#adding-a-firmware-version)
- [Adding a guide](#adding-a-guide)
- [A device capture](#a-device-capture)
- [What is checked, and what is not](#what-is-checked-and-what-is-not)
- [What this pipeline cannot do](#what-this-pipeline-cannot-do)

Run `make` for the same list with timings and costs. Every command below is a `make`
target; the scripts underneath take the same arguments if you prefer them.

## From scratch

```bash
git clone https://github.com/patrickdaj/forti-cli-finder && cd forti-cli-finder
brew install poppler          # or: apt install poppler-utils
make all                      # sources -> fetch -> build, ~12 minutes the first time
make serve                    # http://localhost:8000
```

That is the whole thing — and no FortiGate is involved. The pipeline reads Fortinet's
published PDFs over HTTP and parses them offline; a live device is optional and only
appears in [A device capture](#a-device-capture) below. `python3` and `pdftotext` are the only dependencies and they
are meant to stay the only ones: the bundles ship to a browser from a static host, so a
dependency here is a dependency forever.

What `make all` does, in order:

| step | what it does | cost |
|---|---|---|
| `make sources` | asks docs.fortinet.com what PDF each document in `sources.json` resolves to today, writes `sources.lock.json` | ~20s |
| `make fetch` | downloads exactly what the lock file names, into `sources/` | ~10min, ~550MB |
| `make build` | `pdftotext` → parse → bundle → attach samples → derive get/show → stamp → check | ~60s |

`sources/*.pdf` is gitignored. `site/data/*.json` is **committed**, because GitHub Pages
serves the files as they are rather than building them — so the bundles in the repo must
match what `make build` produces. `make build` is deterministic; confirm with
`git diff --stat site/data` after a rebuild and expect nothing.

## Where the data comes from

Two files decide everything. `sources.json` is the input (which documents, and what each
one is for); `sources.lock.json` is the record (which exact PDF each build read).

```
sources.json
  cli[]     parsed into the command tree -- these ARE the bundles
  output[]  mined for "# command" + output samples and for config examples
  hand[]    course material transcribed by hand, same shape as output[]
```

A `cli` entry becomes one bundle file:

```json
{ "key": "fos-cli", "product": "fortios",   "parser": "fos",  "short": "FGT", "label": "FortiOS 7.6.7",
  "ver": "7.6.7", "src": "CLI Reference + Administration Guide",
  "doc": "/document/fortigate/7.6.7/cli-reference", "title": "...", "expect": "FortiOS-7.6.7-CLI_Reference" }
```

- `product` — which platform it is a build of (FortiGate, FortiSwitch…).
- `bundle` — which **file** it is written to. Omit it and it defaults to `product`, which
  is why the original four are still `fortios.json` and friends. These are two different
  things, and conflating them is what stopped two firmware builds coexisting.
- `ver`, `src` — how `/ver` labels the build on the page.
- `doc` — the page on docs.fortinet.com. The **version is pinned into this path**. That
  one fact drives the whole "how do we add 8.1" answer below.
- `expect` — a substring of the PDF filename. If Fortinet serves something else, the
  build stops rather than silently parsing the wrong document.

What each tool contributes to a finished entry:

| field | from | by |
|---|---|---|
| `k`, `p`, `d`, `pg`, `s` | the CLI Reference PDF | `parse_fos.py` (generated reference) / `parse_hand.py` (hand-written ones) |
| `x[]` parameters, `ty`, `sz`, `df`, `o[]` | the same PDF's Variable tables | the same parsers |
| `o[]` sample output | the guides in `output[]`/`hand[]` | `extract_outputs.py` → `attach_outputs.py` |
| `e[]` worked examples, `fq` frequency | the same guides | `extract_config_examples.py` → `attach_config_examples.py` |
| `show`/`get` for every config table | derived, not read | `derive_getshow.py` |
| `mi` model lists, `BUILD` hash | the reference / the bundles | `build_bundles.py`, `stamp_build.py` |

Three things are worth knowing because they are judgement calls, not mechanics:

**Derived `get`/`show`.** The FortiOS CLI Reference is generated from the config tree and
documents only `config`. But wherever `config firewall policy` exists, `show firewall
policy` and `get firewall policy` are valid and show what it sets — that relationship is
exact, so `derive_getshow.py` writes them and marks them `dv:1` so the page can say so.
The *diagnostic* read tree (`get router info bgp neighbors`) is **not** derivable and is
deliberately not invented.

**Samples can appear under a build they were not written for.** A platform may ship more
than one firmware build while the guides we mine are version-specific, so a `target` list
may name several builds and a sample attaches to each build whose tree contains the
command. Provenance travels with it — a capture from the 7.6 study guide shown under the
8.0 build still prints its own source line. See `docs/sources.md`.

**Worked examples are pooled per bundle and filtered by `target`.** A table name is not
unique across platforms (`system global` exists on all four), so an example only reaches
a bundle its guide actually targets.

## Adding a firmware version

This is the question the pipeline exists to answer well.

**1. Find out it exists.** `make sources` will never tell you — it re-resolves the paths
already in `sources.json`, so it catches Fortinet re-releasing 7.6.7 in place and nothing
else. A new version is a path nobody has looked at:

```bash
make versions
```

reads one sitemap listing every product/version Fortinet publishes and prints what is
newer than what we ship, with the PDF each candidate path actually serves.

> **Read the filename.** Fortinet redirects an unpublished version to the nearest build.
> `/document/fortiswitch/7.6.8/fortiswitchos-cli-reference` resolves — and serves
> `FortiSwitchOS-7.6.7_CLI_Reference.pdf`. That is not a new document and adding it would
> ship a duplicate under a wrong label.

**2. Measure it before you commit to it.** More sections is not automatically better, and
a second near-identical bundle gives the `/ver` picker nothing to distinguish while
doubling that platform's data.

```bash
mkdir -p work/probe/81 && curl -o work/probe/81/fos81.pdf '<the URL make versions printed>'
pdftotext -layout work/probe/81/fos81.pdf work/probe/81/fos81.txt
python3 tools/parse_fos.py work/probe/81/fos81.txt work/probe/81/fos81.tree.json fortios
```

Then compare its section and argument counts against the bundle you already ship. The
rule we used for 8.0: add it when it gains argument lists or adds sections without
removing many; skip it when the parse yields *fewer* sections, which means the parser
needs work on that document first. `work/probe/80/decision.md` is the worked example —
FortiOS 8.0.1 was added (+540 commands, +228 argument lists), the other three platforms
were skipped at deltas under 2%.

**3. Add one entry to `sources.json`.** After its sibling, because a platform's **first**
entry is the build you get by default:

```json
{ "key": "fos-cli-81", "product": "fortios",   "parser": "fos",  "short": "FGT", "label": "FortiOS 8.1.0",
  "ver": "8.1.0", "src": "CLI Reference",
  "bundle": "fortios-8.1",
  "doc": "/document/fortigate/8.1.0/cli-reference", "title": "FortiOS 8.1.0 CLI Reference", "expect": "FortiOS-8.1.0-CLI_Reference" }
```

**4. Point the sample sources at it.** Add `"fortios-8.1"` to the `target` list of every
`output` and `hand` entry whose samples should reach it, or the new bundle ships with no
sample output at all.

**5. Build.**

```bash
make sources && make fetch && make build
```

`stamp_build.py` regenerates the `PRODUCTS` list in `site/index.html` from `sources.json`,
so there is nothing to edit in the page, and `check_bundles.py` fails the build if the two
ever disagree. `/ver` lists the new build and `/fgt@8.1.0` picks it.

**6. Read the diff.**

```bash
make diff
```

`git diff` on a minified bundle says "1 insertion, 1 deletion" whatever happened inside.
`make diff` says it in commands: added, removed, arguments gained or lost, samples gained
or lost. A data-refresh pull request is unreviewable without it.

## Adding a guide

A guide contributes sample output and worked config examples, not commands. Most
contribute almost nothing — six measured candidates yielded 13 new commands between them
— so measure first:

```bash
make probe DOC=/document/fortigate/8.0.1/administration-guide
```

If it pays, add it to `sources.json` under `output` with a `target` (which bundles its
samples may reach) and a `rank` (lower wins when two guides show the same command), then
`make sources && make fetch && make build`. `docs/sources.md` records which guides are in,
which were measured and rejected, and why.

## A device capture

**Optional, and the only part of this document that involves a device.** Nothing above
needs one: `make all` builds every bundle from Fortinet's published PDFs over HTTP, and
`make check` runs offline. If you have no FortiGate, skip this section and the pipeline
is complete without it.

What a device buys you is a second, independent source. Everything above is Fortinet's
documentation; a FortiGate will also describe itself, and it is the only source that is
exact for a firmware *build*:

```
FGT-1 # tree
```

You can paste that into a file by hand, or collect it automatically:

```bash
cp .env.devices.example .env.devices && chmod 600 .env.devices   # then edit it
make capture                      # every device; DEV=fgt1 for one
make tree FILE=work/live/fortios-7.6.4-2731/capture.txt --record
```

`.env.devices` is plain dotenv (`DEVICES=fgt1,fsw1`, then `FGT1_HOST=...`). It is
gitignored, and `capture_device.py` refuses to run if it is group- or world-readable.
Prefer `<NAME>_KEY` or your ssh-agent; `<NAME>_PASS` works and goes straight to the
device's own prompt over the pty, never into a log, a file or an argument list.

The walk runs `get system status`, `tree`, and `<command> ?` for every command the
bundle ships with no arguments — 3104 of them on FortiOS 7.6. It is all reads and it
**never enters config mode**, so it runs happily under an accprofile with
`set cli-config disable`: the device enforces read-only rather than this script
promising to. Field-level help for config tables would need config mode, and is
deliberately not collected.

### Config-mode help, and why `abort` makes it safe

`make capture CONFIG=1` also collects field-level help, which needs config mode. The
safety is structural rather than a promise:

```
config <table>              enter
edit zz-cli-finder-probe    a context for `set ?`, distinctive on purpose
set ?                       the field list with help, options and ranges
abort                       discard the block -- never `end`
```

`abort` leaves a config block discarding everything done inside it, so nothing the walk
types is ever committed. That is what makes probing arbitrary tables reasonable: you can
enter any context and do anything within it, provided you always leave by aborting.

Around the whole walk, two device-native guards:

- **`execute backup config flash "cli-finder pre-walk"`** — a restorable revision on the
  device itself. No TFTP server, and no copy of your configuration (with its secrets) on
  the machine running this.
- **`diagnose sys ha checksum show`** before and after. Equal checksums prove the walk
  wrote nothing. This is why we do not diff `show full-configuration`: that would mean
  writing your entire config to disk in order to check it had not been touched.

If the checksums differ the script says so loudly and prints
`execute revision list config` / `execute restore config flash <revision>`.

The same discipline is what would let the inspector one day *validate* a composed block
against a real device — paste it inside a config block, read the parse errors, abort —
but that is a separate feature and is not built.

Budget, measured rather than guessed: 5,743 round trips for the tree plus the bare
commands — 8 minutes at 80ms per round trip, 29 at 300ms. Adding per-field option and
default help for all 13,336 config fields would be 19,079 round trips, 25 to 95 minutes,
and would need config mode. The config walk as built is 2,500 round trips for FortiOS
— 3 minutes at 80ms, 13 at 300ms. All of it is an unattended coffee, not a project.

One thing nobody can know without a device: whether FortiOS answers `?` through an ssh
pty at all. It acts on the keystroke rather than on a newline, which is why this uses a
pty and not a pipe. The script tries both spellings, reports which answered, and gives
up after 20 unanswered commands — the tree is still captured and still useful.

Then:

```bash
make tree FILE=work/live/fortios-7.6.4-2731/capture.txt
```

`tree` carries what the CLI Reference does not: the arguments of `diagnose` and `execute`
commands, integer ranges and string lengths on every config field, each table's mkey, and
the `<Enter> or` marker that means an argument is optional. It carries no descriptions, no
defaults, no option values, no sample output — and `get router info *` is opaque to it,
because that subtree belongs to the routing daemon. The tree is the skeleton; the PDF is
the flesh; they join on the command path.

A capture identifies itself. Beginning it with `get system status` means the version
banner names the build, so `make tree` matches it to a bundle on its own — same platform,
same major.minor — and refuses across a minor boundary rather than guess. A 7.6.4 box
describes the 7.6 bundle and says nothing trustworthy about 8.0.

`captures.json` is the committed record of what each bundle has been measured against:
model, firmware, build, command count, content hash, date. Never a serial, never a
hostname, never an IP — those stay in `work/live/`, which is gitignored. Write it with
`python3 tools/parse_tree.py <capture> --record`.

Today `make tree` **reports**; it does not write into the bundles. Its value right now is
as ground truth: every disagreement between a 7.6 device and our parsed 7.6.7 bundle is
either a parser bug or a documentation error, and before this there was nothing to measure
against. The column to read is "we ship fewer args".

The parser is pinned by `python3 tools/parse_tree.py --selftest`, which runs as part of
`make check` against `tools/testdata/tree-sample.txt` — a fixture built from real captured
lines, including the awkward ones (a mkey declared inline, a sibling connector aligned to
the inline `--`, parentheses inside a field name, a line the terminal wrapped).

## What is checked, and what is not

`make check` (also the last step of `make build`) asserts:

- one bundle per `cli` entry, and bundle ids and names well formed;
- no two entries writing to the same bundle, no two builds claiming one version;
- every `target` naming a bundle that exists — a typo stops the build and names the source;
- no duplicate derived `get`/`show` paths;
- worked examples not lopsided across builds of one platform, which is how a shared
  example pool starving the second build shows up;
- `index.html`'s generated `PRODUCTS` list agreeing with `sources.json`, including no
  stale entries.

There is no test framework. `check_bundles.py` and three `--selftest`s are the tests,
and the bundles are the thing worth asserting about:

- `parse_tree.py --selftest` — the tree parser against a committed fixture;
- `capture_device.py --selftest` — the device crawl against a scripted box that hangs up
  on cue, which is how we know a crawl resumes and reconnects without a lab to try it in;
- `parse_hand.py --selftest` — the hand-written-reference parser against real syntax
  lines from the FortiSwitch, FortiManager and FortiAnalyzer documents.

`parse_hand.py` additionally refuses to finish if any command it produced is in neither
its source document nor a documented choice. That is the one assertion that matters most
here: a reference that invents commands is worse than a thin one.

### The whole thing rebuilds byte for byte

The strongest check is the cheapest, and it is the one that proves this document is not
fiction. Clone the repo somewhere clean, put the PDFs where it expects them, and build:

```
git clone <this repo> /tmp/check && cd /tmp/check
rm -rf sources && ln -s /path/to/your/sources sources   # or: make fetch
make build
```

Every file under `site/data/` and `site/index.html` must come out byte-identical to the
committed ones. Measured on 2026-10-12 at commit `a4c33c9`: all five bundles and
`index.html` identical, and the build touched nothing else. That one command proves four
things at once — every tool needed is committed, the build is deterministic, the
committed data really is what the pipeline produces rather than something hand-edited
since, and a new machine can reproduce it.

The same invariant holds in place: after `make build`, `git diff --stat site/` is empty
unless an input actually changed.

Not checked, and worth your eyes: whether a parse is *correct*. The counts can be right
while the content is wrong. `make diff` and `make tree` exist for that, and both want a
human reading them.

## What this pipeline cannot do

Stated plainly so nobody rediscovers it:

- **`get router info bgp neighbors` and its family.** The generated CLI Reference
  documents no diagnostic `get` tree, and a device's `tree` does not expand it either. All
  46 `get router info *` entries we ship have empty syntax and no arguments. Closing this
  needs either the hand-written `get` chapter from the 5.6-era CLI Reference (it exists,
  pp. 1071–1129, and was dropped after 6.0) or `?` against a live device.
- **Arguments for 3113 non-config FortiOS commands** (3104 if you exclude `show`).
  The reference prints the bare command. A tree
  capture fixes part of this; `?` on a device fixes more.
- **Required vs optional arguments — and neither device source can tell us.** This was
  measured rather than assumed, so here is the evidence, to save the next person the
  trip:
  - `?` does not answer it. Across 1,938 crawl records from a FortiGate, `<Enter>`
    (the box saying "this command is complete as typed") **never once** co-occurred with
    an argument or a sub-command: the four observed shapes are `<Enter>` alone (1,618),
    sub-commands alone (199), arguments alone (112), and arguments with sub-commands (9).
    `?` prints either "you may press Enter" or "here are your choices", never both, so
    the absence of `<Enter>` beside an argument says nothing about whether that argument
    is required. Inferring requiredness from it would have labelled 123 commands
    "required" on no evidence.
  - `tree` answers it for 55 commands and no more. It has an explicit marker —
    `<Enter>|<passwd>`, "press Enter or give a passwd" — and it means optional. But its
    ABSENCE does not mean required: `diagnose sniffer packet` lists six positional
    arguments with no marker on any of them, and all but the first are plainly
    omittable (`diagnose sniffer packet port1` runs).
  - What is left is the documents' own notation, which is honest but three-valued:
    `[x]` optional, `{a | b}` a mandatory choice, `<x>` a typed variable that claims
    nothing either way — and the generated FortiOS reference almost never brackets
    anything. The parsers keep that notation verbatim inside the argument NAME, so the
    page already shows `[<cmd_cue>]` with its brackets; what is missing is not the
    information but a machine-readable flag, and for `<x>` there is nothing to flag.

  The inspector works without it: arguments are emitted positionally up to the last one
  you filled in, so skipping a trailing argument does the right thing regardless.
- **Sample output coverage.** Thin, and unevenly: FortiAnalyzer ships 9 commands with
  output, FortiManager 7.
- **Anything about a device's actual configuration.** Nothing here reads one, and the
  capture flow is deliberately limited to firmware metadata.
