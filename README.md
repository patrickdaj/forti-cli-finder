# Forti CLI Finder

A keyboard-first lookup for the Fortinet CLI. Type the way you would on the box
(`conf sys ha over`, `diag switch mclag`); prefixes expand, help text and sample output are
searched too. The left side is a running CLI, the right side is an inspector that composes
a config block you can copy.

Static site, no server, no database: `site/index.html` plus one JSON bundle per platform in
`site/data/`.

## Run it

    cd site && python3 -m http.server 8000      # then open http://localhost:8000

Opening `index.html` from disk will not load the data. Any static host works; see
[Deploying](#deploying) for GitHub Pages.

## Keys

| Where | Key | Does |
|---|---|---|
| prompt | type | live `?`-style listing above the prompt |
| prompt | up / down | move through the listing, then on past the top into the scrollback |
| prompt | enter | open in the inspector, keep it in the scrollback, move focus there |
| prompt | tab | complete the path (extra words stay as a parameter filter); tab again moves to the inspector |
| prompt | `/` | slash commands (below) |
| prompt | ctrl/cmd + enter | copy the block |
| prompt | ctrl + L | clear the scrollback |
| inspector | up / down (j / k) | move between parameters |
| inspector | left / right | cycle an option value |
| inspector | `/` | jump to a parameter by name: filters as you type, up/down step the matches, enter lands the cursor on one |
| inspector | `e` | add the fields the guides usually set (the 9 a firewall policy needs) |
| inspector | space | add to or drop from the block |
| inspector | enter | edit a number or string (enter saves, esc cancels) |
| inspector | c | copy the block |
| inspector | x / u | clear the block, undo the clear |
| inspector | a | matching or all parameters |
| inspector | n / p | next / previous sample output |
| inspector | tab or esc | back to the prompt |

Arguments to `diagnose`, `execute` and `get` commands are positional and fillable the same
way parameters are: `diagnose sniffer packet` gives you `<interface> <filter> <verbose>
<count>`, and the block keeps the placeholders for any you skip, so
`diagnose sniffer packet port1 "host 10.0.0.5 and port 443" 4 0` composes without typing.

On a big table (`config firewall policy` has 186 parameters) `/` is how you work: `/dstaddr`
enter, set it, `/dstintf` enter, set it, and so on without scrolling. While the bar is open
the list filters to matches, up/down steps between them, enter picks one and restores the
full list with the cursor on your choice, esc cancels. Values are quoted the way `show`
prints them: string types quoted, numbers, options and addresses bare.

Slash commands: `/fgt /fsw /faz /fmg /all` (platform), `/config /diag /exec /get /show /any`
(command type), `/ver` (list and pick a firmware build), `/fgt@8.0.1`, `/reset`, `/clear`,
`/help`. They combine: `/fsw diag`, `/fgt fsw show`.

## The data

Everything is parsed from Fortinet's public documentation and every entry keeps the guide
and page it came from.

| Bundle | Built from |
|---|---|
| `fortios.json` | FortiOS 7.6.7 CLI Reference |
| `fortios-8.0.json` | FortiOS 8.0.1 CLI Reference |
| `fortiswitch.json` | FortiSwitchOS 7.6.7 CLI Reference |
| `fortianalyzer.json` | FortiAnalyzer 7.6.7 CLI Reference |
| `fortimanager.json` | FortiManager 7.6.7 CLI Reference |

Sample output is mined separately from eight guides plus course material transcribed by
hand. Which guides, why those and not others, and what coverage actually looks like:
[docs/sources.md](docs/sources.md).

Where every byte comes from, how to rebuild from an empty directory, and how to add a
firmware version when Fortinet ships one: [docs/pipeline.md](docs/pipeline.md). Start
with `make`, which lists every step with what it costs.

### Rebuild it

Needs `python3` and `pdftotext` (poppler: `brew install poppler` /
`apt install poppler-utils`). The PDFs are ~500MB and are not in the repo.

    python3 tools/discover_sources.py    # resolve sources.json -> sources.lock.json
    python3 tools/fetch_sources.py       # download into sources/
    ./build.sh                           # parse and bundle, about 60s

`sources.json` lists documents by their page on docs.fortinet.com, not by S3 link, because
those links carry a UUID that changes on every re-release. `discover_sources.py` resolves
them and writes `sources.lock.json`, which is committed — so a build is reproducible, and
`--check` tells you whether Fortinet has published anything new. That is all the scheduled
workflow needs.

### Pipeline

1. `tools/parse_fos.py` — the FortiOS CLI Reference (generated from the command tree) into
   sections with syntax and parameter tables. Also folds element rows: the reference prints
   a list-valued parameter over two rows (`srcaddr` then `<name>`) with the description and
   size wrapping across both, which is one parameter, not two.
2. `tools/parse_hand.py` — the hand-written references (FortiSwitchOS, FortiAnalyzer,
   FortiManager): syntax blocks, variable tables, examples.
3. `tools/build_bundles.py` — one compact JSON bundle per platform into `site/data/`.
4. `tools/extract_outputs.py` — finds `# command` prompts in a guide and the output under
   them, captioned by the procedure step that introduces it. The page footer is learned per
   document, so it works on any Fortinet guide.
5. `tools/attach_outputs.py` — attaches each sample to the longest matching command.
   Annotated course samples rank first, then current firmware over older.

`tools/prospect.py` measures what a candidate guide would add before you commit to it.

### Adding a source

Add it to `sources.json` under `output` with a `target` (which bundles its samples may
attach to) and a `rank` (lower wins when two guides show the same command), then
re-run discovery, fetch and build. Measure it first:

    python3 tools/prospect.py /document/fortigate/7.6.7/new-features

### Adding a firmware build

One entry in `sources.json` under `cli`, with a `bundle` naming its own file and a `ver`
and `src` for the `/ver` listing:

    { "key": "fos-cli-74", "product": "fortios",   "parser": "fos",  "short": "FGT", "label": "FortiOS 7.4.12",
      "ver": "7.4.12", "src": "CLI Reference",
      "bundle": "fortios-7.4",
      "doc": "/document/fortigate/7.4.12/cli-reference",      "title": "FortiOS 7.4.12 CLI Reference", "expect": "FortiOS-7.4.12-CLI_Reference" }

`product` says which platform it is a build of; `bundle` says which file it is written to.
Leave `bundle` out and it defaults to `product`, which is why the original four bundles
are still `fortios.json` and friends.

Put the new entry **after** its siblings: a platform's first entry is the build you get by
default. Then add the new bundle to the `target` list of every `output` and `hand` source
whose samples should reach it -- the guides are version-specific but a 7.6 guide is still
evidence about an 8.0 command, and each sample names the guide it came from, so the page
says which firmware the output was captured on.

Re-run discovery, fetch and build. `tools/stamp_build.py` regenerates the `PRODUCTS` list
in `site/index.html` from `sources.json`, so there is nothing to edit there, and
`tools/check_bundles.py` fails the build if the two ever disagree.

Measure before you add: a reference that duplicates one you already ship costs a bundle
and gives the `/ver` picker nothing to distinguish. Parse it to a scratch tree and diff
the section and argument counts against the bundle you have.

## Deploying

Two workflows:

- **`.github/workflows/pages.yml`** deploys `site/` to GitHub Pages on push to `main`. The
  built bundles are committed, so a deploy is a file copy and takes seconds.
- **`.github/workflows/refresh.yml`** runs weekly, asks docs.fortinet.com whether any
  source document has been re-released, and if so rebuilds and opens a pull request. It
  does not push to `main` on its own: a Fortinet re-release can change the parse, and the
  data diff is worth a look.

To turn Pages on: Settings → Pages → Source → GitHub Actions.

The bundles total ~7.5MB and are committed on every refresh, so the repo grows by roughly
that much each time the data changes. At a handful of refreshes a year that is fine; if it
becomes a problem, build in CI instead and drop `site/data` from the repo — at the cost of
downloading 500MB of PDFs on every deploy.

### Which fields a table actually needs

Nothing in the CLI Reference marks a field required -- 42 of 13336 descriptions say
"required" and all of them are prose. FortiOS only objects at `end`.

What does exist is evidence. The guides configure these tables thousands of times, and
`tools/extract_config_examples.py` mines those blocks -- 3786 of them in the FortiOS
Administration Guide alone, which the output extractor had been discarding as "not sample
output". Each parameter gets `fq`, the share of that table's examples which set it,
counted once per example and only where there are at least five to count.

For `config firewall policy`, across 223 examples: dstintf 87%, schedule 87%, action 85%,
srcaddr 84%, service 83%, dstaddr 81%, srcintf 81%, nat 56%, name 54% -- the nine fields
every admin knows, arrived at from Fortinet's own examples. `e` in the inspector adds them
all. Fields at 50% or more show their percentage in the row.

It also gives FortiOS worked examples, which the CLI Reference ships none of: 714 of them
across 317 tables.

## What the CLI Reference does not cover

Worth knowing before you go looking for a bug that is not there. Fortinet generates the
7.6.x FortiOS CLI Reference from the configuration tree, so:

- `config` is documented exhaustively: 625 tables, 16477 parameters with types, defaults,
  ranges and option values.
- The `diagnose` and `execute` trees are *enumerated* -- 5100 command names -- but most
  carry no arguments. 3113 non-config commands have none, and for all but 11 of them the
  reference's own syntax line is just the command, so that is what Fortinet documents, not
  something lost in parsing. `diagnose sys session filter` is the usual surprise: the box
  takes `src`, `dst`, `proto` and friends; the reference prints the bare command.
- It contains **no `get` and no `show` commands at all**.

That last one is not FortiOS-specific, and it is worth seeing laid out:

| platform | config tables | `show` documented | `get` documented | of those, config views |
|---|---:|---:|---:|---:|
| FortiOS | 625 | 0 | 0 | 0 |
| FortiSwitch | 128 | 0 | 105 | 43 |
| FortiAnalyzer | 85 | 0 | 54 | 37 |
| FortiManager | 82 | 0 | 53 | 36 |

**No platform documents a single `show` command.** The three hand-written references do
document `get`, and 62 of FortiSwitch's are exactly the diagnostic family FortiOS lacks
(`get router info bgp cidr-only`, `get hardware cpu`), with their arguments -- so the gap
is an artefact of generating FortiOS's reference from the config tree, not Fortinet policy.

`tools/derive_getshow.py` closes half of it. Wherever `config X` exists, `show X` and
`get X` are valid and display what it sets, narrowed by the table's key if it has one, so
those are derived: `show firewall policy [<policyid>]`. They are badged *derived* in the
listing and say where they came from, and they are skipped wherever a reference or a guide
already covers the command. It runs after sample attachment, so a guide's
`get system ha status` still gets its own entry rather than being swallowed by a derived
`get system ha` that merely prefixes it.

What is deliberately **not** derived is the diagnostic read tree -- `get router info bgp
network`, `get system performance status`. Those are not views of a config object; they
have their own arguments and nothing in the FortiOS reference describes them. Inventing
them would mean inventing their syntax. They stay as whatever the guides happen to show,
which is why `get router info bgp network` has sample output but no `<network>` to fill in.

The inspector says which of these applies rather than showing an empty pane.

## Notes

- The content is Fortinet's documentation, reproduced with attribution and page numbers.
  Check your own policy before publishing it publicly.
- `site/index.html` is one self-contained file (HTML, CSS and JS); fonts load from Google
  Fonts.
- Bundles are served as plain JSON; GitHub Pages gzips them in transit (5.5MB → ~600KB).
