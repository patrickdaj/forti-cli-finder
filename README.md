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
| prompt | up / down | move through the listing (the inspector follows) |
| prompt | enter | open in the inspector, keep it in the scrollback, move focus there |
| prompt | tab | complete the path (extra words stay as a parameter filter); tab again moves to the inspector |
| prompt | `/` | slash commands (below) |
| prompt | ctrl/cmd + enter | copy the block |
| prompt | ctrl + L | clear the scrollback |
| inspector | up / down (j / k) | move between parameters |
| inspector | left / right | cycle an option value |
| inspector | space | add to or drop from the block |
| inspector | enter | edit a number or string (enter saves, esc cancels) |
| inspector | c | copy the block |
| inspector | x / u | clear the block, undo the clear |
| inspector | a | matching or all parameters |
| inspector | n / p | next / previous sample output |
| inspector | tab or esc | back to the prompt |

Slash commands: `/fgt /fsw /faz /fmg /all` (platform), `/config /diag /exec /get /show /any`
(command type), `/ver` (list and pick a firmware build), `/fgt@7.6.4`, `/reset`, `/clear`,
`/help`. They combine: `/fsw diag`, `/fgt fsw show`.

## The data

Everything is parsed from Fortinet's public documentation and every entry keeps the guide
and page it came from.

| Bundle | Built from |
|---|---|
| `fortios.json` | FortiOS 7.6.4 CLI Reference |
| `fortiswitch.json` | FortiSwitchOS 7.6.2 CLI Reference |
| `fortianalyzer.json` | FortiAnalyzer 7.6.5 CLI Reference |
| `fortimanager.json` | FortiManager 7.6.5 CLI Reference |

Sample output is mined separately from eight guides plus course material transcribed by
hand. Which guides, why those and not others, and what coverage actually looks like:
[docs/sources.md](docs/sources.md).

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

    python3 tools/prospect.py /document/fortigate/7.6.4/new-features

### Adding a firmware build

Build its bundle under a new name (`fortios-7.4.8.json`) and add it to that platform's
`vers` list at the top of the script in `site/index.html`:
`{v:'7.4.8', f:'fortios-7.4.8', src:'CLI Reference'}`. `/ver` then lists it and `/fgt@7.4.8`
picks it.

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

## Notes

- The content is Fortinet's documentation, reproduced with attribution and page numbers.
  Check your own policy before publishing it publicly.
- `site/index.html` is one self-contained file (HTML, CSS and JS); fonts load from Google
  Fonts.
- Bundles are served as plain JSON; GitHub Pages gzips them in transit (5.5MB → ~600KB).
