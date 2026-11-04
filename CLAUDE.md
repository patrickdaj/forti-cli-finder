# Forti CLI Finder — conventions

A static, single-page search over Fortinet's CLI references: bundles of commands, config
tables, arguments and sample output, built from Fortinet's PDFs plus a few committed overlays.
The directory is `forti-cli-helper`; the remote and the README say `forti-cli-finder`. Same
project; the rename was judged not worth doing.

## Non-negotiables
1. The build and the shipped site use python3 stdlib and `pdftotext` and nothing else. No
   `pyproject`, no pip, no npm. `node` is optional and only for `tools/check_page.py`.
2. The site is one self-contained `site/index.html` plus the bundles in `site/data/`. The
   bundles are committed.
3. A rebuild from unchanged input is byte-identical. Confirm with `git diff --stat site/data`.
4. Every new tool ships a `--selftest` wired into `make check` (the 16 older tools predate this). There is no pytest, by design.
5. This repo is public. From the lab's `investigations/` only command text and anonymised
   output may arrive: no hostname, public address, token or company name, and serials only as their last four
   characters.
   `tools/import_lab.py` anonymises and refuses to write (exit 1) if anything survives its
   own final scan. Do not weaken that scan to get a file through.
6. Data from the other two repos arrives only as a committed JSON overlay written by a tool in
   `tools/` at generation time: `device-overlay.json`, `cheat-overlay.json`,
   `lab-overlay.json`. Never read the other repos at build time or on CI; neither has them.
   An importer that needs YAML runs under the owning repo's environment
   (`uv run --project ~/Development/fortinet-brain python3 tools/<importer>.py`); the
   committed overlay stays JSON and `make check` never needs YAML.
7. Provenance travels with every fact: the page prints a source line under each sample.

## The sibling repos
- `~/Development/fortinet-brain`: the documentation corpus, citations, FortiManager's syntax
  schema (`fmg-syntax-<train>-device.json`) and the clicheck rules. Has its own CLAUDE.md.
- `~/Development/fortinet-lab`: the devices and their logs. All device access goes through its
  `uv run lab`, never from this repo, and never to the 70G pair (the October crawl hung the
  household perimeter every 450 asks). Nothing crawls from here.

## Before committing
- `make check`. It runs `check_bundles.py`, six `--selftest`s and `check_page.py`.
- A data change also needs `make diff`; put its counts in the commit message.
- A report-only tool (`diff_schema.py`) changes no parser, bundle or site file. Do not edit a
  parser on the strength of a schema disagreement until `docs/schema-diff.md` says it is real.

## Where things are
- `docs/pipeline.md`: how every byte is built, and what is and is not checked.
- `docs/sources.md`: which documents are shipped and why.
- `docs/schema-diff.md`: FortiManager's schema against the bundles.
- `docs/usability-2026-11.md`: the walk of every README flow, and the ranked fixes.
- `docs/superpowers/plans/2026-11-04-use-the-lab-and-the-brain.md`: the plan for feeding the
  Finder from the lab and the brain; its section 2 is the rules, section 6 the decisions.
- `make` prints every target with its cost.
